#!/usr/bin/env python3
"""
Real pf experiment (OpenBSD or FreeBSD) for the policy-semantics identification paper.

The probe oracle is the packet filter pf of the host itself, driven through the loopback interface:
a policy is loaded with pfctl, one UDP datagram per flow is sent to 127.0.0.1, and a flow is permitted iff
the datagram reaches a bound socket. Rules only touch inbound UDP on lo0, so the rest of the machine
(ssh included) keeps working; the original ruleset is restored at the end.

Flow f in 0..3 is UDP destination port 9000+f; a rule box [a,b] is `port 9000+a:9000+b`.
A model rule (box, action, priority, quick) becomes
    {pass|block} in [quick] on lo0 inet proto udp from any to any port A:B no state
Priority is not expressible in pf (the rule pool uses priority 0 only). The default decision is the model's
default: permit is pf's own default; deny is a first, non-quick `block in on lo0 inet proto udp all no state`.

What it does (same protocol as real_engine_experiment.py, with the pf class H8 and quick flags):
  1. controls (permit-all, deny-all, deny one flow);
  2. identification suite from the greedy construction over the observational classes of H8 on the pool,
     the consistent set it gives, and an exhaustive sweep of the pool (13,120 probes) with d_h per hypothesis;
  3. determinism re-probe of 25% of the policies;
  4. the paper's example on the real engine: with the quick-free class H4 the suite identifies pf as
     last-match, plans chosen under FM and LM fail Q1, and the plan under LMQ holds.

Target: OpenBSD (record the release printed in the first line of the output). FreeBSD should work but is not the design target.
Usage (as root, needs real_engine_experiment.py in the same directory):
    python3 real_engine_experiment6_pf.py                 full run
    python3 real_engine_experiment6_pf.py --sample 400    sweep a random subset only
    python3 real_engine_experiment6_pf.py --simulate      self-test: no pfctl, rules interpreted in Python
Python 3 standard library only.
"""
import argparse, os, random, re, select, socket, subprocess, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import real_engine_experiment as R
from real_engine_experiment import N, BASE, H8, ev, universe, classes, greedy, fmt, pkey

ap = argparse.ArgumentParser()
ap.add_argument("--simulate", action="store_true", help="interpret the generated rules in Python instead of calling pfctl")
ap.add_argument("--sample", type=int, default=0, help="sweep only this many random policies (0 = all)")
ap.add_argument("--wait", type=float, default=0.1, help="seconds to wait for datagrams after each install")
ARGS = ap.parse_args()


# ---------------------------------------------------------------- policy -> pf ruleset
def pf_text(P):
    L = ["set block-policy drop"]
    if P["default"] == 0:
        L.append("block in on lo0 inet proto udp all no state")
    for (bx, a, _, q) in P["rules"]:
        port = "%d" % (BASE + bx[0]) if bx[0] == bx[1] else "%d:%d" % (BASE + bx[0], BASE + bx[1])
        L.append("%s in %son lo0 inet proto udp from any to any port %s no state"
                 % ("pass" if a else "block", "quick " if q else "", port))
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- simulated pf (self-test only)
_RULE = re.compile(r"^(pass|block) in (quick )?on lo0 inet proto udp (?:all|from any to any port (\d+)(?::(\d+))?) no state$")
def simulate_pf(text):
    rules = []
    for line in text.strip().split("\n"):
        if line.startswith("set "): continue
        m = _RULE.match(line)
        assert m, "unparsable rule: " + line
        act, quick, a, b = m.groups()
        lo = hi = None if a is None else int(a)
        if b is not None: hi = int(b)
        rules.append((act == "pass", quick is not None, lo, hi))
    out = []
    for f in range(N):
        port, dec = BASE + f, True                       # pf default: pass
        for (p, q, lo, hi) in rules:
            if lo is None or lo <= port <= hi:
                dec = p
                if q: break                              # quick ends evaluation; otherwise the last match wins
        out.append(1 if dec else 0)
    return tuple(out)


# ---------------------------------------------------------------- oracle
def sh(cmd, inp=None, check=True):
    r = subprocess.run(cmd, shell=True, input=inp, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError("cmd failed: %s\n%s%s" % (cmd, r.stdout, r.stderr))
    return r

class Oracle:
    def __init__(self):
        self.calls = 0
        if ARGS.simulate: return
        if os.geteuid() != 0: sys.exit("run as root")
        self.was_enabled = "Status: Enabled" in sh("pfctl -si", check=False).stdout
        sh("pfctl -e", check=False)                      # enable pf; harmless if already enabled
        self.opt = "-o none " if sh("pfctl -o none -nf /dev/null", check=False).returncode == 0 else ""
        print("ruleset optimizer:", "disabled with -o none" if self.opt else "left ON (this pfctl has no -o none); rule merging or reordering is possible")
        print("lo0 in pf:", " ".join(sh("pfctl -sI", check=False).stdout.split()))
        self.recv = []
        for f in range(N):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("127.0.0.1", BASE + f)); s.setblocking(False); self.recv.append(s)
        self.snd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.snd.bind(("127.0.0.1", 0))
        # IPv6 sentinel: the rules are inet only, so a datagram to ::1 always passes; once it has arrived, every IPv4
        # datagram sent before it has been delivered too, so a late packet cannot be mistaken for a deny
        self.sent6 = self.recv6 = None
        try:
            self.recv6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); self.recv6.bind(("::1", BASE + 100)); self.recv6.setblocking(False)
            self.sent6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        except OSError:
            self.recv6 = None; print("no IPv6 loopback: using the timed wait only")

    def close(self):
        if ARGS.simulate: return
        sh("pfctl -f /etc/pf.conf", check=False)         # restore the system ruleset
        if not self.was_enabled: sh("pfctl -d", check=False)   # and the original on/off state

    def decisions(self, P, wait=None):
        self.calls += 1
        text = pf_text(P)
        if ARGS.simulate: return simulate_pf(text)
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
            fh.write(text); path = fh.name
        try: sh("pfctl %s-f %s" % (self.opt, path))
        finally: os.unlink(path)
        for s in self.recv:                              # drain
            while True:
                try: s.recv(64)
                except BlockingIOError: break
        for f in range(N): self.snd.sendto(b"p%d" % f, ("127.0.0.1", BASE + f))
        w = ARGS.wait if wait is None else wait
        if self.recv6 is not None:
            self.sent6.sendto(b"s", ("::1", BASE + 100))
            end = time.time() + max(1.0, 10 * w)
            while time.time() < end:
                r, _, _ = select.select([self.recv6], [], [], 0.05)
                if r:
                    try: self.recv6.recv(8); break
                    except BlockingIOError: pass
            else: raise RuntimeError("IPv6 sentinel never arrived; the loopback or the ruleset is not behaving")
            w = 0.02                                     # everything sent before the sentinel is already queued
        got, deadline = set(), time.time() + w
        while len(got) < N and time.time() < deadline:
            r, _, _ = select.select(self.recv, [], [], max(0.0, deadline - time.time()))
            for s in r:
                try: s.recv(64); got.add(self.recv.index(s))
                except BlockingIOError: pass
        return tuple(1 if f in got else 0 for f in range(N))


def full(P, f):
    """Readable probe: every rule with box, action and quick flag, then default and flow."""
    rs = ["(%s,%s%s)" % (list(r[0]), "permit" if r[1] else "deny", ",quick" if r[3] else "") for r in P["rules"]]
    return "[" + ", ".join(rs) + "] default=" + ("permit" if P["default"] else "deny") + " flow=%d" % f

def main():
    t0 = time.time()
    print("system:", " ".join(os.uname()[:3]), "| python", sys.version.split()[0], "| mode:", "SIMULATED (self-test)" if ARGS.simulate else "real pf")
    if not ARGS.simulate: print("pf status:", sh("pfctl -si", check=False).stdout.split("\n")[0])
    orc = Oracle()
    try:
        run(orc, t0)
    finally:
        orc.close()

def run(orc, t0):
    Ue = universe(R.rules_for(True, True, (0,)), maxn=2)          # permit/deny, quick flag, no priority
    pols = {}
    for (P, f) in Ue: pols.setdefault(pkey(P), P)
    print("pool: %d probes, %d policies (1-2 rules, quick flag, both defaults, N=%d flows)" % (len(Ue), len(pols), N))

    # controls
    c_all = orc.decisions({"rules": [], "default": 1}, wait=0.3)
    c_none = orc.decisions({"rules": [], "default": 0}, wait=0.1)
    c_one = orc.decisions({"rules": [((0, 0), 0, 0, 0)], "default": 1}, wait=0.3)
    c_q = orc.decisions({"rules": [((0, 0), 0, 0, 1), ((0, 3), 1, 0, 0)], "default": 1}, wait=0.3)
    c_lm = orc.decisions({"rules": [((1, 1), 0, 0, 0), ((0, 3), 1, 0, 0)], "default": 1}, wait=0.3)
    print("controls  permit-all %s (want 1111)  deny-all %s (want 0000)  deny flow0 %s (want 0111)" % (c_all, c_none, c_one))
    print("          quick deny flow0 then permit 0-3 %s (want 0111)  plain deny flow1 then permit 0-3 (last match) %s (want 1111)" % (c_q, c_lm))
    assert c_all == (1, 1, 1, 1) and c_none == (0, 0, 0, 0) and c_one == (0, 1, 1, 1) and c_q == (0, 1, 1, 1) and c_lm == (1, 1, 1, 1), "oracle controls failed"

    cls = classes(Ue, H8)
    reps = [K[0] for K in cls]
    suite, _ = greedy(Ue, reps)
    print("observational classes of H8 on the pool:", cls)
    print("greedy identification suite: %d probes" % len(suite))
    for (P, f) in suite: print("   probe", full(P, f))

    keys = sorted(pols, key=lambda k: str(k))
    if ARGS.sample and ARGS.sample < len(keys):
        keys = random.Random(11).sample(keys, ARGS.sample)
        print("sweeping a random subset of %d policies" % len(keys))
    resp, ts = {}, time.time()
    for k in keys:
        d = orc.decisions(pols[k])
        for f in range(N): resp[(k, f)] = d[f]
    print("sweep: %d policies installed, %d probe responses, %.1fs" % (len(keys), len(resp), time.time() - ts))
    rnd = random.Random(7); sample = rnd.sample(keys, max(1, len(keys) // 4)); mism = 0
    for k in sample:
        d = orc.decisions(pols[k])
        mism += sum(1 for f in range(N) if d[f] != resp[(k, f)])
    print("determinism: re-probed %d policies in shuffled order, %d response mismatches" % (len(sample), mism))

    U = [(P, f) for (P, f) in Ue if (pkey(P), f) in resp]
    dh = {h: sum(1 for (P, f) in U if ev(h, P, f) != resp[(pkey(P), f)]) / len(U) for h in H8}
    print("disagreement d_h with the real engine: " + "  ".join("%s=%.4f" % (h, dh[h]) for h in H8))
    sd = {}
    for (P, f) in suite: sd[(pkey(P), f)] = orc.decisions(P)[f]
    cons_suite = [h for h in H8 if all(ev(h, P, f) == sd[(pkey(P), f)] for (P, f) in suite)]
    cons_all = [h for h in H8 if dh[h] == 0.0]
    print("consistent with the %d-probe suite: %s" % (len(suite), cons_suite))
    print("consistent with all %d probes: %s" % (len(U), cons_all))
    if cons_all: print("VERDICT: in class; identified up to observational class %s" % cons_all)
    elif cons_suite: print("VERDICT: suite accepts %s but exhaustive probing refutes every member (min eps=%.4f)" % (cons_suite, min(dh.values())))
    else: print("VERDICT: deviation detected by the suite; min eps=%.4f" % min(dh.values()))

    # ---- paper example on the real engine
    print("\n==================== plan under an assumed semantics, checked on the real engine ====================")
    H4 = ["FM", "LM", "PRhi", "BM"]
    Uq = universe(R.rules_for(True, False, (0,)), maxn=2)         # no quick flag in the pool
    cls4 = classes(Uq, H4); suite4, _ = greedy(Uq, [K[0] for K in cls4])
    sd4 = {}
    for (P, f) in suite4: sd4[(pkey(P), f)] = orc.decisions(P)[f]
    cons4 = [h for h in H4 if all(ev(h, P, f) == sd4[(pkey(P), f)] for (P, f) in suite4)]
    print("class H4 (no quick), %d-probe suite -> consistent set %s (expected [LM])" % (len(suite4), cons4))
    Pprod = {"rules": [((1, 1), 0, 0, 1)], "default": 1}           # one quick deny rule on flow 1, default permit
    M = (0, 2)
    def ins(P, pos, rule): return {"rules": P["rules"][:pos] + [rule] + P["rules"][pos:], "default": P["default"]}
    plans = {"FM (insert at 0)": ins(Pprod, 0, (M, 1, 0, 0)), "LM (insert at end)": ins(Pprod, 1, (M, 1, 0, 0)),
             "LMQ (quick permit at 0)": ins(Pprod, 0, (M, 1, 0, 1))}
    for name, P in plans.items():
        d = orc.decisions(P, wait=0.3)
        ok = all(d[f] == 1 for f in range(M[0], M[1] + 1))
        print("  plan %-26s Q1 holds on real pf: %-5s decisions for flows 0..3 = %s" % (name, ok, d))
    print("\ntotal installs %d, wall time %.0fs" % (orc.calls, time.time() - t0))

if __name__ == "__main__":
    main()
