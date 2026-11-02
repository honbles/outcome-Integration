#!/usr/bin/env python3
"""
Experiment 7: a real divergence in a live engine, Linux netfilter with the connection-tracking idiom.

Most real rule sets start with `ct state established,related accept`. Connection-tracking entries
survive a rule change, so a probe whose 5-tuple was seen before can be accepted by the entry instead of
by the policy under test. Then the engine's answer is no longer a function of (policy, flow), which
breaks the oracle (and class) assumptions behind identification and behind apply-and-diff checks.

Three modes, each on a fresh pair of network namespaces:
  plain   no ct rule, same 5-tuple for every probe of a flow   (control: expect in class, eps = 0)
  fresh   ct rule first, a new source port for every probe     (the fix: expect in class)
  stale   ct rule first, same 5-tuple for every probe of a flow (the realistic sandbox: expect a divergence)

Then a plan check: a plan chosen under last-match is applied to a real first-match engine, after a
history in which flows were permitted, and judged by probing the engine.

Needs root, ip, nft, Python 3, and ../code/real_engine_experiment.py in the same directory.
Usage:  python3 real_engine_experiment7_state.py > exp7_run.txt 2>&1
"""
import os, random, select, socket, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import real_engine_experiment as B
from real_engine_experiment import (N, H8, BASE, ev, sh, setup_ns, in_ns, mk_receivers, mk_sender,
                                    universe, rules_for, classes, greedy, pkey, fmt)

def nft_ct_text(P, ct):
    d = "accept" if P["default"] else "drop"
    L = ["flush ruleset", "table ip fw {",
         " chain a { type filter hook input priority 0; policy %s;" % d]
    if ct: L.append("  ct state established,related accept")
    for (bx, a, _, _) in P["rules"]:
        L.append("  udp dport %d-%d %s" % (BASE + bx[0], BASE + bx[1], "accept" if a else "drop"))
    L += [" }", "}"]
    return "\n".join(L) + "\n"

class Lab:
    def __init__(self, mode):
        self.mode = mode
        setup_ns()
        self.recv = in_ns("fwB", mk_receivers)
        self.fixed = in_ns("fwA", lambda: [mk_sender() for _ in range(N)])
        self.n_calls = 0
        self.port = 20000

    def new_senders(self):
        out = []
        for _ in range(N):
            self.port += 1                       # never reuse a source port, so no 5-tuple repeats
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.99.0.1", self.port)); out.append(s)
        return out

    def drain(self):
        for s in self.recv:
            while True:
                try: s.recvfrom(64)
                except BlockingIOError: break
        for s in self.fixed:
            s.setblocking(False)
            while True:
                try: s.recvfrom(64)
                except (BlockingIOError, OSError): break

    def decisions(self, P, wait=0.05):
        sh("ip netns exec fwB nft -f -", inp=nft_ct_text(P, self.mode != "plain"))
        self.drain()
        if self.mode == "fresh":
            snd = in_ns("fwA", self.new_senders)
        else:
            snd = self.fixed
        for f in range(N): snd[f].sendto(b"p%d" % f, ("10.99.0.2", BASE + f))
        got, deadline = set(), time.time() + wait
        while len(got) < N and time.time() < deadline:
            r, _, _ = select.select(self.recv, [], [], max(0.0, deadline - time.time()))
            for s in r:
                try:
                    _, addr = s.recvfrom(64); got.add(self.recv.index(s))
                    s.sendto(b"r", addr)            # reply, so the entry becomes ESTABLISHED
                except BlockingIOError: pass
        time.sleep(0.01)
        if self.mode == "fresh":
            for s in snd: s.close()
        self.n_calls += 1
        return tuple(1 if f in got else 0 for f in range(N))

def sweep(mode, pols, keys, suite, seed):
    lab = Lab(mode)
    print("\n==================== mode: %s ====================" % mode)
    a = lab.decisions({"rules": [], "default": 1}, 0.3)
    b = lab.decisions({"rules": [], "default": 0}, 0.1)
    c = lab.decisions({"rules": [((0, 0), 0, 0, 0)], "default": 1}, 0.3)
    ok = (a == (1,) * 4 and b == (0,) * 4 and c == (0, 1, 1, 1))
    print("controls  permit-all %s  deny-all %s  deny flow0 %s (want 1111 0000 0111): %s" % (a, b, c, "pass" if ok else "FAIL"))
    if mode != "stale":
        assert ok, "controls failed"
        if mode == "fresh":
            lab = Lab(mode)
    order = list(keys); random.Random(seed).shuffle(order)
    obs = {}
    t0 = time.time()
    for k in order:
        dec = lab.decisions(pols[k])
        for f in range(N): obs[(k, f)] = dec[f]
    print("sweep: %d policies, %d probes, %.1fs" % (len(order), len(order) * N, time.time() - t0))
    tot = len(obs)
    d = {h: sum(1 for (k, f), v in obs.items() if ev(h, pols[k], f) != v) / tot for h in H8}
    print("disagreement with H8: " + "  ".join("%s=%.4f" % (h, d[h]) for h in H8))
    eps = min(d.values())
    fm_perm = sum(1 for (k, f), v in obs.items() if v == 1 and ev("FM", pols[k], f) == 0)
    fm_deny = sum(1 for (k, f), v in obs.items() if v == 0 and ev("FM", pols[k], f) == 1)
    print("eps = %.4f;  vs first-match: engine permits where the policy denies %d, denies where the policy permits %d, of %d probes" % (eps, fm_perm, fm_deny, tot))
    cons3 = [h for h in H8 if all(ev(h, P, f) == obs[(pkey(P), f)] for (P, f) in suite)]
    consall = [h for h in H8 if d[h] == 0]
    print("consistent with the 3-probe suite: %s;  with all probes: %s" % (cons3, consall))
    if mode == "stale":
        print("VERDICT: %s" % ("outside H8 (no member agrees on all probes)" if not consall else "in class"))
    else:
        print("VERDICT: %s" % ("in class" if consall else "outside H8"))
    # guard: re-probe 40 policies in a new order and compare with the first answers
    chk = random.Random(seed + 1).sample(order, 40)
    mism = 0
    for k in chk:
        dec = lab.decisions(pols[k])
        mism += sum(1 for f in range(N) if dec[f] != obs[(k, f)])
    print("guard: re-probed 40 policies in a new order: %d mismatching responses of %d" % (mism, 40 * N))
    return lab, eps

def plan_check(mode):
    lab = Lab(mode)
    print("\n---- plan check, mode: %s ----" % mode)
    # history: the sandbox has already been used with a permissive policy
    lab.decisions({"rules": [], "default": 1}, 0.3)
    P0 = {"rules": [((1, 1), 0, 0, 0)], "default": 0}
    print("history: permit-all probed first; then P0 = [deny flow 1], default deny; request: permit flows 0..2")
    print("  P0 decisions         :", lab.decisions(P0, 0.1), "(first-match model: (0,0,0,0))")
    plans = {
        "plan FM  (permit [0,2] at top)": {"rules": [((0, 2), 1, 0, 0), ((1, 1), 0, 0, 0)], "default": 0},
        "plan LM  (permit [0,2] at end)": {"rules": [((1, 1), 0, 0, 0), ((0, 2), 1, 0, 0)], "default": 0},
    }
    for name, P in plans.items():
        dec = lab.decisions(P, 0.1)
        q1 = all(dec[f] == 1 for f in range(3))
        pred = tuple(ev("FM", P, f) for f in range(N))
        print("  %-32s engine %s  first-match model %s  Q1 check says %s; Q2 (flow 3 unchanged, deny) %s"
              % (name, dec, pred, "holds" if q1 else "fails", "holds" if dec[3] == 0 else "fails"))

def main():
    t0 = time.time()
    print("kernel:", sh("uname -r").stdout.strip(), "| nft:", sh("nft --version").stdout.strip(), "| python", sys.version.split()[0])
    Ue = universe(rules_for(True, False, (0,)))
    pols = {}
    for (P, f) in Ue: pols.setdefault(pkey(P), P)
    keys = sorted(pols, key=lambda k: str(k))
    cls = classes(Ue, H8)
    suite, _ = greedy(Ue, [K[0] for K in cls])
    print("pool: %d policies (1-2 rules, both defaults), %d probes; identification suite %d probes" % (len(keys), len(keys) * N, len(suite)))
    res = {}
    for mode in ("plain", "fresh", "stale"):
        res[mode] = sweep(mode, pols, keys, suite, 7)[1]
    print("\nSUMMARY eps: plain=%.4f fresh=%.4f stale=%.4f" % (res["plain"], res["fresh"], res["stale"]))
    for mode in ("fresh", "stale"): plan_check(mode)
    sh("ip netns exec fwB nft flush ruleset", check=False)
    print("\nDONE %.0fs" % (time.time() - t0))

if __name__ == "__main__":
    main()
