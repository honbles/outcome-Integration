#!/usr/bin/env python3
"""
Real-engine experiment for the policy-semantics identification paper.

The probe oracle is the real Linux kernel netfilter running in a network namespace:
  ns fwA (client) --veth-- ns fwB (firewall host). A policy is installed on fwB's INPUT hook,
  one UDP datagram per flow is sent from fwA, and "permit" means the datagram reached a socket
  bound on fwB. Nothing here is a simulator of the engine; only the hypothesis class H8 and the
  suite construction are copied from engine_experiments.py (same definitions, same pool).

Engines under test (all real kernel behavior, driven through different front ends):
  iptables-legacy   xtables front end, policy applied with iptables-legacy-restore
  iptables-nft      iptables syntax on the nf_tables back end
  nft-1chain        native nftables, all rules in one base chain
  nft-2chain        native nftables, rule 0 in a base chain at priority 0, rules 1.. in a second
                    base chain at priority 10 (an adapter convention fixed before the run). In
                    nftables an `accept` in one base chain does not end evaluation at that hook.

Flow f in 0..N-1 is UDP destination port BASE+f; a rule box [a,b] is `dport BASE+a : BASE+b`.
Python standard library only; needs root, `ip`, iptables(-legacy/-nft), nft.
"""
import itertools, math, os, random, select, socket, subprocess, sys, time
from collections import defaultdict

# ---------------------------------------------------------------- class H8 (copied definitions)
N = 4
H8 = ["FM", "LM", "PRhi", "PRlo", "BM", "PO", "DO", "LMQ"]
BASE = 9000

def vol(b): return b[1] - b[0] + 1
def inb(b, f): return b[0] <= f <= b[1]
def sig(P, f): return tuple(i for i, r in enumerate(P["rules"]) if inb(r[0], f))

def winner(h, P, S):
    R = P["rules"]
    if h == "FM": return min(S)
    if h == "LM": return max(S)
    if h == "PRhi":
        m = max(R[i][2] for i in S); return min(i for i in S if R[i][2] == m)
    if h == "PRlo":
        m = min(R[i][2] for i in S); return min(i for i in S if R[i][2] == m)
    if h == "BM":
        m = min(vol(R[i][0]) for i in S); return min(i for i in S if vol(R[i][0]) == m)
    if h == "PO":
        pm = [i for i in S if R[i][1] == 1]; return min(pm) if pm else min(S)
    if h == "DO":
        dn = [i for i in S if R[i][1] == 0]; return min(dn) if dn else min(S)
    if h == "LMQ":
        q = [i for i in S if R[i][3] == 1]; return min(q) if q else max(S)
    raise ValueError(h)

def ev(h, P, f):
    S = sig(P, f)
    return P["rules"][winner(h, P, S)][1] if S else P["default"]

boxes = [(a, b) for a in range(N) for b in range(a, N)]
def rules_for(allow_deny=True, allow_quick=True, prios=(0, 1, 2)):
    return [(bx, a, p, q) for bx in boxes for a in ((0, 1) if allow_deny else (1,))
            for p in prios for q in ((0, 1) if allow_quick else (0,))]

def universe(rs, maxn=2):
    U = []
    for n in range(1, maxn + 1):
        for combo in itertools.product(rs, repeat=n):
            for d in (0, 1):
                P = {"rules": list(combo), "default": d}
                for f in range(N): U.append((P, f))
    return U

def classes(U, H):
    sigs = defaultdict(list)
    for h in H: sigs[tuple(ev(h, P, f) for (P, f) in U)].append(h)
    return list(sigs.values())

def greedy(U, H):
    order, seen = [], {}
    for (P, f) in U:
        v = tuple(ev(h, P, f) for h in H)
        if v not in seen: seen[v] = (P, f); order.append(v)
    part, S = [list(range(len(H)))], []
    while any(len(K) > 1 for K in part):
        t = next((v for v in order if any(len({v[i] for i in K}) > 1 for K in part)), None)
        if t is None: return None, part
        S.append(seen[t]); new = []
        for K in part:
            for b in (0, 1):
                kk = [i for i in K if t[i] == b]
                if kk: new.append(kk)
        part = new
    return S, part

def fmt(P, f=None):
    rs = ["(%s,%s)" % (list(r[0]), "permit" if r[1] else "deny") for r in P["rules"]]
    return "[" + ", ".join(rs) + "] default=" + ("permit" if P["default"] else "deny") + (" flow=%d" % f if f is not None else "")

def pkey(P): return (tuple(P["rules"]), P["default"])

# ---------------------------------------------------------------- namespaces and oracle
def sh(cmd, inp=None, check=True):
    r = subprocess.run(cmd, shell=True, input=inp, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError("cmd failed: %s\n%s" % (cmd, r.stderr))
    return r

def mac(ns, dev):
    out = sh("ip netns exec %s cat /sys/class/net/%s/address" % (ns, dev)).stdout.strip()
    return out

def setup_ns():
    for ns in ("fwA", "fwB"): sh("ip netns del %s" % ns, check=False)
    sh("ip netns add fwA; ip netns add fwB; ip link add va type veth peer name vb")
    sh("ip link set va netns fwA; ip link set vb netns fwB")
    sh("ip netns exec fwA ip addr add 10.99.0.1/24 dev va; ip netns exec fwA ip link set va up; ip netns exec fwA ip link set lo up")
    sh("ip netns exec fwB ip addr add 10.99.0.2/24 dev vb; ip netns exec fwB ip link set vb up; ip netns exec fwB ip link set lo up")
    # static neighbours so no ARP latency can be mistaken for a drop
    sh("ip netns exec fwA ip neigh replace 10.99.0.2 lladdr %s dev va nud permanent" % mac("fwB", "vb"))
    sh("ip netns exec fwB ip neigh replace 10.99.0.1 lladdr %s dev vb nud permanent" % mac("fwA", "va"))

def in_ns(name, fn):
    cur = os.open("/proc/self/ns/net", os.O_RDONLY)
    tgt = os.open("/var/run/netns/%s" % name, os.O_RDONLY)
    os.setns(tgt, 0)
    try: return fn()
    finally:
        os.setns(cur, 0); os.close(cur); os.close(tgt)

def mk_receivers():
    socks = []
    for f in range(N):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", BASE + f)); s.setblocking(False); socks.append(s)
    return socks

def mk_sender():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.99.0.1", 0)); return s

# ---------------------------------------------------------------- engine front ends
def ipt_text(P):
    d = "ACCEPT" if P["default"] else "DROP"
    L = ["*filter", ":INPUT %s [0:0]" % d, ":FORWARD ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]"]
    for (bx, a, _, _) in P["rules"]:
        L.append("-A INPUT -p udp -m udp --dport %d:%d -j %s" % (BASE + bx[0], BASE + bx[1], "ACCEPT" if a else "DROP"))
    L.append("COMMIT")
    return "\n".join(L) + "\n"

def nft_text(P, split):
    d = "accept" if P["default"] else "drop"
    def r(x):
        bx, a = x[0], x[1]
        return "udp dport %d-%d %s" % (BASE + bx[0], BASE + bx[1], "accept" if a else "drop")
    rules = P["rules"]
    A, B = (rules, []) if split is None else (rules[:split], rules[split:])
    L = ["flush ruleset", "table ip fw {",
         " chain a { type filter hook input priority 0; policy %s;" % d]
    L += ["  " + r(x) for x in A]
    L += [" }"]
    if split is not None:
        L += [" chain b { type filter hook input priority 10; policy %s;" % d]
        L += ["  " + r(x) for x in B]
        L += [" }"]
    L += ["}"]
    return "\n".join(L) + "\n"

def flush_all():
    sh("ip netns exec fwB sh -c 'iptables-legacy -F; iptables-legacy -P INPUT ACCEPT; "
       "iptables-nft -F; iptables-nft -P INPUT ACCEPT; nft flush ruleset'")

ENGINES = {
    "iptables-legacy": lambda P: sh("ip netns exec fwB iptables-legacy-restore", inp=ipt_text(P)),
    "iptables-nft":    lambda P: sh("ip netns exec fwB iptables-nft-restore", inp=ipt_text(P)),
    "nft-1chain":      lambda P: sh("ip netns exec fwB nft -f -", inp=nft_text(P, None)),
    "nft-2chain":      lambda P: sh("ip netns exec fwB nft -f -", inp=nft_text(P, 1)),
}

class Oracle:
    def __init__(self):
        setup_ns()
        self.recv = in_ns("fwB", mk_receivers)
        self.snd = in_ns("fwA", mk_sender)
        self.calls = 0

    def drain(self):
        for s in self.recv:
            while True:
                try: s.recv(64)
                except BlockingIOError: break

    def decisions(self, engine, P, wait=0.040):
        """Install P on `engine`, send one datagram per flow, return the 4 decisions (1=permit)."""
        ENGINES[engine](P)
        self.drain()
        for f in range(N): self.snd.sendto(b"p%d" % f, ("10.99.0.2", BASE + f))
        got, deadline = set(), time.time() + wait
        while len(got) < N and time.time() < deadline:
            r, _, _ = select.select(self.recv, [], [], max(0.0, deadline - time.time()))
            for s in r:
                try: s.recv(64); got.add(self.recv.index(s))
                except BlockingIOError: pass
        self.calls += 1
        return tuple(1 if f in got else 0 for f in range(N))

# ---------------------------------------------------------------- experiment
def main():
    t0 = time.time()
    print("kernel:", sh("uname -r").stdout.strip())
    for c in ("iptables-legacy --version", "iptables-nft --version", "nft --version"):
        print("tool:", sh(c).stdout.strip())
    print("python:", sys.version.split()[0])
    orc = Oracle()

    Ue = universe(rules_for(True, False, (0,)))          # what iptables/nft can express: permit/deny, no priority, no quick
    pols = {}
    for (P, f) in Ue: pols.setdefault(pkey(P), P)
    print("probe universe U_e: %d (policy,flow) probes, %d distinct policies (1-2 rules, both defaults, N=%d flows)" % (len(Ue), len(pols), N))

    # Identification suite: Algorithm 1 over representatives of the observational classes on U_e
    cls = classes(Ue, H8)
    reps = [K[0] for K in cls]
    suite, _ = greedy(Ue, reps)
    print("observational classes of H8 on U_e (hypotheses a probe in U_e cannot separate):", cls)
    print("greedy suite over class representatives: %d probes" % len(suite))
    for (P, f) in suite: print("   probe", fmt(P, f))

    results = {}
    keys = sorted(pols, key=lambda k: str(k))
    for eng in ENGINES:
        flush_all()
        print("\n==================== engine: %s ====================" % eng)
        # controls
        c_all = orc.decisions(eng, {"rules": [], "default": 1}, wait=0.5)
        c_none = orc.decisions(eng, {"rules": [], "default": 0}, wait=0.15)
        c_one = orc.decisions(eng, {"rules": [((0, 0), 0, 0, 0)], "default": 1}, wait=0.5)
        print("controls  permit-all -> %s (want 1111)   deny-all -> %s (want 0000)   deny flow0 only -> %s (want 0111)" % (c_all, c_none, c_one))
        assert c_all == (1, 1, 1, 1) and c_none == (0, 0, 0, 0) and c_one == (0, 1, 1, 1), "oracle controls failed"
        # exhaustive sweep
        resp = {}
        ts = time.time()
        for k in keys:
            d = orc.decisions(eng, pols[k])
            for f in range(N): resp[(k, f)] = d[f]
        print("sweep: %d policies installed, %d probe responses, %.1fs" % (len(keys), len(resp), time.time() - ts))
        # determinism: re-run 25% of policies in shuffled order
        rnd = random.Random(7); sample = rnd.sample(keys, len(keys) // 4); mism = 0
        for k in sample:
            d = orc.decisions(eng, pols[k])
            mism += sum(1 for f in range(N) if d[f] != resp[(k, f)])
        print("determinism: re-probed %d policies in shuffled order, %d response mismatches" % (len(sample), mism))
        results[eng] = resp

        # agreement of every hypothesis with the real engine over all of U_e
        dh = {h: sum(1 for (P, f) in Ue if ev(h, P, f) != resp[(pkey(P), f)]) / len(Ue) for h in H8}
        print("disagreement d_h with the real engine over U_e: " + "  ".join("%s=%.4f" % (h, dh[h]) for h in H8))
        eps = min(dh.values()); near = [h for h in H8 if dh[h] == eps]
        # what the greedy suite alone would conclude
        cons_suite = [h for h in H8 if all(ev(h, P, f) == resp[(pkey(P), f)] for (P, f) in suite)]
        cons_all = [h for h in H8 if dh[h] == 0.0]
        print("consistent with the %d-probe suite: %s" % (len(suite), cons_suite))
        print("consistent with all %d probes     : %s" % (len(Ue), cons_all))
        if cons_all:
            truth_class = [K for K in cls if set(K) == set(cons_all)]
            print("VERDICT: in class; identified up to observational class %s (expected class structure %s)" % (cons_all, "matches" if truth_class else "DIFFERS"))
        elif cons_suite:
            print("VERDICT: suite alone would ACCEPT %s but exhaustive probing REFUTES every member: undetected-by-suite deviation, min eps=%.4f (nearest %s)" % (cons_suite, eps, near))
        else:
            print("VERDICT: deviation detected by the suite (empty consistent set); min eps over U_e = %.4f (nearest %s)" % (eps, near))

    # ---------- differential check between real implementations
    print("\n==================== differential: implementation vs implementation ====================")
    base = results["iptables-legacy"]
    for eng in ("iptables-nft", "nft-1chain", "nft-2chain"):
        diff = sum(1 for k in base if base[k] != results[eng][k])
        print("iptables-legacy vs %-12s: %d of %d probes differ" % (eng, diff, len(base)))

    # ---------- Q1 plan under assumed semantics, executed in the sandbox on each real engine
    print("\n==================== plan under an assumed semantics, checked on the real engine ====================")
    Pprod = {"rules": [((1, 1), 0, 0, 0)], "default": 1}   # production: deny flow 1, default permit
    M = (0, 2)                                              # outcome: every flow in [0,2] must be permitted
    def insert(P, pos, rule): return {"rules": P["rules"][:pos] + [rule] + P["rules"][pos:], "default": P["default"]}
    def q1_model(h, P): return all(ev(h, P, f) == 1 for f in range(M[0], M[1] + 1))
    def q1_real(eng, P):
        d = orc.decisions(eng, P, wait=0.1); return all(d[f] == 1 for f in range(M[0], M[1] + 1)), d
    plan = next((pos, insert(Pprod, pos, (M, 1, 0, 0))) for pos in range(2) if q1_model("FM", insert(Pprod, pos, (M, 1, 0, 0))))
    print("production policy %s; request: permit flows %s" % (fmt(Pprod), list(M)))
    print("plan chosen assuming FM: insert permit %s at position %d -> %s; model predicts Q1 = True" % (list(M), plan[0], fmt(plan[1])))
    for eng in ENGINES:
        flush_all(); ok, d = q1_real(eng, plan[1])
        print("  real %-16s Q1 holds: %-5s decisions for flows 0..3 = %s" % (eng, ok, d))
    print("\ntotal oracle installs: %d, wall time %.1fs" % (orc.calls, time.time() - t0))

    # ---------- random-probing detection bound versus the real nft-2chain deviation
    print("\n==================== detection by random probing vs Theorem 4 (real nft-2chain) ====================")
    resp = results["nft-2chain"]
    dh = {h: sum(1 for (P, f) in Ue if ev(h, P, f) != resp[(pkey(P), f)]) / len(Ue) for h in H8}
    eps = min(dh.values()); k = len(H8)
    print("eps = min_h d_h = %.4f; theory: n >= ln(k/delta)/eps suffices; (1-eps)ln(1/delta)/eps is necessary" % eps)
    for delta in (0.1, 0.01):
        print("  delta=%.2f: sufficient n = %d, necessary n = %d" % (delta, math.ceil(math.log(k / delta) / eps), math.ceil((1 - eps) * math.log(1 / delta) / eps)))
    rnd = random.Random(2026)
    bad = {h: {i for i, (P, f) in enumerate(Ue) if ev(h, P, f) != resp[(pkey(P), f)]} for h in H8}
    for n in (1, 2, 3, 5, 8, 12):
        miss = 0; T = 20000
        for _ in range(T):
            S = [rnd.randrange(len(Ue)) for _ in range(n)]
            if any(all(i not in bad[h] for i in S) for h in H8): miss += 1
        lo = (1 - eps) ** n; hi = min(1.0, sum((1 - dh[h]) ** n for h in H8))
        print("  n=%2d  empirical miss=%.4f   theorem lower=%.4f upper=%.4f   (MC s.e. <= %.4f)" % (n, miss / T, lo, hi, 0.5 / math.sqrt(T)))

if __name__ == "__main__":
    main()
