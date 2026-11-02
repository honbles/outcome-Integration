#!/usr/bin/env python3
"""
Extended real-engine experiment (continuation of real_engine_experiment.py; same oracle idea:
the Linux netfilter kernel in network namespaces, one real UDP datagram per flow).

Pre-registered before running (written down in this docstring, then run once):

PART A  (d=1, N=4 flows, 1-2 rules, exhaustive: 840 policies + 2 empty policies)
  More out-of-class engines, including ones that arise from tools coexisting on one hook:
    iptables-nft-userchain  policy in a user chain reached by `-j FW` (in-class expected, d_FM = 0)
    nft-2chain-split2       first two rules in base chain 1, the rest in base chain 2
    bg-drop3                iptables-nft policy plus a second nft table (priority 10) that drops port of flow 3
    bg-drop01               same, background rule drops flows 0-1
    bg-accept2              same, background rule accepts flow 2 (no effect: in-class expected, eps = 0)
    nft-2chain              engine from the first run (re-measured here)
    iptables-nft            in-class baseline
  Detection suites compared on every engine (all deterministic, fixed before the run):
    S_id   the 3-probe greedy identification suite of the first run
    S_cc   structured suite: one probe per "interaction type" (relation of the two boxes: disjoint /
           equal / A strictly inside B / B strictly inside A / partial overlap, x both actions x both
           defaults x which of the two boxes contain the flow) plus per-flow coverage (for each flow
           f: empty policy under both defaults, a rule permitting only f under default deny, a rule
           denying only f under default permit)
    random n probes drawn uniformly from the pool (Monte Carlo from the recorded table)
  Note: S_cc was designed after seeing that single-rule probes cannot expose nft-2chain; the other
  engines were fixed before S_cc was evaluated on them, but the comparison is not blind.

PART B  (d=2: destination port x source address, 5 x 3 = 15 flows; 500 random policies of 3-5 rules)
  Engines: iptables-legacy, iptables-nft, nft-1chain (in-class expected), nft-2chain (out of class).
  Checks on the real engines:
    B1 agreement of each hypothesis (FM, LM, BM, PO, DO) with the engine on all 7500 probes
    B2 cell lemma: decisions are constant on every elementary cell (coordinate-compression cells)
    B3 non-interference (Q2): insert a permit rule at a random position of a random production policy.
       exact  : rule box == requested match M  -> expect Delta subset of M on in-class engines
       loose  : rule box strictly contains M   -> interference expected sometimes
       compare real Delta to the first-match model's Delta
"""
import math, os, random, select, socket, sys, time
from collections import defaultdict
import real_engine_experiment as r
from real_engine_experiment import sh, in_ns, setup_ns, ev, pkey, fmt, N, BASE, H8

# ------------------------------------------------------------------ oracle on a grid of flows
class Oracle2:
    def __init__(self, NX, NY):
        setup_ns()
        for y in range(NY):
            sh("ip netns exec fwA ip addr add 10.99.0.%d/24 dev va" % (11 + y))
        self.NX, self.NY, self.calls = NX, NY, 0
        def mkrecv():
            ss = []
            for x in range(NX):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", BASE + x)); s.setblocking(False); ss.append(s)
            return ss
        def mksnd():
            ss = []
            for y in range(NY):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.99.0.%d" % (11 + y), 0)); ss.append(s)
            return ss
        self.recv = in_ns("fwB", mkrecv); self.snd = in_ns("fwA", mksnd)

    def drain(self):
        for s in self.recv:
            while True:
                try: s.recvfrom(64)
                except BlockingIOError: break

    def decisions(self, load, P, wait=0.040):
        load(P); self.drain()
        for y in range(self.NY):
            for x in range(self.NX): self.snd[y].sendto(b"p", ("10.99.0.2", BASE + x))
        want, got, deadline = self.NX * self.NY, set(), time.time() + wait
        while len(got) < want and time.time() < deadline:
            rd, _, _ = select.select(self.recv, [], [], max(0.0, deadline - time.time()))
            for s in rd:
                x = self.recv.index(s)
                while True:
                    try: _, addr = s.recvfrom(64)
                    except BlockingIOError: break
                    got.add((x, int(addr[0].split(".")[-1]) - 11))
        self.calls += 1
        return {(x, y): 1 if (x, y) in got else 0 for x in range(self.NX) for y in range(self.NY)}

def flush_all(): r.flush_all()

# ------------------------------------------------------------------ PART A engines (d=1)
def load_iptnft(P): sh("ip netns exec fwB iptables-nft-restore", inp=r.ipt_text(P))
def load_userchain(P):
    t = r.ipt_text(P).replace(":OUTPUT ACCEPT [0:0]\n", ":OUTPUT ACCEPT [0:0]\n:FW - [0:0]\n-A INPUT -j FW\n").replace("-A INPUT -p udp", "-A FW -p udp")
    sh("ip netns exec fwB iptables-nft-restore", inp=t)
def load_nft(split): return lambda P: sh("ip netns exec fwB nft -f -", inp=r.nft_text(P, split))
def setup_bg(rule):
    def f(): sh("ip netns exec fwB nft -f -", inp="table ip bg {\n chain c {\n type filter hook input priority 10; policy accept;\n  %s\n }\n}\n" % rule)
    return f

ENG_A = {
    "iptables-nft":           (None, load_iptnft, True),
    "iptables-nft-userchain": (None, load_userchain, True),
    "nft-2chain":             (None, load_nft(1), True),
    "nft-2chain-split2":      (None, load_nft(2), False),
    "bg-drop3":               (setup_bg("udp dport %d drop" % (BASE + 3)), load_iptnft, False),
    "bg-drop01":              (setup_bg("udp dport %d-%d drop" % (BASE, BASE + 1)), load_iptnft, False),
    "bg-accept2":             (setup_bg("udp dport %d accept" % (BASE + 2)), load_iptnft, True),
}

def relation(A, B):
    if A == B: return "equal"
    if A[1] < B[0] or B[1] < A[0]: return "disjoint"
    if A[0] >= B[0] and A[1] <= B[1]: return "A-in-B"
    if B[0] >= A[0] and B[1] <= A[1]: return "B-in-A"
    return "overlap"

def build_scc(Ue):
    seen, S = set(), []
    for (P, f) in Ue:
        rs = P["rules"]
        if len(rs) == 1: t = ("1", rs[0][1], P["default"], r.inb(rs[0][0], f))
        else: t = ("2", relation(rs[0][0], rs[1][0]), rs[0][1], rs[1][1], P["default"], (r.inb(rs[0][0], f), r.inb(rs[1][0], f)))
        if t not in seen: seen.add(t); S.append((P, f))
    n_types = len(S)
    for f in range(N):
        for P in ({"rules": [], "default": 1}, {"rules": [], "default": 0},
                  {"rules": [((f, f), 1, 0, 0)], "default": 0}, {"rules": [((f, f), 0, 0, 0)], "default": 1}):
            S.append((P, f))
    return S, n_types

def partA():
    t0 = time.time()
    orc = Oracle2(4, 1)
    Ue = r.universe(r.rules_for(True, False, (0,)))
    pols = {}
    for (P, f) in Ue: pols.setdefault(pkey(P), P)
    for d in (0, 1): E = {"rules": [], "default": d}; pols.setdefault(pkey(E), E)
    cls = r.classes(Ue, H8); reps = [K[0] for K in cls]
    S_id, _ = r.greedy(Ue, reps)
    S_cc, ntypes = build_scc(Ue)
    print("PART A: |U_e|=%d probes, %d policies (incl. 2 empty); observational classes %s" % (len(Ue), len(pols), cls))
    print("S_id: %d probes; S_cc: %d probes (%d interaction types + %d per-flow probes)" % (len(S_id), len(S_cc), ntypes, len(S_cc) - ntypes))
    # sanity: S_cc separates every pair of observational classes (can identify when in class)
    sep_ok = all(any(ev(a, P, f) != ev(b, P, f) for (P, f) in S_cc) for a in reps for b in reps if a != b)
    print("S_cc separates all observational classes of H8 on U_e:", sep_ok)
    rnd = random.Random(2026)
    keys = sorted(pols, key=str)
    summary = []
    for eng, (setup, load, assert_controls) in ENG_A.items():
        flush_all()
        if setup: setup()
        print("\n==================== engine: %s ====================" % eng, flush=True)
        ctl = (orc.decisions(load, {"rules": [], "default": 1}, 0.5), orc.decisions(load, {"rules": [], "default": 0}, 0.15),
               orc.decisions(load, {"rules": [((0, 0), 0, 0, 0)], "default": 1}, 0.5))
        ctl = tuple(tuple(c[(x, 0)] for x in range(4)) for c in ctl)
        print("controls permit-all/deny-all/deny-flow0: %s %s %s" % ctl)
        if assert_controls: assert ctl == ((1, 1, 1, 1), (0, 0, 0, 0), (0, 1, 1, 1)), "controls failed"
        resp = {}
        ts = time.time()
        for k in keys:
            d = orc.decisions(load, pols[k])
            for f in range(4): resp[(k, f)] = d[(f, 0)]
        print("sweep: %d policies, %.1fs" % (len(keys), time.time() - ts))
        samp = rnd.sample(keys, 80); mism = 0
        for k in samp:
            d = orc.decisions(load, pols[k]); mism += sum(1 for f in range(4) if d[(f, 0)] != resp[(k, f)])
        print("determinism: %d policies re-probed, %d mismatches" % (len(samp), mism))
        dh = {h: sum(1 for (P, f) in Ue if ev(h, P, f) != resp[(pkey(P), f)]) / len(Ue) for h in H8}
        eps = min(dh.values()); near = [h for h in H8 if dh[h] == eps]
        cons = lambda S: [h for h in H8 if all(ev(h, P, f) == resp[(pkey(P), f)] for (P, f) in S)]
        c_id, c_cc, c_all = cons(S_id), cons(S_cc), [h for h in H8 if dh[h] == 0.0]
        print("d_h: " + " ".join("%s=%.4f" % (h, dh[h]) for h in H8))
        print("consistent after S_id: %s | after S_cc: %s | after all %d probes: %s" % (c_id, c_cc, len(Ue), c_all))
        bad = {h: {i for i, (P, f) in enumerate(Ue) if ev(h, P, f) != resp[(pkey(P), f)]} for h in H8}
        def miss(n, T=4000):
            m = 0
            for _ in range(T):
                S = [rnd.randrange(len(Ue)) for _ in range(n)]
                if any(all(i not in bad[h] for i in S) for h in H8): m += 1
            return m / T
        m_cc, m56 = miss(len(S_cc)), miss(56)
        print("random probing miss probability: n=%d (size of S_cc) %.4f ; n=56 %.4f%s" % (len(S_cc), m_cc, m56, "   (n/a: engine is in class, nothing to detect)" if c_all else ""))
        status_id = "ACCEPTS %s" % c_id if c_id and not c_all else ("in class" if c_all else "detects")
        status_cc = "detects" if not c_cc else ("in class %s" % c_cc)
        summary.append((eng, eps, near[0] if eps > 0 else "-", len(c_id), status_id, status_cc, m_cc, m56, bool(c_all)))
    print("\n==================== PART A summary ====================")
    print("%-24s %-7s %-8s %-30s %-22s %-9s %-8s" % ("engine", "eps", "nearest", "S_id (3 probes)", "S_cc (%d probes)" % len(S_cc), "rand n=%d" % len(S_cc), "rand n=56"))
    for (eng, eps, near, nid, sid, scc, m1, m2, inc) in summary:
        print("%-24s %-7.4f %-8s %-30s %-22s miss=%.3f  miss=%.3f" % (eng, eps, near, sid[:30], scc[:22], m1, m2))
    print("PART A oracle installs: %d, wall time %.1fs" % (orc.calls, time.time() - t0))

# ------------------------------------------------------------------ PART B (d=2)
NX, NY = 5, 3
H2 = ["FM", "LM", "BM", "PO", "DO"]
def inb2(b, f): return b[0][0] <= f[0] <= b[0][1] and b[1][0] <= f[1] <= b[1][1]
def area(b): return (b[0][1] - b[0][0] + 1) * (b[1][1] - b[1][0] + 1)
def ev2(h, P, f):
    R = P["rules"]; S = [i for i, x in enumerate(R) if inb2(x[0], f)]
    if not S: return P["default"]
    if h == "FM": w = min(S)
    elif h == "LM": w = max(S)
    elif h == "BM": m = min(area(R[i][0]) for i in S); w = min(i for i in S if area(R[i][0]) == m)
    elif h == "PO": pm = [i for i in S if R[i][1] == 1]; w = min(pm) if pm else min(S)
    elif h == "DO": dn = [i for i in S if R[i][1] == 0]; w = min(dn) if dn else min(S)
    return R[w][1]

def ipt2_text(P):
    d = "ACCEPT" if P["default"] else "DROP"
    L = ["*filter", ":INPUT %s [0:0]" % d, ":FORWARD ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]"]
    for (bx, a) in [(x[0], x[1]) for x in P["rules"]]:
        L.append("-A INPUT -p udp -m iprange --src-range 10.99.0.%d-10.99.0.%d -m udp --dport %d:%d -j %s" %
                 (11 + bx[1][0], 11 + bx[1][1], BASE + bx[0][0], BASE + bx[0][1], "ACCEPT" if a else "DROP"))
    L.append("COMMIT"); return "\n".join(L) + "\n"

def nft2_text(P, split):
    d = "accept" if P["default"] else "drop"
    def rr(x):
        bx, a = x[0], x[1]
        return "ip saddr 10.99.0.%d-10.99.0.%d udp dport %d-%d %s" % (11 + bx[1][0], 11 + bx[1][1], BASE + bx[0][0], BASE + bx[0][1], "accept" if a else "drop")
    R = P["rules"]; A, B = (R, []) if split is None else (R[:split], R[split:])
    L = ["flush ruleset", "table ip fw {", " chain a { type filter hook input priority 0; policy %s;" % d] + ["  " + rr(x) for x in A] + [" }"]
    if split is not None: L += [" chain b { type filter hook input priority 10; policy %s;" % d] + ["  " + rr(x) for x in B] + [" }"]
    return "\n".join(L + ["}"]) + "\n"

ENG_B = {
    "iptables-legacy": lambda P: sh("ip netns exec fwB iptables-legacy-restore", inp=ipt2_text(P)),
    "iptables-nft":    lambda P: sh("ip netns exec fwB iptables-nft-restore", inp=ipt2_text(P)),
    "nft-1chain":      lambda P: sh("ip netns exec fwB nft -f -", inp=nft2_text(P, None)),
    "nft-2chain":      lambda P: sh("ip netns exec fwB nft -f -", inp=nft2_text(P, 1)),
}

def rand_box(rnd):
    x0 = rnd.randrange(NX); x1 = rnd.randrange(x0, NX); y0 = rnd.randrange(NY); y1 = rnd.randrange(y0, NY)
    return ((x0, x1), (y0, y1))
def rand_policy(rnd, nlo, nhi):
    return {"rules": [(rand_box(rnd), rnd.randrange(2), 0, 0) for _ in range(rnd.randint(nlo, nhi))], "default": rnd.randrange(2)}
def loosen(rnd, M):
    (x0, x1), (y0, y1) = M; o = []
    if x0 > 0: o.append(((x0 - 1, x1), (y0, y1)))
    if x1 < NX - 1: o.append(((x0, x1 + 1), (y0, y1)))
    if y0 > 0: o.append(((x0, x1), (y0 - 1, y1)))
    if y1 < NY - 1: o.append(((x0, x1), (y0, y1 + 1)))
    return rnd.choice(o) if o else None
def pk2(P): return (tuple(P["rules"]), P["default"])
FLOWS = [(x, y) for x in range(NX) for y in range(NY)]

def cells(P):
    bxs = [x[0] for x in P["rules"]]
    xs = sorted({0, NX} | {b[0][0] for b in bxs} | {b[0][1] + 1 for b in bxs})
    ys = sorted({0, NY} | {b[1][0] for b in bxs} | {b[1][1] + 1 for b in bxs})
    out = []
    for i in range(len(xs) - 1):
        for j in range(len(ys) - 1):
            out.append([(x, y) for x in range(xs[i], xs[i + 1]) for y in range(ys[j], ys[j + 1])])
    return out

def partB(npol=500, ntrial=200):
    t0 = time.time()
    orc = Oracle2(NX, NY)
    rnd = random.Random(31337)
    pols = [rand_policy(rnd, 3, 5) for _ in range(npol)]
    trials = []
    for variant in ("exact", "loose"):
        while sum(1 for t in trials if t[0] == variant) < ntrial:
            P = rand_policy(rnd, 2, 4); M = rand_box(rnd)
            B = M if variant == "exact" else loosen(rnd, M)
            if B is None: continue
            pos = rnd.randrange(len(P["rules"]) + 1)
            P2 = {"rules": P["rules"][:pos] + [(B, 1, 0, 0)] + P["rules"][pos:], "default": P["default"]}
            trials.append((variant, P, M, B, P2))
    print("PART B: grid %dx%d=%d flows; %d policies of 3-5 rules; %d Q2 trials per variant" % (NX, NY, len(FLOWS), npol, ntrial))
    for eng, load in ENG_B.items():
        flush_all(); print("\n==================== engine: %s ====================" % eng, flush=True)
        c1 = orc.decisions(load, {"rules": [], "default": 1}, 0.5); c0 = orc.decisions(load, {"rules": [], "default": 0}, 0.15)
        assert all(c1.values()) and not any(c0.values()), "controls failed"
        print("controls: permit-all all permitted, deny-all all denied")
        ts = time.time(); R = {}
        for P in pols: R[pk2(P)] = orc.decisions(load, P)
        print("sweep: %d policies x %d flows = %d probes, %.1fs" % (len(pols), len(FLOWS), len(pols) * len(FLOWS), time.time() - ts))
        samp = random.Random(5).sample(pols, min(60, len(pols))); mism = 0
        for P in samp:
            d = orc.decisions(load, P); mism += sum(1 for f in FLOWS if d[f] != R[pk2(P)][f])
        print("determinism: %d policies re-probed, %d mismatches" % (len(samp), mism))
        tot = len(pols) * len(FLOWS)
        dh = {h: sum(1 for P in pols for f in FLOWS if ev2(h, P, f) != R[pk2(P)][f]) / tot for h in H2}
        print("B1 d_h over %d probes: " % tot + " ".join("%s=%.4f" % (h, dh[h]) for h in H2))
        ok_cells, ncell_sum, bound_ok = 0, 0, True
        for P in pols:
            cs = cells(P); ncell_sum += len(cs); n = len(P["rules"])
            bound_ok &= len(cs) <= (2 * n + 1) ** 2
            ok_cells += all(len({R[pk2(P)][f] for f in c}) == 1 for c in cs)
        print("B2 cell lemma on the real engine: decision-constant on every cell for %d/%d policies; mean cells %.1f of %d flows; cell bound (2n+1)^d held: %s" %
              (ok_cells, len(pols), ncell_sum / len(pols), len(FLOWS), bound_ok))
        stats = defaultdict(lambda: defaultdict(int))
        for (variant, P, M, B, P2) in trials:
            D0 = orc.decisions(load, P); D1 = orc.decisions(load, P2)
            Mset = [f for f in FLOWS if inb2(M, f)]
            real_delta = {f for f in FLOWS if D0[f] != D1[f]}
            mod_delta = {f for f in FLOWS if ev2("FM", P, f) != ev2("FM", P2, f)}
            s = stats[variant]; s["n"] += 1
            s["interf_real"] += bool(real_delta - set(Mset))
            s["interf_model"] += bool(mod_delta - set(Mset))
            s["delta_agree"] += (real_delta == mod_delta)
            s["q1_real"] += all(D1[f] == 1 for f in Mset)
            s["q1_model"] += all(ev2("FM", P2, f) == 1 for f in Mset)
            s["q1_agree"] += (all(D1[f] == 1 for f in Mset) == all(ev2("FM", P2, f) == 1 for f in Mset))
        for v in ("exact", "loose"):
            s = stats[v]
            print("B3 %-5s n=%d  Delta not within M: real %d, first-match model %d | real Delta == model Delta in %d | Q1 real holds %d, model %d, agree %d" %
                  (v, s["n"], s["interf_real"], s["interf_model"], s["delta_agree"], s["q1_real"], s["q1_model"], s["q1_agree"]))
    print("\nPART B oracle installs: %d, wall time %.1fs" % (orc.calls, time.time() - t0))

if __name__ == "__main__":
    print("kernel:", sh("uname -r").stdout.strip(), "| python", sys.version.split()[0])
    which = sys.argv[1] if len(sys.argv) > 1 else "AB"
    if "A" in which: partA()
    if "B" in which:
        if "A" in which: print("\n" + "#" * 78 + "\n")
        small = len(sys.argv) > 2 and sys.argv[2] == "smoke"
        partB(30, 10) if small else partB()
