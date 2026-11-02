#!/usr/bin/env python3
"""
Detection phase on the second engine family (routing, nginx).

Suites compared on each engine, all deterministic and built from the pool alone:
  S_id    the greedy identification suite of experiment3 (re-derived)
  S_cc    the structured suite of experiment2, same construction rule: one probe per interaction type of two
          rules (box relation, both actions, default, containment of the flow) plus per-flow coverage.
          Type key as in experiment2, i.e. WITHOUT the quick flag.
  S_ccq   S_cc with the quick flag of both rules added to the interaction type (needed only for pools that
          contain exact-match rules). This is a change made after seeing S_cc fail, so it is not blind.
Random: n probes drawn uniformly from the pool, Monte Carlo from the recorded response table.

A suite "detects" an engine when no hypothesis of the class agrees with the engine on every suite probe.
Class H8; for nginx-exact also H9 = H8 + QBM (no alarm expected).

Usage: python3 real_engine_experiment4.py E     (needs root, ip, nginx; real_engine_experiment3.py alongside)
"""
import math, random, sys, os, time, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import real_engine_experiment as R
import real_engine_experiment3 as X
from real_engine_experiment import N, ev, universe, classes, greedy, fmt, pkey

H8 = list(R.H8)
orig_winner = R.winner
def winner_x(h, P, S):
    if h == "QBM":
        Rr = P["rules"]; q = [i for i in S if Rr[i][3] == 1]
        if q: return min(q)
        m = min(R.vol(Rr[i][0]) for i in S); return min(i for i in S if R.vol(Rr[i][0]) == m)
    return orig_winner(h, P, S)
R.winner = winner_x
H9 = H8 + ["QBM"]

def relation(A, B):
    if A == B: return "equal"
    if A[1] < B[0] or B[1] < A[0]: return "disjoint"
    if A[0] >= B[0] and A[1] <= B[1]: return "A-in-B"
    if B[0] >= A[0] and B[1] <= A[1]: return "B-in-A"
    return "overlap"

def build_scc(U, with_quick):
    seen, S = set(), []
    for (P, f) in U:
        rs = P["rules"]
        if len(rs) == 1:
            t = ("1", rs[0][1], P["default"], R.inb(rs[0][0], f)) + ((rs[0][3],) if with_quick else ())
        else:
            t = ("2", relation(rs[0][0], rs[1][0]), rs[0][1], rs[1][1], P["default"], (R.inb(rs[0][0], f), R.inb(rs[1][0], f))) \
                + (((rs[0][3], rs[1][3]),) if with_quick else ())
        if t not in seen: seen.add(t); S.append((P, f))
    n_types = len(S)
    for f in range(N):
        for P in ({"rules": [], "default": 1}, {"rules": [], "default": 0},
                  {"rules": [((f, f), 1, 0, 0)], "default": 0}, {"rules": [((f, f), 0, 0, 0)], "default": 1}):
            S.append((P, f))
    return S, n_types

def sweep(decide, U, extra=()):
    pols = {}
    for (P, f) in list(U) + [pf for S in extra for pf in S]: pols.setdefault(pkey(P), P)
    resp = {}
    for k in sorted(pols, key=str):
        d = decide(pols[k])
        for f in range(N): resp[(k, f)] = d[f]
    return resp

def consistent(H, suite, resp):
    return [h for h in H if all(ev(h, P, f) == resp[(pkey(P), f)] for (P, f) in suite)]

def report(name, resp, U, suites, H, label):
    dh = {h: sum(1 for (P, f) in U if ev(h, P, f) != resp[(pkey(P), f)]) / len(U) for h in H}
    eps = min(dh.values()); cons_all = [h for h in H if dh[h] == 0.0]
    print("\n--- %s vs class %s: eps = %.4f, consistent with all %d probes: %s" % (name, label, eps, len(U), cons_all))
    for sn, S in suites.items():
        c = consistent(H, S, resp)
        print("  %-6s (%3d probes): consistent hypotheses %-22s -> %s" % (sn, len(S), c, "DETECTED" if not c else "accepted"))
    if eps > 0:
        k = len(H)
        bad = {h: {i for i, (P, f) in enumerate(U) if ev(h, P, f) != resp[(pkey(P), f)]} for h in H}
        rnd = random.Random(2026)
        print("  random probing: sufficient n for delta=.05: %d, necessary %d" % (math.ceil(math.log(k / .05) / eps), math.ceil((1 - eps) * math.log(1 / .05) / eps)))
        for n in (8, 24, 56, 200, 600, 1500):
            miss, T = 0, 4000
            for _ in range(T):
                S = [rnd.randrange(len(U)) for _ in range(n)]
                if any(all(i not in bad[h] for i in S) for h in H): miss += 1
            print("    n=%4d  empirical miss=%.4f  (MC s.e. <= %.4f)" % (n, miss / T, 0.5 / math.sqrt(T)))

def part_E():
    print("kernel:", R.sh("uname -r").stdout.strip(), " python:", sys.version.split()[0])
    # ------------- routing
    print("\n################ routing ################")
    orc = X.RouteOracle()
    U = universe([(bx, a, 0, 0) for bx in X.AL for a in (0, 1)])
    cls = classes(U, H8); s_id, _ = greedy(U, [K[0] for K in cls]); s_cc, nt = build_scc(U, False)
    print("pool %d probes; S_id %d probes; S_cc %d probes (%d interaction types + 16 per-flow)" % (len(U), len(s_id), len(s_cc), nt))
    E = {"ip-route": lambda P: X.route_text(P, "first"), "ip-rule": X.rule_text, "ip-route-revtie": lambda P: X.route_text(P, "rev")}
    for eng, mk in E.items():
        resp = sweep(lambda P: orc.decisions(mk(P)), U, (s_id, s_cc))
        report(eng, resp, U, {"S_id": s_id, "S_cc": s_cc}, H8, "H8")
    # ------------- nginx
    print("\n################ nginx ################")
    ng = X.NgxOracle()
    def dupfree(P):
        k = [(X.pfx(r[0]), r[3]) for r in P["rules"]]; return len(k) == len(set(k))
    singles = [b for b in X.AL if b[0] == b[1]]
    U1 = [(P, f) for (P, f) in universe([(bx, a, 0, 0) for bx in X.AL for a in (0, 1)]) if dupfree(P)]
    rs2 = [(bx, a, 0, 0) for bx in X.AL for a in (0, 1)] + [(bx, a, 0, 1) for bx in singles for a in (0, 1)]
    U2 = [(P, f) for (P, f) in universe(rs2) if dupfree(P)]
    cls1 = classes(U1, H8); sid1, _ = greedy(U1, [K[0] for K in cls1]); scc1, nt1 = build_scc(U1, False)
    resp1 = sweep(lambda P: ng.decisions(P), U1, (sid1, scc1))
    print("nginx-prefix pool %d probes; S_id %d; S_cc %d" % (len(U1), len(sid1), len(scc1)))
    report("nginx-prefix", resp1, U1, {"S_id": sid1, "S_cc": scc1}, H8, "H8")
    cls2 = classes(U2, H8); sid2, _ = greedy(U2, [K[0] for K in cls2]); scc2, nt2 = build_scc(U2, False); sccq, ntq = build_scc(U2, True)
    cls9 = classes(U2, H9); sid9, _ = greedy(U2, [K[0] for K in cls9])
    resp2 = sweep(lambda P: ng.decisions(P), U2, (sid2, scc2, sccq, sid9))
    print("\nnginx-exact pool %d probes; S_id %d; S_cc %d (%d types); S_ccq %d (%d types)" % (len(U2), len(sid2), len(scc2), nt2, len(sccq), ntq))
    report("nginx-exact", resp2, U2, {"S_id": sid2, "S_cc": scc2, "S_ccq": sccq}, H8, "H8")
    report("nginx-exact", resp2, U2, {"S_id9": sid9, "S_cc": scc2, "S_ccq": sccq}, H9, "H9 = H8+QBM")
    ng.close()

if __name__ == "__main__":
    part_E()
