import itertools, random, math, json
from collections import defaultdict

# Rule = (box, action, priority, quick); policy = {"rules": [...], "default": d}; d=1 flow dimension, flows 0..N-1
N = 4
H8 = ["FM", "LM", "PRhi", "PRlo", "BM", "PO", "DO", "LMQ"]
H4 = ["FM", "LM", "PRhi", "BM"]

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
    out = []
    for bx in boxes:
        for a in ((0, 1) if allow_deny else (1,)):
            for p in prios:
                for q in ((0, 1) if allow_quick else (0,)):
                    out.append((bx, a, p, q))
    return out

def universe(rs, distinct_prios=False, maxn=2):
    U = []
    for n in range(1, maxn + 1):
        for combo in itertools.product(rs, repeat=n):
            if distinct_prios and len({r[2] for r in combo}) != n: continue
            for d in (0, 1):
                P = {"rules": list(combo), "default": d}
                for f in range(N):
                    U.append((P, f))
    return U

def vectors(U, H):
    vec = {}
    for (P, f) in U:
        v = tuple(ev(h, P, f) for h in H)
        if v not in vec or len(vec[v][0]["rules"]) > len(P["rules"]): vec[v] = (P, f)
    return vec

def classes(U, H):
    sigs = defaultdict(list)
    cols = {h: tuple(ev(h, P, f) for (P, f) in U) for h in H}
    for h in H: sigs[cols[h]].append(h)
    return list(sigs.values())

def fmt(P, f=None):
    rs = ["(%s,%s,p%d%s)" % (list(r[0]), "permit" if r[1] else "deny", r[2], ",q" if r[3] else "") for r in P["rules"]]
    return "[" + ", ".join(rs) + "] default=" + ("permit" if P["default"] else "deny") + (" flow=%d" % f if f is not None else "")

# ------------- E1: class H8 on the full 2-rule universe -------------
Ufull = universe(rules_for())
vec8 = vectors(Ufull, H8)
cl8 = classes(Ufull, H8)
print("E1  |U| probes:", len(Ufull), "| distinct response vectors over H8:", len(vec8), "| observational classes:", len(cl8), "(irredundant:", len(cl8) == len(H8), ")")
pairs = list(itertools.combinations(range(len(H8)), 2))
def sep(vs): return all(any(v[i] != v[j] for v in vs) for i, j in pairs)
vl = list(vec8)
minsize = None
for k in range(1, 6):
    hit = None
    for c in itertools.combinations(vl, k):
        if sep(c): hit = c; break
    if hit: minsize = k; best = hit; break
print("E1  minimum distinguishing suite size for k=%d: %d (lower bound ceil(log2 k)=%d, upper bound k-1=%d)" % (len(H8), minsize, math.ceil(math.log2(len(H8))), len(H8) - 1))
for v in best:
    P, f = vec8[v]; print("      probe", fmt(P, f), "->", dict(zip(H8, ["permit" if x else "deny" for x in v])))

# Algorithm 1 (greedy, fixed pool order)
def greedy(U, H):
    resp = {}
    order = []
    seen = {}
    for (P, f) in U:
        v = tuple(ev(h, P, f) for h in H)
        if v not in seen: seen[v] = (P, f); order.append(v)
    part = [list(range(len(H)))]
    S = []
    while any(len(K) > 1 for K in part):
        t = None
        for v in order:
            if any(len({v[i] for i in K}) > 1 for K in part): t = v; break
        if t is None: return None, part
        S.append(seen[t]); new = []
        for K in part:
            for b in (0, 1):
                kk = [i for i in K if t[i] == b]
                if kk: new.append(kk)
        part = new
    return S, part
S8, _ = greedy(Ufull, H8)
print("E1  Algorithm 1 (greedy) suite size on H8:", len(S8), "(bound k-1 = %d)" % (len(H8) - 1))

# ------------- E2: engines from vendor documentation -------------
engines = {
    "iptables (flat chain, ACCEPT/DROP)": dict(h="FM", rs=rules_for(True, False, (0,)), distinct=False),
    "pf (pass/block, quick)":             dict(h="LMQ", rs=rules_for(True, True, (0,)), distinct=False),
    "AWS NACL (rule numbers)":            dict(h="PRlo", rs=rules_for(True, False, (0, 1, 2)), distinct=True),
    "Azure NSG (priorities)":             dict(h="PRlo", rs=rules_for(True, False, (0, 1, 2)), distinct=True),
    "AWS security group (allow-only)":    dict(h="PO", rs=rules_for(False, False, (0,)), distinct=False),
}
print("\nE2  identification on simulated engines (class H8, probe universe restricted to what each engine can express)")
for name, e in engines.items():
    U = universe(e["rs"], e["distinct"])
    cl = classes(U, H8)
    truth = [K for K in cl if e["h"] in K][0]
    reps = [K[0] for K in cl]
    S, part = greedy(U, reps)
    print("  %-38s |U|=%6d  observational classes=%d  true semantics %s  its class=%s  greedy suite separating the classes: %s" %
          (name, len(U), len(cl), e["h"], truth, "%d probes" % len(S)))

# ------------- E3: blind spot, pf quick -------------
print("\nE3  class without 'quick' vs with 'quick', target = pf model (LMQ)")
suite4 = [
    ({"rules": [(( 0, 0), 0, 0, 0), ((0, 0), 1, 1, 0)], "default": 0}, 0),
    ({"rules": [((0, 1), 0, 0, 0), ((0, 0), 1, 0, 0)], "default": 0}, 0),
]
resp = [ev("LMQ", P, f) for P, f in suite4]
cons4 = [h for h in H4 if all(ev(h, P, f) == r for (P, f), r in zip(suite4, resp))]
print("  H4 suite (no quick probes) against pf: consistent set =", cons4)
Pprod = {"rules": [((1, 1), 0, 0, 1)], "default": 1}   # existing quick deny on flow 1, pf default pass
M = (0, 2)
def insert(P, pos, rule):
    return {"rules": P["rules"][:pos] + [rule] + P["rules"][pos:], "default": P["default"]}
def q1(h, P):
    return all(ev(h, P, f) == 1 for f in range(M[0], M[1] + 1))
def plan(h, qs):
    for pos in range(0, len(Pprod["rules"]) + 1):
        for q in qs:
            P2 = insert(Pprod, pos, (M, 1, 0, q))
            if q1(h, P2): return pos, q, P2
    return None
for assumed, qs in (("LM", (0,)), ("FM", (0,)), ("LMQ", (0, 1))):
    pl = plan(assumed, qs)
    if pl is None: print("  assumed", assumed, ": no plan"); continue
    pos, q, P2 = pl
    print("  assumed %-4s plan: insert permit %s at position %d, quick=%d -> predicted Q1 true; actual pf Q1 = %s" % (assumed, list(M), pos, q, q1("LMQ", P2)))

# ------------- E4: out-of-class target -------------
print("\nE4  out-of-class engine: priority order with ties to the LATER rule (not in H8)")
def ev_late(P, f):
    S = sig(P, f)
    if not S: return P["default"]
    R = P["rules"]; m = max(R[i][2] for i in S)
    return R[max(i for i in S if R[i][2] == m)][1]
cons = [h for h in H8 if all(ev(h, P, f) == ev_late(P, f) for (P, f) in S8)]
print("  greedy H8 suite: consistent set =", cons, "(empty = deviation detected)")
bad = {h: sum(1 for (P, f) in Ufull if ev(h, P, f) != ev_late(P, f)) / len(Ufull) for h in H8}
print("  uniform deviation distance to each member over the 2-rule pool: min eps = %.4f (member %s)" % (min(bad.values()), min(bad, key=bad.get)))
