import itertools, random, math, json
random.seed(20261022)
PERMIT, DENY = 1, 0
HYP = ["FM", "LM", "PR", "BM"]

def vol(box):
    v = 1
    for (a, b) in box: v *= (b - a + 1)
    return v

def inbox(box, f):
    return all(a <= x <= b for (a, b), x in zip(box, f))

def sig(P, f):
    return tuple(i for i, r in enumerate(P["rules"]) if inbox(r[0], f))

def winner(h, P, S):
    R = P["rules"]
    if h == "FM": return min(S)
    if h == "LM": return max(S)
    if h == "PR":
        m = max(R[i][2] for i in S); return min(i for i in S if R[i][2] == m)
    if h == "BM":
        m = min(vol(R[i][0]) for i in S); return min(i for i in S if vol(R[i][0]) == m)

def ev(h, P, f):
    S = sig(P, f)
    return P["rules"][winner(h, P, S)][1] if S else P["default"]

# ---------- (1) minimal distinguishing suite, d=1, N=4 ----------
N = 4
boxes = [((a, b),) for a in range(N) for b in range(a, N)]
rules = [(bx, act, pr) for bx in boxes for act in (0, 1) for pr in (0, 1, 2)]
vec_example = {}
for n in (1, 2, 3):
    for rs in itertools.product(rules, repeat=n):
        for dflt in (0, 1):
            P = {"rules": list(rs), "default": dflt}
            for f in range(N):
                v = tuple(ev(h, P, (f,)) for h in HYP)
                key = v
                if key not in vec_example or len(vec_example[key][0]["rules"]) > n:
                    vec_example[key] = (P, f)
vecs = list(vec_example)
pairs = list(itertools.combinations(range(4), 2))
def separates(vs):
    return all(any(v[i] != v[j] for v in vs) for i, j in pairs)
irredundant = separates(vecs)
minsize = None; minsuites = []
for k in range(1, 5):
    found = [c for c in itertools.combinations(vecs, k) if separates(c)]
    if found:
        minsize = k; minsuites = found; break
# choose the suite with fewest total rules
def cost(c): return sum(len(vec_example[v][0]["rules"]) for v in c)
best = min(minsuites, key=cost)
print("distinct response vectors:", len(vecs), "irredundant:", irredundant)
print("min distinguishing suite size:", minsize, "; number of minimum suites (over distinct response vectors):", len(minsuites))
for v in best:
    P, f = vec_example[v]
    print("probe", [(r[0][0], "permit" if r[1] else "deny", r[2]) for r in P["rules"]], "default", "permit" if P["default"] else "deny", "flow", f, "-> responses", dict(zip(HYP, ["permit" if x else "deny" for x in v])))


# ---------- (2) cell compression and (3) Q2 / locality, d=2, N=6 ----------
random.seed(20261022)
D, NN = 2, 6
def rbox():
    return tuple((lambda a: (a, random.randrange(a, NN)))(random.randrange(NN)) for _ in range(D))
def subbox(bx):
    return tuple((lambda a: (a, random.randrange(a, b + 1)))(random.randrange(a, b + 1)) for (a, b) in bx)
def cuts(rs, extra=()):
    cs = []
    for j in range(D):
        s = {0}
        for bx in [r[0] for r in rs] + list(extra):
            a, b = bx[j]; s.add(a)
            if b + 1 < NN: s.add(b + 1)
        cs.append(sorted(s))
    return cs
def segments(cs):
    return [[(s, (c[i + 1] - 1) if i + 1 < len(c) else NN - 1) for i, s in enumerate(c)] for c in cs]
allF = list(itertools.product(range(NN), repeat=D))
cell_ok = True; maxratio = 0; trials = 0
for _ in range(3000):
    n = random.randint(1, 5)
    P = {"rules": [(rbox(), random.randint(0, 1), random.randint(0, 2)) for _ in range(n)], "default": random.randint(0, 1)}
    segs = segments(cuts(P["rules"]))
    ncells = math.prod(len(s) for s in segs)
    assert len({sig(P, f) for f in allF}) <= (2 * n + 1) ** D and ncells <= (2 * n + 1) ** D
    maxratio = max(maxratio, ncells / (2 * n + 1) ** D)
    for h in HYP:
        for cell in itertools.product(*segs):
            dec = ev(h, P, tuple(c[0] for c in cell))
            for f in itertools.product(*[range(c[0], c[1] + 1) for c in cell]):
                if ev(h, P, f) != dec: cell_ok = False
    trials += 1
print("cell-compression policies:", trials, "| all cells decision-constant (4 semantics):", cell_ok, "| max cells/(2n+1)^d:", round(maxratio, 3))

agree = True; locality = True; held = viol = 0; viol_exact = 0; viol_broader = 0; tot = 0
for _ in range(2000):
    n = random.randint(1, 4)
    rs = [(rbox(), random.randint(0, 1), random.randint(0, 2)) for _ in range(n)]
    P = {"rules": rs, "default": random.randint(0, 1)}
    nb = rbox(); new = (nb, 1, random.randint(0, 2))
    M = subbox(nb) if random.random() < 0.5 else nb
    pos = random.randint(0, n)
    P2 = {"rules": rs[:pos] + [new] + rs[pos:], "default": P["default"]}
    segs = segments(cuts(P2["rules"], [M]))
    for h in HYP:
        d_bf = {f for f in allF if ev(h, P, f) != ev(h, P2, f)}
        if not all(inbox(nb, f) for f in d_bf): locality = False
        d_cell = set()
        for cell in itertools.product(*segs):
            if ev(h, P, tuple(c[0] for c in cell)) != ev(h, P2, tuple(c[0] for c in cell)):
                d_cell |= set(itertools.product(*[range(c[0], c[1] + 1) for c in cell]))
        if d_bf != d_cell: agree = False
        tot += 1
        if all(inbox(M, f) for f in d_bf): held += 1
        else:
            viol += 1
            if M == nb: viol_exact += 1
            else: viol_broader += 1
print("Q2 trials:", tot, "| cell-diff == brute-force diff:", agree, "| locality lemma held:", locality)
print("Q2 held:", held, "| violated:", viol, "(with B == M:", viol_exact, "; with M strictly inside B:", viol_broader, ")")

# ---------- (4) Monte Carlo for detection bounds ----------

pool = []
for n in (1, 2):
    for rs in itertools.product(rules, repeat=n):
        for dflt in (0, 1):
            P = {"rules": list(rs), "default": dflt}
            for f in range(N):
                pool.append((P, f))
M_ = len(pool)
H = {h: [ev(h, P, (f,)) for P, f in pool] for h in HYP}
base = H["PR"]
rng = random.Random(7)
res = []
for eps in (0.02, 0.05):
    dev = [1 if rng.random() < eps else 0 for _ in range(M_)]
    T = [b ^ d for b, d in zip(base, dev)]
    dist = {h: sum(1 for a, b in zip(T, H[h]) if a != b) / M_ for h in HYP}
    emin = min(dist.values())
    for n in (50, 100, 200):
        miss = 0; trials = 20000
        for _ in range(trials):
            idx = [rng.randrange(M_) for _ in range(n)]
            cons = [h for h in HYP if all(T[i] == H[h][i] for i in idx)]
            if cons: miss += 1
        lo = (1 - emin) ** n; hi = min(1, sum((1 - dist[h]) ** n for h in HYP))
        res.append((eps, round(emin, 4), n, miss / trials, lo, hi))
        print("eps_target", eps, "eps_min", round(emin, 4), "n", n, "empirical miss", round(miss / trials, 4), "lower", "%.3e" % lo, "upper", "%.3e" % hi)
