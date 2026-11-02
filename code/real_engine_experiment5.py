#!/usr/bin/env python3
"""
Blind-style detection experiment on real Linux netfilter engines.

Purpose: the structured suite S_cc of experiment2/4 was designed after the first deviation was seen, so
its success is not a blind result. Here the deviating engines are produced by a seeded generator that was
written and fixed before any engine was run, the suites are the frozen ones (S_id, S_cc built by the
unchanged rule of experiment4), and engines may deviate only on policies with three rules, which no suite
built from a pool of at most two rules can contain. One extra suite S_3 applies the same construction
idea to three-rule policies (one probe per action pattern, default and containment pattern); it is
defined here before the run and its result is reported whatever it is.

Engines (all real kernel behavior; every policy is installed with a single `nft -f` call):
  T0 decoy  in-class engines with extra structure (no alarm expected)
  T1 late split(k)   rules after the first k go to a second base chain of lower precedence; the second
                     chain exists only when the policy has more than k rules
  T2 late drop(m,f)  a second table that drops flow f, installed only when the policy has >= m rules
  T3 always drop(f)  a second table that always drops flow f (the type of deviation found in experiment2)
Generator: random.Random(GEN_SEED) draws the type and parameters, see GENERATE.

Evaluation distribution mu: the rule count is uniform on {1,2,3}, then the policy is uniform, then the
flow is uniform. mu is sampled with SAMPLE policies per rule count. eps(h) is the weighted disagreement of
hypothesis h with the engine on that sample; eps is the minimum over H8. One extra engine deviates only at
four rules (beyond the reach of every suite and of mu); it is checked separately on four-rule policies.

Needs root, ip, nft, iptables-legacy, and real_engine_experiment*.py alongside.
Usage: python3 real_engine_experiment5.py [--seed S] [--engines N] [--sample K] [--sample4 K] [--mc T]
"""
import itertools, math, os, random, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import real_engine_experiment as R
import real_engine_experiment4 as E4
from real_engine_experiment import N, BASE, H8, ev, universe, classes, greedy, fmt, pkey, sh

import argparse
_ap = argparse.ArgumentParser(description="Blind-style detection experiment (needs root, ip, nft).")
_ap.add_argument("--seed", type=int, default=20261022, help="generator seed (default: the seed used in the paper)")
_ap.add_argument("--engines", type=int, default=12, help="number of generated deviating engines")
_ap.add_argument("--sample", type=int, default=300, help="policies per rule count in the evaluation sample")
_ap.add_argument("--sample4", type=int, default=200, help="four-rule policies for the beyond-reach engine")
_ap.add_argument("--only", default="", help="comma-separated engine names to run (e.g. x4); the default runs all")
_ap.add_argument("--mc", type=int, default=4000, help="Monte Carlo trials for random probing")
_ARGS = _ap.parse_args()
GEN_SEED = _ARGS.seed
SAMPLE = _ARGS.sample
SAMPLE4 = _ARGS.sample4
MC = _ARGS.mc

RS = R.rules_for(True, False, (0,))        # boxes x {deny,permit}; what iptables/nft can express

# ------------------------------------------------------------------ engines
def nft_engine(P, k=None, drop=None, always=False, m=None, decoy=None):
    d = "accept" if P["default"] else "drop"
    rules = P["rules"]
    def r(x): return "udp dport %d-%d %s" % (BASE + x[0][0], BASE + x[0][1], "accept" if x[1] else "drop")
    split = k is not None and len(rules) > k
    A, B = (rules[:k], rules[k:]) if split else (rules, [])
    L = ["flush ruleset", "table ip fw {", " chain a { type filter hook input priority 0; policy %s;" % d]
    L += ["  " + r(x) for x in A]
    L += [" }"]
    if split:
        L += [" chain b { type filter hook input priority 10; policy %s;" % d] + ["  " + r(x) for x in B] + [" }"]
    L += ["}"]
    if drop is not None and (always or len(rules) >= m):
        L += ["table ip x {", " chain c { type filter hook input priority 5;", "  udp dport %d drop" % (BASE + drop), " }", "}"]
    if decoy == "accept":
        L += ["table ip y {", " chain c { type filter hook input priority 5;", "  udp dport %d accept" % (BASE + 2), " }", "}"]
    return "\n".join(L) + "\n"

def make_engine(spec):
    t = spec["type"]
    if t == "T0":  return lambda P: sh("ip netns exec fwB nft -f -", inp=nft_engine(P, decoy="accept"))
    if t == "T0u": return lambda P: sh("ip netns exec fwB nft -f -", inp=nft_engine(P))
    if t == "T1":  return lambda P: sh("ip netns exec fwB nft -f -", inp=nft_engine(P, k=spec["k"]))
    if t == "T2":  return lambda P: sh("ip netns exec fwB nft -f -", inp=nft_engine(P, drop=spec["f"], m=spec["m"]))
    if t == "T3":  return lambda P: sh("ip netns exec fwB nft -f -", inp=nft_engine(P, drop=spec["f"], always=True))
    raise ValueError(t)

def GENERATE(n=12):
    rnd = random.Random(GEN_SEED)
    out = []
    for i in range(n):
        t = rnd.choice(["T1", "T2", "T2", "T3"])
        s = {"name": "g%02d" % i, "type": t}
        if t == "T1": s["k"] = rnd.choice([1, 2])
        if t == "T2": s["m"] = rnd.choice([2, 3]); s["f"] = rnd.randrange(N)
        if t == "T3": s["f"] = rnd.randrange(N)
        out.append(s)
    return out

def spec_str(s): return s["name"] + " " + s["type"] + "".join(" %s=%s" % (k, v) for k, v in s.items() if k not in ("name", "type"))

# ------------------------------------------------------------------ pools, suites
def sample_policies(rnd, n_rules, count):
    seen, out = set(), []
    count = min(count, 2 * len(RS) ** n_rules)      # the one-rule pool has only 40 distinct policies
    while len(out) < count:
        P = {"rules": [rnd.choice(RS) for _ in range(n_rules)], "default": rnd.randrange(2)}
        k = pkey(P)
        if k not in seen: seen.add(k); out.append(P)
    return out

def build_s3():
    """Same idea as S_cc, one level up: one probe per (actions, default, containment) pattern of three rules."""
    seen, S = set(), []
    for combo in itertools.product(RS, repeat=3):
        for dflt in (0, 1):
            for f in range(N):
                P = {"rules": list(combo), "default": dflt}
                t = (tuple(r[1] for r in combo), dflt, tuple(R.inb(r[0], f) for r in combo))
                if t not in seen: seen.add(t); S.append((P, f))
        if len(seen) >= 128: break           # every pattern is reached within the first few hundred combos
    n_types = len(S)
    for f in range(N):
        for P in ({"rules": [], "default": 1}, {"rules": [], "default": 0},
                  {"rules": [((f, f), 1, 0, 0)], "default": 0}, {"rules": [((f, f), 0, 0, 0)], "default": 1}):
            S.append((P, f))
    return S, n_types

def detects(suite, resp):
    return not any(all(ev(h, P, f) == resp[(pkey(P), f)] for (P, f) in suite) for h in H8)

def consistent(suite, resp):
    return [h for h in H8 if all(ev(h, P, f) == resp[(pkey(P), f)] for (P, f) in suite)]

# ------------------------------------------------------------------ main
def main():
    import fcntl
    global _LOCK
    _LOCK = open("/tmp/real_engine_experiment5.lock", "w")
    try: fcntl.flock(_LOCK, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError: sys.exit("another run of this experiment is active (it shares the network namespaces); stop it first")
    t0 = time.time()
    print("kernel:", sh("uname -r").stdout.strip(), "| nft:", sh("nft --version").stdout.strip())
    orc = R.Oracle()
    rnd = random.Random(99)

    Ue2 = universe(RS, maxn=2)
    cls = classes(Ue2, H8)
    reps = [K[0] for K in cls]
    S_id, _ = greedy(Ue2, reps)
    S_cc, ncc = E4.build_scc(Ue2, False)
    S_3, n3 = build_s3()
    print("suites: S_id %d probes, S_cc %d probes (%d interaction types), S_3 %d probes (%d patterns)" % (len(S_id), len(S_cc), ncc, len(S_3), n3))

    specs = [{"name": "d0", "type": "T0u"}, {"name": "d1", "type": "T0"}] + GENERATE(_ARGS.engines)
    specs.append({"name": "x4", "type": "T2", "m": 4, "f": 1})
    if _ARGS.only: specs = [s for s in specs if s["name"] in _ARGS.only.split(",")]
    print("engines (generator seed %d):" % GEN_SEED)
    for s in specs: print("   ", spec_str(s))

    strata = {c: sample_policies(rnd, c, SAMPLE) for c in (1, 2, 3)}
    four = sample_policies(rnd, 4, SAMPLE4)

    rows = []
    for s in specs:
        eng = make_engine(s)
        R.flush_all()
        R.ENGINES["_cur"] = eng
        c_all = orc.decisions("_cur", {"rules": [], "default": 1}, wait=0.5)
        c_none = orc.decisions("_cur", {"rules": [], "default": 0}, wait=0.15)
        want_all = tuple(0 if (s["type"] == "T3" and g == s["f"]) else 1 for g in range(N))   # an always-drop engine must block its flow
        assert c_all == want_all and c_none == (0, 0, 0, 0), "controls failed for %s: permit-all gave %s (want %s), deny-all gave %s" % (s["name"], c_all, want_all, c_none)
        cache = {}
        def get(P):
            k = pkey(P)
            if k not in cache: cache[k] = orc.decisions("_cur", P)
            return cache[k]
        resp = {}
        def fill(probes):
            for (P, f) in probes:
                d = get(P)
                for g in range(N): resp[(pkey(P), g)] = d[g]
        _t=time.time(); fill(S_id); fill(S_cc); fill(S_3)
        print('   [%s] suites installed in %.0fs' % (s['name'], time.time()-_t), flush=True)
        pool, wts = [], []
        for c, pols in strata.items():
            for P in pols:
                d = get(P)
                for f in range(N):
                    resp[(pkey(P), f)] = d[f]; pool.append((P, f)); wts.append(1.0 / (3 * len(pols) * N))
        print('   [%s] eval sample installed, %.0fs total' % (s['name'], time.time()-t0), flush=True)
        dh = {h: sum(w for (P, f), w in zip(pool, wts) if ev(h, P, f) != resp[(pkey(P), f)]) for h in H8}
        eps = min(dh.values())
        res = {"id": detects(S_id, resp), "cc": detects(S_cc, resp), "s3": detects(S_3, resp)}
        # random probing: miss = some hypothesis agrees with the engine on every drawn probe
        bad = {h: {i for i, (P, f) in enumerate(pool) if ev(h, P, f) != resp[(pkey(P), f)]} for h in H8}
        cum = []; acc = 0.0
        for w in wts: acc += w; cum.append(acc)
        import bisect
        rr = random.Random(5)
        miss = {}
        for n in (56, 200, 1200):
            m = 0
            for _ in range(MC):
                S = [min(bisect.bisect_left(cum, rr.random() * acc), len(pool) - 1) for _ in range(n)]
                if any(all(i not in bad[h] for i in S) for h in H8): m += 1
            miss[n] = m / MC
        # visible at all within the two-rule pool? (check only the 1- and 2-rule strata)
        vis2 = any(resp[(pkey(P), f)] != ev(min(H8, key=lambda h: dh[h]), P, f) for c in (1, 2) for P in strata[c] for f in range(N))
        # four-rule check
        dev4 = 0
        for P in four:
            d = get(P)
            dev4 += sum(1 for f in range(N) if d[f] != ev("FM", P, f))
        near = [h for h in H8 if dh[h] == eps]
        print("%-3s %-16s eps=%.4f nearest=%-12s  S_id:%s  S_cc:%s  S_3:%s  random miss n=56/200/1200: %.3f/%.3f/%.3f  | 1-2 rule sample deviates from nearest: %s | 4-rule FM-disagreement: %.3f"
              % (s["name"], s["type"], eps, ",".join(near), "detect" if res["id"] else "accept", "detect" if res["cc"] else "accept",
                 "detect" if res["s3"] else "accept", miss[56], miss[200], miss[1200], vis2, dev4 / (4.0 * len(four))))
        rows.append((s, eps, res, miss))
        sys.stdout.flush()

    print("\nSUMMARY")
    dev = [r for r in rows if r[0]["type"] not in ("T0", "T0u")]
    for key, label in (("id", "S_id (3 probes)"), ("cc", "S_cc"), ("s3", "S_3")):
        print("%-16s detects %d of %d deviating engines; alarms on %d of 2 in-class decoys" %
              (label, sum(1 for r in dev if r[2][key]), len(dev), sum(1 for r in rows if r[0]["type"] in ("T0", "T0u") and r[2][key])))
    print("total oracle installs %d, wall time %.0fs" % (orc.calls, time.time() - t0))

if __name__ == "__main__":
    main()
