#!/usr/bin/env python3
"""Brute-force check that every member of H8 is insertion-stable (Lemma 5 in the paper).

For every hypothesis h in H8, every policy of one or two rules over the full rule set (boxes, actions,
priorities {0,1,2}, quick flag), every inserted rule, every insertion position and every nonempty set S of
rule indices, check  w_h(P', iota_p(S)) == iota_p(w_h(P, S)).
Standard library only; imports the winner maps of real_engine_experiment.py."""
import itertools, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import real_engine_experiment as R

rules = R.rules_for(True, True, (0, 1, 2))
checked = 0
bad = 0
for h in R.H8:
    n_h = 0
    for n in (1, 2):
        for combo in itertools.product(rules, repeat=n):
            P = {"rules": list(combo), "default": 0}
            idx = list(range(n))
            subsets = [S for k in range(1, n + 1) for S in itertools.combinations(idx, k)]
            for new in rules:
                for p in range(n + 1):
                    Q = {"rules": list(combo[:p]) + [new] + list(combo[p:]), "default": 0}
                    iota = lambda i: i if i < p else i + 1
                    for S in subsets:
                        n_h += 1
                        if R.winner(h, Q, tuple(iota(i) for i in S)) != iota(R.winner(h, P, S)):
                            bad += 1
    print("%-5s checked %d (policy, rule, position, subset) cases" % (h, n_h))
    checked += n_h
print("total checked %d, violations %d" % (checked, bad))
sys.exit(1 if bad else 0)
