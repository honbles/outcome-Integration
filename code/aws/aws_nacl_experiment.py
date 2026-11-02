#!/usr/bin/env python3
"""
Real AWS network ACL experiment for the policy-semantics identification paper.

The oracle is a real network ACL attached to the subnet of an EC2 instance that runs aws_receiver.py. A policy
is written into the ACL as inbound entries, one UDP datagram per flow is sent to the instance from this machine
(whose IP is allowed in the security group), and a flow is permitted iff the receiver saw it.

Model rule (box, action, priority) becomes an inbound UDP entry numbered 100*(priority+1) with the box as port range.
Default permit becomes an allow-all-UDP entry numbered 32000; default deny is the ACL's built-in final deny.
Priorities in one policy are distinct (ACL rule numbers are unique). Quick flags are not expressible.

What it does (same protocol as the netfilter experiments):
  1. controls (permit-all, deny-all, deny one flow);
  2. the identification suite from the greedy construction over the observational classes of H8 on the pool
     of ACL-expressible probes, and the consistent set it gives;
  3. a sweep of a random sample of policies (default 150), with d_h per hypothesis, and a determinism re-probe.
Expected under the documentation (lowest rule number wins): consistent set {PRlo}.

Usage:
  python3 aws_nacl_experiment.py --region R --nacl-id acl-... --receiver IP --token T [--sweep 150] [--settle 6]
  python3 aws_nacl_experiment.py --simulate          self-test: ACL entries evaluated in Python, no AWS
Needs boto3 (not in --simulate), real_engine_experiment.py two folders up or alongside.
"""
import argparse, os, random, socket, sys, time, json, urllib.request
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, here); sys.path.insert(0, os.path.dirname(here))
import real_engine_experiment as R
from real_engine_experiment import N, BASE, H8, ev, universe, classes, greedy, fmt, pkey

ap = argparse.ArgumentParser()
ap.add_argument("--region"); ap.add_argument("--nacl-id"); ap.add_argument("--receiver"); ap.add_argument("--token")
ap.add_argument("--sweep", type=int, default=150, help="random policies to sweep (0 = whole pool, slow)")
ap.add_argument("--settle", type=float, default=6.0, help="seconds to wait after changing the ACL")
ap.add_argument("--simulate", action="store_true")
ap.add_argument("--check-settle", action="store_true", help="only test whether the answers depend on the settle time (3, 6, 12 s) and exit")
ap.add_argument("--reprobe", type=int, default=40, help="policies re-probed in shuffled order for the determinism check")
ARGS = ap.parse_args()

TEST_NUMBERS = (100, 200, 300, 32000)

def entries_for(P):
    """Desired inbound test entries: {rule number: (allow?, port_from, port_to)}."""
    E = {}
    prios = [r[2] for r in P["rules"]]
    assert len(set(prios)) == len(prios), "priorities must be distinct in a policy"
    for (bx, a, p, _q) in P["rules"]:
        E[100 * (p + 1)] = (bool(a), BASE + bx[0], BASE + bx[1])
    if P["default"] == 1: E[32000] = (True, 0, 65535)
    return E

def eval_acl(E):
    """AWS documentation: entries are evaluated from the lowest number; the first match applies; final rule denies."""
    out = []
    for f in range(N):
        port, dec = BASE + f, False
        for num in sorted(E):
            allow, lo, hi = E[num]
            if lo <= port <= hi: dec = allow; break
        out.append(1 if dec else 0)
    return tuple(out)

class Oracle:
    def __init__(self):
        self.calls, self.cur = 0, {}
        if ARGS.simulate: return
        import boto3
        self.ec2 = boto3.client("ec2", region_name=ARGS.region)
        for _ in range(60):                                   # wait until the receiver answers
            try: urllib.request.urlopen("http://%s:8080/seen?t=%s" % (ARGS.receiver, ARGS.token), timeout=4).read(); break
            except Exception: time.sleep(5)
        else: sys.exit("the receiver does not answer on port 8080: is it up, and is your current public IP the one in the security group?")
        self.snd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # clear any leftover test entries
        acl = self.ec2.describe_network_acls(NetworkAclIds=[ARGS.nacl_id])["NetworkAcls"][0]
        for e in acl["Entries"]:
            if not e["Egress"] and e["RuleNumber"] in TEST_NUMBERS: self.api("delete_network_acl_entry", NetworkAclId=ARGS.nacl_id, RuleNumber=e["RuleNumber"], Egress=False)

    def api(self, name, **kw):
        for i in range(6):
            try: return getattr(self.ec2, name)(**kw)
            except Exception as e:
                if "Throttl" in str(e) or "RequestLimit" in str(e): time.sleep(2 ** i); continue
                raise

    def apply(self, E):
        for num in TEST_NUMBERS:
            if num in E and self.cur.get(num) != E[num]:
                allow, lo, hi = E[num]
                kw = dict(NetworkAclId=ARGS.nacl_id, RuleNumber=num, Protocol="17", RuleAction="allow" if allow else "deny",
                          Egress=False, CidrBlock="0.0.0.0/0", PortRange={"From": lo, "To": hi})
                self.api("replace_network_acl_entry" if num in self.cur else "create_network_acl_entry", **kw)
            elif num not in E and num in self.cur:
                self.api("delete_network_acl_entry", NetworkAclId=ARGS.nacl_id, RuleNumber=num, Egress=False)
        self.cur = dict(E)

    def http(self, path):
        return json.loads(urllib.request.urlopen("http://%s:8080%s?t=%s" % (ARGS.receiver, path, ARGS.token), timeout=10).read())

    def decisions(self, P, settle=None):
        self.calls += 1
        E = entries_for(P)
        if ARGS.simulate: return eval_acl(E)
        self.apply(E); time.sleep(ARGS.settle if settle is None else settle)
        self.http("/reset")
        for rep in range(3):
            for f in range(N): self.snd.sendto(b"p%d" % f, (ARGS.receiver, BASE + f))
            time.sleep(0.15)
        time.sleep(0.6)
        seen = set(self.http("/seen"))
        return tuple(1 if (BASE + f) in seen else 0 for f in range(N))

def main():
    t0 = time.time()
    if not ARGS.simulate and not (ARGS.region and ARGS.nacl_id and ARGS.receiver and ARGS.token): sys.exit("need --region --nacl-id --receiver --token (or --simulate)")
    print("mode:", "SIMULATED (self-test)" if ARGS.simulate else "real AWS network ACL %s in %s" % (ARGS.nacl_id, ARGS.region), "| python", sys.version.split()[0])
    orc = Oracle()

    c_all = orc.decisions({"rules": [], "default": 1}); c_none = orc.decisions({"rules": [], "default": 0})
    c_one = orc.decisions({"rules": [((0, 0), 0, 0, 0)], "default": 1})
    c_ord = orc.decisions({"rules": [((0, 3), 1, 1, 0), ((0, 1), 0, 0, 0)], "default": 0})
    print("controls  permit-all %s (want 1111)  deny-all %s (want 0000)  deny flow0 %s (want 0111)  deny[0,1]@0 over permit[0,3]@1 %s (want 0011)" % (c_all, c_none, c_one, c_ord))
    assert c_all == (1, 1, 1, 1) and c_none == (0, 0, 0, 0) and c_one == (0, 1, 1, 1) and c_ord == (0, 0, 1, 1), "oracle controls failed"

    if ARGS.check_settle:
        probe_pols = [{"rules": [((0, 1), 0, 0, 0), ((0, 3), 1, 1, 0)], "default": 0}, {"rules": [((1, 2), 1, 0, 0), ((0, 3), 0, 2, 0)], "default": 1}, {"rules": [((0, 0), 1, 2, 0), ((0, 0), 0, 0, 0)], "default": 0}]
        for P in probe_pols:
            res = {s: orc.decisions(P, settle=s) for s in (3, 6, 12)}
            print("settle check", fmt(P), res, "AGREE" if len(set(res.values())) == 1 else "DISAGREE: use a longer --settle")
        return
    Ue = [(P, f) for (P, f) in universe(R.rules_for(True, False, (0, 1, 2)), maxn=2) if len({r[2] for r in P["rules"]}) == len(P["rules"])]
    pols = {}
    for (P, f) in Ue: pols.setdefault(pkey(P), P)
    print("ACL-expressible pool: %d probes, %d policies (1-2 rules, distinct priorities in {0,1,2}, both defaults, N=%d flows)" % (len(Ue), len(pols), N))
    cls = classes(Ue, H8); reps = [K[0] for K in cls]
    suite, _ = greedy(Ue, reps)
    print("observational classes of H8 on the pool:", cls)
    print("greedy identification suite: %d probes" % len(suite))
    for (P, f) in suite: print("   probe", fmt(P, f))
    sd = {}
    for (P, f) in suite: sd[(pkey(P), f)] = orc.decisions(P)[f]
    cons_suite = [h for h in H8 if all(ev(h, P, f) == sd[(pkey(P), f)] for (P, f) in suite)]
    print("consistent with the %d-probe suite: %s" % (len(suite), cons_suite))

    keys = sorted(pols, key=lambda k: str(k))
    if ARGS.sweep and ARGS.sweep < len(keys): keys = random.Random(5).sample(keys, ARGS.sweep)
    resp, ts = {}, time.time()
    for i, k in enumerate(keys):
        d = orc.decisions(pols[k])
        for f in range(N): resp[(k, f)] = d[f]
        if (i + 1) % 25 == 0: print("   swept %d/%d policies, %.0fs" % (i + 1, len(keys), time.time() - ts), flush=True)
    print("sweep: %d of the %d policies in the pool (a random sample), %d probe responses, %.0fs" % (len(keys), len(pols), len(resp), time.time() - ts))
    sample = random.Random(7).sample(keys, max(1, min(ARGS.reprobe, len(keys)))); mism = 0
    for k in sample:
        d = orc.decisions(pols[k]); mism += sum(1 for f in range(N) if d[f] != resp[(k, f)])
    print("determinism: re-probed %d policies in shuffled order, %d response mismatches (mismatches mean slow ACL propagation or a lost datagram; raise --settle)" % (len(sample), mism))
    U = [(P, f) for (P, f) in Ue if (pkey(P), f) in resp]
    dh = {h: sum(1 for (P, f) in U if ev(h, P, f) != resp[(pkey(P), f)]) / len(U) for h in H8}
    print("disagreement d_h with the real ACL over the %d swept probes: " % len(U) + "  ".join("%s=%.4f" % (h, dh[h]) for h in H8))
    cons_all = [h for h in H8 if dh[h] == 0.0]
    print("consistent with every swept probe: %s" % cons_all)
    if cons_all: print("VERDICT: in class on the swept sample; identified up to observational class %s" % cons_all)
    elif cons_suite: print("VERDICT: suite accepts %s but the sweep refutes every member (min eps=%.4f)" % (cons_suite, min(dh.values())))
    else: print("VERDICT: deviation detected by the suite; min eps=%.4f" % min(dh.values()))
    print("\ntotal policy installs %d, wall time %.0fs" % (orc.calls, time.time() - t0))

if __name__ == "__main__":
    main()
