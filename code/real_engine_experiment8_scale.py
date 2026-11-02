#!/usr/bin/env python3
"""
Experiment 8: checking a plan on a large flow space of a real engine (Linux nftables).

Flow f in {0..65535} is the destination address 10.98.(f>>8).(f&255). Fwd B owns the whole /16 as a local
route and one UDP socket receives every datagram, the destination address is read with IP_PKTINFO.
For random policies of n rules (default deny) a plan inserts ([M] permit) at position 0.
  enumerate : install the plan, query all 65,536 flows (and the old policy, for Q2)
  cells     : query one flow per elementary cell of the plan's boxes and M (Theorem 5),
              Q2 from first-match differencing (Theorem 6)
We count probes, time both, and compare the verdicts.
Last part: a second table that drops one address inside M that is not a cell representative
(violates signature determinacy): the cell check misses it, enumeration finds it.

Needs root, ip, nft, Python 3, and real_engine_experiment.py alongside.   Usage: python3 real_engine_experiment8_scale.py
"""
import os, random, select, socket, struct, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from real_engine_experiment import sh, setup_ns, in_ns

NF = 65536
PORT = 9100
def addr(f): return "10.98.%d.%d" % (f >> 8, f & 255)
def idx(a): p = a.split("."); return (int(p[2]) << 8) | int(p[3])

def nft_text(P, extra_drop=None):
    d = "accept" if P["default"] else "drop"
    L = ["flush ruleset", "table ip fw {", " chain a { type filter hook input priority 0; policy %s;" % d]
    for (lo, hi), a in P["rules"]:
        L.append("  ip daddr %s-%s udp dport %d %s" % (addr(lo), addr(hi), PORT, "accept" if a else "drop"))
    L.append(" }")
    if extra_drop is not None:
        L += [" chain b { type filter hook input priority 10; policy accept;",
              "  ip daddr %s udp dport %d drop" % (addr(extra_drop), PORT), " }"]
    L.append("}")
    return "\n".join(L) + "\n"

def ev_fm(P, f):
    for (lo, hi), a in P["rules"]:
        if lo <= f <= hi: return a
    return P["default"]

class Lab:
    def __init__(self):
        setup_ns()
        sh("ip netns exec fwB ip route add local 10.98.0.0/16 dev lo")
        sh("ip netns exec fwA ip route add 10.98.0.0/16 via 10.99.0.2 dev va")
        def mk():
            r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            r.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32 << 20)
            r.setsockopt(socket.IPPROTO_IP, socket.IP_PKTINFO, 1)
            r.bind(("0.0.0.0", PORT)); r.setblocking(False); return r
        self.recv = in_ns("fwB", mk)
        def mks():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.99.0.1", 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 << 20); return s
        self.snd = in_ns("fwA", mks)
        self.probes = 0

    def install(self, P, extra_drop=None):
        sh("ip netns exec fwB nft -f -", inp=nft_text(P, extra_drop))

    def query(self, flows, batch=400, settle=0.03):
        """Send one datagram per flow; return the set of flows that arrived."""
        got = set()
        def drain(wait):
            end = time.time() + wait
            while True:
                r, _, _ = select.select([self.recv], [], [], max(0.0, end - time.time()))
                if not r: break
                while True:
                    try: data, anc, _, _ = self.recv.recvmsg(64, 64)
                    except BlockingIOError: break
                    for lvl, typ, cd in anc:
                        if lvl == socket.IPPROTO_IP and typ == socket.IP_PKTINFO:
                            got.add(idx(socket.inet_ntoa(cd[8:12])))
                end = time.time() + wait
        flows = list(flows)
        for i in range(0, len(flows), batch):
            for f in flows[i:i + batch]: self.snd.sendto(b"x", (addr(f), PORT))
            drain(settle)
        drain(0.15)
        self.probes += len(flows)
        return got

def cells_in(boxes, M):
    """Elementary cells (Lemma 4, d=1) of the given boxes and M; returns the cells inside M as (start, end)."""
    K = {0}
    for (lo, hi) in boxes + [M]:
        K.add(lo)
        if hi + 1 < NF: K.add(hi + 1)
    K = sorted(K) + [NF]
    segs = [(K[i], K[i + 1] - 1) for i in range(len(K) - 1)]
    return segs, [s for s in segs if s[0] >= M[0] and s[1] <= M[1]]

def rand_policy(rnd, n):
    rules = []
    for _ in range(n):
        lo = rnd.randrange(NF); hi = min(NF - 1, lo + rnd.randrange(1, 12000))
        rules.append(((lo, hi), rnd.randrange(2)))
    return {"rules": rules, "default": 0}

def main():
    print("kernel:", sh("uname -r").stdout.strip(), "| nft:", sh("nft --version").stdout.strip(), "| python", sys.version.split()[0])
    lab = Lab()
    # controls
    lab.install({"rules": [], "default": 1}); g = lab.query(range(0, NF, 997))
    lab.install({"rules": [], "default": 0}); h = lab.query(range(0, NF, 997))
    exp = len(range(0, NF, 997))
    print("controls: permit-all %d/%d arrive, deny-all %d/%d arrive" % (len(g), exp, len(h), exp))
    assert len(g) == exp and len(h) == 0, "controls failed"
    rnd = random.Random(11)
    print("\n n  |M|     cells  Q1 cell probes  enum probes(Q1+Q2)  t_enum  t_cells  verdict Q1 (cells/enum)  Q2 (model/measured)  engine==first-match")
    rows = []
    for n in (5, 10, 20, 40):
        for rep in range(2):
            P = rand_policy(rnd, n)
            M = (rnd.randrange(0, 30000), 0)
            M = (M[0], M[0] + rnd.randrange(8000, 30000))
            Pn = {"rules": [(M, 1)] + P["rules"], "default": 0}
            boxes = [b for (b, _) in Pn["rules"]]
            segs, inM = cells_in(boxes, M)
            # enumeration
            t0 = time.time()
            lab.install(P); old = lab.query(range(NF))
            lab.install(Pn); new = lab.query(range(NF))
            t_enum = time.time() - t0
            q1_enum = all(f in new for f in range(M[0], M[1] + 1))
            q2_meas = all((f in old) == (f in new) for f in range(NF) if not (M[0] <= f <= M[1]))
            same_fm = all((f in new) == bool(ev_fm(Pn, f)) for f in range(NF)) and all((f in old) == bool(ev_fm(P, f)) for f in range(NF))
            # cells
            t0 = time.time()
            lab.install(Pn); got = lab.query([s[0] for s in inM])
            t_cells = time.time() - t0
            q1_cells = all(s[0] in got for s in inM)
            q2_model = all(ev_fm(P, f) == ev_fm(Pn, f) for f in range(NF) if not (M[0] <= f <= M[1]))
            print("%2d %6d %6d %8d %20d %8.1f %8.2f   %-5s/%-5s          %-5s/%-5s       %s" %
                  (n, M[1] - M[0] + 1, len(segs), len(inM), 2 * NF, t_enum, t_cells, q1_cells, q1_enum, q2_model, q2_meas, same_fm))
            rows.append((q1_cells == q1_enum, q2_model == q2_meas, same_fm))
    print("\nverdicts agree on %d/%d plans for Q1, %d/%d for Q2; engine equals first-match on all flows for %d/%d plans" %
          (sum(r[0] for r in rows), len(rows), sum(r[1] for r in rows), len(rows), sum(r[2] for r in rows), len(rows)))
    # a deviation inside a cell
    P = {"rules": [((1000, 60000), 0)], "default": 0}
    M = (20000, 30000)
    Pn = {"rules": [(M, 1)] + P["rules"], "default": 0}
    segs, inM = cells_in([b for (b, _) in Pn["rules"]], M)
    reps = {s[0] for s in inM}
    bad = next(f for f in range(M[0] + 5, M[1]) if f not in reps)
    lab.install(Pn, extra_drop=bad)
    got = lab.query([s[0] for s in inM]); cells_ok = all(s[0] in got for s in inM)
    enum = lab.query(range(NF)); enum_ok = all(f in enum for f in range(M[0], M[1] + 1))
    print("\nhidden drop of one address (%s) inside a cell of M, second table: cell check says Q1 %s (%d probes); enumeration says Q1 %s (%d probes)" %
          (addr(bad), "holds" if cells_ok else "fails", len(inM), "holds" if enum_ok else "fails", NF))
    sh("ip netns exec fwB nft flush ruleset", check=False)
    print("DONE")

if __name__ == "__main__":
    main()
