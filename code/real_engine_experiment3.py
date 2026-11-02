#!/usr/bin/env python3
"""
Second engine family for the policy-semantics identification paper.

Reuses, unchanged, from real_engine_experiment.py: the hypothesis class H8, ev(), universe(),
classes(), greedy(), fmt(), pkey(), the namespace helpers. What changes per engine family is
only (i) the front end that installs a policy and (ii) the set of rules the front end can
express (the pool), exactly as U_e was restricted for iptables in the first experiment.

Part C  Linux routing in namespace fwA (client side lookup decides whether a datagram leaves):
          ip-route         `ip route`, longest prefix, ties by metric (metric = rule index, lowest wins)
          ip-route-revtie  same, but metric = 100 - index (last rule wins ties): out-of-class control
          ip-rule          `ip rule` policy routing, priority = 100 + index, first match
        flow f = destination 10.99.0.(16+f); a box must be an aligned prefix (/32, /31, /30).
        permit = datagram arrives at the receiver on fwB; deny = blackhole route/rule.
Part D  nginx location matching (real nginx 1.24, HTTP status is the decision):
          nginx-prefix     prefix locations only
          nginx-exact      prefix locations plus `location = /xy` (quick=1 in the rule tuple)
        flow f = URI "/" + 2-bit binary of f ("/00","/01","/10","/11"); prefix "/0" = box [0,1].
        permit = `return 200`, deny = `return 403`, default permit/deny = static file present/absent (200/404).

Usage: python3 real_engine_experiment3.py C | D | CD      (needs root, ip, nginx)
"""
import math, os, random, select, shutil, socket, subprocess, sys, time, http.client
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import real_engine_experiment as R
from real_engine_experiment import (N, H8, ev, universe, classes, greedy, fmt, pkey, sh, in_ns)

BASE = R.BASE
AL = [(0, 0), (1, 1), (2, 2), (3, 3), (0, 1), (2, 3), (0, 3)]     # aligned boxes = expressible prefixes

def plen(bx): return 32 - int(math.log2(bx[1] - bx[0] + 1))

# ---------------------------------------------------------------- common verdict logic
def analyse(name, results, Ue, suite, cls):
    keys = sorted({pkey(P) for (P, f) in Ue}, key=str)
    dh = {h: sum(1 for (P, f) in Ue if ev(h, P, f) != results[(pkey(P), f)]) / len(Ue) for h in H8}
    print("disagreement d_h with %s over U_e: " % name + "  ".join("%s=%.4f" % (h, dh[h]) for h in H8))
    eps = min(dh.values()); near = [h for h in H8 if dh[h] == eps]
    cons_suite = [h for h in H8 if all(ev(h, P, f) == results[(pkey(P), f)] for (P, f) in suite)]
    cons_all = [h for h in H8 if dh[h] == 0.0]
    print("consistent with the %d-probe suite: %s" % (len(suite), cons_suite))
    print("consistent with all %d probes     : %s" % (len(Ue), cons_all))
    if cons_all:
        ok = [K for K in cls if set(K) == set(cons_all)]
        print("VERDICT: in class; identified up to observational class %s (%s)" % (cons_all, "class structure matches" if ok else "class structure DIFFERS"))
    elif cons_suite:
        print("VERDICT: suite alone would ACCEPT %s but exhaustive probing REFUTES every member; min eps=%.4f (nearest %s)" % (cons_suite, eps, near))
    else:
        print("VERDICT: deviation detected by the suite (empty consistent set); min eps over U_e = %.4f (nearest %s)" % (eps, near))
    return dh

def header(Ue, extra=""):
    pols = {}
    for (P, f) in Ue: pols.setdefault(pkey(P), P)
    cls = classes(Ue, H8); reps = [K[0] for K in cls]; suite, _ = greedy(Ue, reps)
    print("probe universe U_e: %d (policy,flow) probes, %d distinct policies%s" % (len(Ue), len(pols), extra))
    print("observational classes of H8 on U_e:", cls)
    print("greedy suite over class representatives: %d probes" % len(suite))
    for (P, f) in suite: print("   probe", fmt(P, f))
    return pols, cls, suite

# ================================================================ Part C: routing
def box_pref(bx): return "10.99.0.%d/%d" % (16 + bx[0], plen(bx))

RESET = ("rule flush\nrule add pref 32766 lookup main\nrule add pref 32767 lookup default\n"
         "route flush table main\n")
CONNECTED = "route add 10.99.0.0/24 dev va proto kernel scope link src 10.99.0.1\n"

def route_text(P, tie):
    t = RESET + (CONNECTED if P["default"] else "")
    for i, (bx, a, _, _) in enumerate(P["rules"]):
        m = (i + 1) if tie == "first" else (100 - i)
        if a: t += "route add %s dev va scope link metric %d\n" % (box_pref(bx), m)
        else: t += "route add blackhole %s metric %d\n" % (box_pref(bx), m)
    return t

def rule_text(P):
    t = RESET + CONNECTED
    for i, (bx, a, _, _) in enumerate(P["rules"]):
        t += "rule add pref %d to %s %s\n" % (100 + i, box_pref(bx), "lookup main" if a else "blackhole")
    if not P["default"]: t += "rule add pref 5000 blackhole\n"
    return t

class RouteOracle:
    def __init__(self):
        R.setup_ns()
        mb = R.mac("fwB", "vb")
        for f in range(N):
            sh("ip netns exec fwB ip addr add 10.99.0.%d/32 dev vb" % (16 + f))
            sh("ip netns exec fwA ip neigh replace 10.99.0.%d lladdr %s dev va nud permanent" % (16 + f, mb))
        def rcv():
            L = []
            for f in range(N):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.99.0.%d" % (16 + f), BASE)); s.setblocking(False); L.append(s)
            return L
        self.recv = in_ns("fwB", rcv)
        def snd():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.99.0.1", 0)); return s
        self.snd = in_ns("fwA", snd); self.calls = 0
    def drain(self):
        for s in self.recv:
            while True:
                try: s.recv(64)
                except BlockingIOError: break
    def decisions(self, text, wait=0.04):
        sh("ip netns exec fwA ip -batch -", inp=text)
        self.drain()
        for f in range(N):
            try: self.snd.sendto(b"p%d" % f, ("10.99.0.%d" % (16 + f), BASE))
            except OSError: pass                      # unreachable / prohibit: decision = deny
        got, dl = set(), time.time() + wait
        while len(got) < N and time.time() < dl:
            r, _, _ = select.select(self.recv, [], [], max(0.0, dl - time.time()))
            for s in r:
                try: s.recv(64); got.add(self.recv.index(s))
                except BlockingIOError: pass
        self.calls += 1
        return tuple(1 if f in got else 0 for f in range(N))

def run_family(title, engines, decide, Ue, ctrl):
    """engines: {name: install-text-or-config builder}; decide(engine, P, wait) -> 4 decisions"""
    pols, cls, suite = header(Ue)
    keys = sorted(pols, key=str); res = {}
    for eng in engines:
        print("\n==================== engine: %s ====================" % eng)
        c = ctrl(eng)
        print("controls: %s" % c)
        resp = {}; ts = time.time()
        for k in keys:
            d = decide(eng, pols[k], 0.04)
            for f in range(N): resp[(k, f)] = d[f]
        print("sweep: %d policies installed, %d probe responses, %.1fs" % (len(keys), len(resp), time.time() - ts))
        rnd = random.Random(7); sample = rnd.sample(keys, len(keys) // 4); mism = 0
        for k in sample:
            d = decide(eng, pols[k], 0.04); mism += sum(1 for f in range(N) if d[f] != resp[(k, f)])
        print("determinism: re-probed %d policies in shuffled order, %d response mismatches" % (len(sample), mism))
        res[eng] = resp
        analyse(eng, resp, Ue, suite, cls)
    return res, suite, cls

def part_C():
    print("kernel:", sh("uname -r").stdout.strip()); print("tool:", sh("ip -V").stdout.strip()); print("python:", sys.version.split()[0])
    orc = RouteOracle()
    rs = [(bx, a, 0, 0) for bx in AL for a in (0, 1)]
    Ue = universe(rs)
    E = {"ip-route": lambda P: route_text(P, "first"), "ip-route-revtie": lambda P: route_text(P, "rev"), "ip-rule": rule_text}
    def decide(eng, P, w): return orc.decisions(E[eng](P), wait=w)
    def ctrl(eng):
        a = decide(eng, {"rules": [], "default": 1}, 0.5); b = decide(eng, {"rules": [], "default": 0}, 0.15)
        c = decide(eng, {"rules": [((0, 0), 0, 0, 0)], "default": 1}, 0.5)
        assert a == (1, 1, 1, 1) and b == (0, 0, 0, 0) and c == (0, 1, 1, 1), (a, b, c)
        return "permit-all %s  deny-all %s  deny flow0 only %s (all as wanted)" % (a, b, c)
    res, suite, cls = run_family("routing", E, decide, Ue, ctrl)
    print("\n==================== differential ====================")
    for a, b in (("ip-route", "ip-rule"), ("ip-route", "ip-route-revtie"), ("ip-rule", "ip-route-revtie")):
        print("%-10s vs %-16s: %d of %d probes differ" % (a, b, sum(1 for k in res[a] if res[a][k] != res[b][k]), len(res[a])))
    print("total oracle installs:", orc.calls)

# ================================================================ Part D: nginx
D_ROOT = "/tmp/ngx"; D_PORT = 18080
def uri(f): return "/" + format(f, "02b")
def pfx(bx):                                   # aligned box -> URI prefix string
    n = bx[1] - bx[0] + 1
    return "/" if n == 4 else ("/" + str(bx[0] >> 1) if n == 2 else uri(bx[0]))

def ngx_conf(P, ver):
    L = ["worker_processes 1; daemon off; pid %s/pid; error_log %s/err.log;" % (D_ROOT, D_ROOT),
         "events { worker_connections 64; }",
         "http { access_log off; default_type text/plain;",
         " server { listen 127.0.0.1:%d; root %s/%s;" % (D_PORT, D_ROOT, "rp" if P["default"] else "rd"),
         "  location = /__ver { return 200 \"%d\"; }" % ver]
    for (bx, a, _, q) in P["rules"]:
        mod = "= " if q else ""
        L.append("  location %s%s { return %s; }" % (mod, pfx(bx), "200 \"P\"" if a else "403"))
    L += [" }", "}"]
    return "\n".join(L) + "\n"

class NgxOracle:
    def __init__(self):
        shutil.rmtree(D_ROOT, ignore_errors=True)
        for d in ("rp", "rd"): os.makedirs("%s/%s" % (D_ROOT, d))
        for f in range(N): open("%s/rp/%s" % (D_ROOT, format(f, "02b")), "w").write("S")
        self.ver = 0; self.calls = 0; self.proc = None
        self.conf = D_ROOT + "/nginx.conf"
        open(self.conf, "w").write(ngx_conf({"rules": [], "default": 0}, 0))
        self.proc = subprocess.Popen(["nginx", "-c", self.conf, "-p", D_ROOT], stderr=subprocess.DEVNULL)
        self.get("/__ver", retry=True)
    def get(self, path, retry=False):
        for _ in range(200 if retry else 1):
            try:
                c = http.client.HTTPConnection("127.0.0.1", D_PORT, timeout=2); c.request("GET", path, headers={"Connection": "close"})
                r = c.getresponse(); b = r.read().decode(); c.close(); return r.status, b
            except OSError: time.sleep(0.02)
        raise RuntimeError("nginx unreachable")
    def install(self, P):
        self.ver += 1
        open(self.conf, "w").write(ngx_conf(P, self.ver))
        self.proc.send_signal(1)                      # SIGHUP: reload
        t0 = time.time()
        while True:                                   # done when the new version answers AND the old worker has exited
            s, b = self.get("/__ver", retry=True)
            kids = open("/proc/%d/task/%d/children" % (self.proc.pid, self.proc.pid)).read().split()
            if b == str(self.ver) and len(kids) == 1: break
            if time.time() - t0 > 5: raise RuntimeError("reload did not complete (config rejected?)")
            time.sleep(0.005)
    def decisions(self, P, wait=None):
        self.install(P); self.calls += 1
        return tuple(1 if self.get(uri(f))[0] == 200 else 0 for f in range(N))
    def close(self):
        self.proc.terminate(); self.proc.wait()

def part_D():
    print("tool:", subprocess.run(["nginx", "-v"], capture_output=True, text=True).stderr.strip()); print("python:", sys.version.split()[0])
    orc = NgxOracle()
    def dupfree(P):
        k = [(pfx(r[0]), r[3]) for r in P["rules"]]; return len(k) == len(set(k))
    # nginx rejects two locations with the same modifier and path; check that claim on a real config first
    bad = {"rules": [((0, 1), 1, 0, 0), ((0, 1), 0, 0, 0)], "default": 1}
    open(D_ROOT + "/t.conf", "w").write(ngx_conf(bad, 0).replace("listen 127.0.0.1:%d" % D_PORT, "listen 127.0.0.1:%d" % (D_PORT + 1)).replace("pid %s/pid" % D_ROOT, "pid %s/pid2" % D_ROOT))
    t = subprocess.run(["nginx", "-t", "-c", D_ROOT + "/t.conf", "-p", D_ROOT], capture_output=True, text=True)
    print("nginx -t on a config with two identical prefix locations: rc=%d  (%s)" % (t.returncode, t.stderr.strip().splitlines()[0][-60:]))
    assert t.returncode != 0
    # ---- D1: prefix only
    print("\n######## D1: prefix locations only ########")
    U1 = [(P, f) for (P, f) in universe([(bx, a, 0, 0) for bx in AL for a in (0, 1)]) if dupfree(P)]
    E1 = {"nginx-prefix": None}
    def ctrl(eng):
        a = orc.decisions({"rules": [], "default": 1}); b = orc.decisions({"rules": [], "default": 0}); c = orc.decisions({"rules": [((0, 0), 0, 0, 0)], "default": 1})
        assert a == (1, 1, 1, 1) and b == (0, 0, 0, 0) and c == (0, 1, 1, 1), (a, b, c)
        return "permit-all %s  deny-all %s  deny flow0 only %s (all as wanted)" % (a, b, c)
    r1, s1, c1 = run_family("nginx-prefix", E1, lambda e, P, w: orc.decisions(P), U1, ctrl)
    # ---- D2: prefix + exact (exact only for single-flow boxes), quick=1 <-> `=`
    print("\n######## D2: prefix + exact locations ########")
    singles = [b for b in AL if b[0] == b[1]]
    rs2 = [(bx, a, 0, 0) for bx in AL for a in (0, 1)] + [(bx, a, 0, 1) for bx in singles for a in (0, 1)]
    U2 = [(P, f) for (P, f) in universe(rs2) if dupfree(P)]
    r2, s2, c2 = run_family("nginx-exact", {"nginx-exact": None}, lambda e, P, w: orc.decisions(P), U2, ctrl)
    # ---- D3: extend the class by one hypothesis, QBM = exact (quick) first, else longest prefix; re-identify
    print("\n######## D3: class extended by QBM (exact first, else longest prefix) ########")
    def winner_x(h, P, S):
        Rr = P["rules"]
        if h == "QBM":
            q = [i for i in S if Rr[i][3] == 1]
            if q: return min(q)
            m = min(R.vol(Rr[i][0]) for i in S); return min(i for i in S if R.vol(Rr[i][0]) == m)
        return orig_winner(h, P, S)
    orig_winner = R.winner
    R.winner = winner_x
    H9 = H8 + ["QBM"]
    import real_engine_experiment as RR
    RR.H8 = H9
    globals()["H8"] = H9
    cls9 = classes(U2, H9); suite9, _ = greedy(U2, [K[0] for K in cls9])
    print("classes of H9 on U_e(nginx-exact):", cls9); print("greedy suite: %d probes" % len(suite9))
    resp = r2["nginx-exact"]
    dh = {h: sum(1 for (P, f) in U2 if ev(h, P, f) != resp[(pkey(P), f)]) / len(U2) for h in H9}
    print("d_h: " + "  ".join("%s=%.4f" % (h, dh[h]) for h in H9))
    print("consistent with all %d probes: %s" % (len(U2), [h for h in H9 if dh[h] == 0.0]))
    print("consistent with the %d-probe suite: %s" % (len(suite9), [h for h in H9 if all(ev(h, P, f) == resp[(pkey(P), f)] for (P, f) in suite9)]))
    print("total oracle installs:", orc.calls)
    orc.close()

if __name__ == "__main__":
    w = sys.argv[1] if len(sys.argv) > 1 else "CD"
    if "C" in w: print("################ Part C: Linux routing ################"); part_C()
    if "D" in w: print("\n################ Part D: nginx ################"); part_D()
