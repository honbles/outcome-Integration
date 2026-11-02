#!/usr/bin/env python3
"""Receiver for the AWS network ACL experiment. Runs on the EC2 instance.
Listens on UDP 9000-9003 and serves, over HTTP on TCP 8080, which ports have received a datagram:
    GET /reset?t=TOKEN   forget what was seen
    GET /seen?t=TOKEN    JSON list of ports seen since the last reset
Standard library only."""
import json, socket, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

TOKEN = sys.argv[1]
SEEN, LOCK = set(), threading.Lock()

def listen(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", port))
    while True:
        s.recvfrom(256)
        with LOCK: SEEN.add(port)

for p in range(9000, 9004): threading.Thread(target=listen, args=(p,), daemon=True).start()

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query)
        if q.get("t", [""])[0] != TOKEN: self.send_response(403); self.end_headers(); return
        with LOCK:
            if u.path == "/reset": SEEN.clear()
            body = json.dumps(sorted(SEEN)).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass

HTTPServer(("0.0.0.0", 8080), H).serve_forever()
