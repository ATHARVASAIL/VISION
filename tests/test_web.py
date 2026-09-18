"""Web assessment tests: detection accuracy, false positives, scanner safety."""
import http.server, socket, socketserver, sys, tempfile, threading, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.core.pipeline import Pipeline, RunState
from vision.core.scope import Scope
from vision.core.web import (
    worst_severity, http_request, MAX_BODY, SEVERITY_RANK, _is_tls,
)

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

# ---------------------------------------------------------------- fixtures

PORT_VULN, PORT_CLEAN, PORT_HUGE, PORT_REDIS, PORT_SILENT = 18101, 18102, 18103, 18104, 18105

class Vulnerable(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _s(self, code, body, extra=None):
        self.send_response(code)
        self.send_header("Server", "Apache/2.4.29 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/7.2.24")
        self.send_header("Content-Type", "text/html")
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())
    def do_GET(self):
        p = self.path
        if p == "/.git/HEAD":     return self._s(200, "ref: refs/heads/main\n")
        if p == "/.env":          return self._s(200, "DB_PASSWORD=x\nSECRET_KEY=y\n")
        if p == "/server-status": return self._s(200, "<h1>Apache Server Status</h1>")
        if p == "/phpinfo.php":   return self._s(200, "<title>phpinfo()</title>")
        if p == "/manager/html":  return self._s(200, "<h1>Tomcat Manager</h1>")
        # Soft-404: returns 200 with a generic page for everything else. This is
        # the false-positive trap — a naive scanner reports every path as found.
        return self._s(200, "<title>Index of /</title>")
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, TRACE, OPTIONS")
        self.end_headers()

class Hardened(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(404 if self.path != "/" else 200)
        for k, v in {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Type": "text/html",
        }.items(): self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b"<html><body>ok</body></html>")
    def do_OPTIONS(self):
        self.send_response(200); self.send_header("Allow", "GET, POST"); self.end_headers()

class Flood(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type", "text/plain")
        self.end_headers()
        try:
            for _ in range(400):           # ~4 MB, well past MAX_BODY
                self.wfile.write(b"A" * 10240)
        except (BrokenPipeError, ConnectionResetError):
            pass

class Reuse(socketserver.TCPServer): allow_reuse_address = True

def http_server(port, handler):
    threading.Thread(target=lambda: Reuse(("127.0.0.1", port), handler).serve_forever(),
                     daemon=True).start()

def raw_server(port, reply=None, silent=False):
    def run():
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try: s.bind(("127.0.0.1", port))
        except OSError: return
        s.listen(8)
        while True:
            try:
                c, _ = s.accept()
                if silent:
                    time.sleep(30); c.close(); continue
                c.recv(256)
                if reply: c.sendall(reply)
                c.close()
            except OSError: break
    threading.Thread(target=run, daemon=True).start()

http_server(PORT_VULN, Vulnerable)
http_server(PORT_CLEAN, Hardened)
http_server(PORT_HUGE, Flood)
raw_server(PORT_REDIS, b"+PONG\r\n")
raw_server(PORT_SILENT, silent=True)
time.sleep(1.5)

up = 0
for p in (PORT_VULN, PORT_CLEAN, PORT_HUGE, PORT_REDIS, PORT_SILENT):
    try:
        c = socket.create_connection(("127.0.0.1", p), 2); c.close(); up += 1
    except OSError: pass
check(f"test fixtures listening ({up}/5)", up == 5)

SCOPE = Scope.from_lists(["127.0.0.1/32"])
def run(services, stages):
    wd = Path(tempfile.mkdtemp()); st = RunState(scope="t", workdir=str(wd))
    st.services = services
    pl = Pipeline(SCOPE, wd, st)
    results = [getattr(pl, s)() for s in stages]
    return st.findings, results

W = lambda port, **kw: {"ip": "127.0.0.1", "port": port, "proto": "tcp",
                        "name": "http", **kw}

print("\n--- severity ranking (max() on strings gets this wrong) ---")
check("critical beats medium", worst_severity(["medium", "critical"]) == "critical")
check("high beats low", worst_severity(["low", "high"]) == "high")
check("alphabetical max would differ", max(["low", "critical", "medium"]) == "medium")
check("empty defaults to info", worst_severity([]) == "info")
check("unknown values ignored", worst_severity(["bogus", "high"]) == "high")
check("rank is complete", set(SEVERITY_RANK) ==
      {"info", "low", "medium", "high", "critical"})

print("\n--- misconfigured server detection ---")
f, _ = run([W(PORT_VULN)], ["web_assessment", "web_paths"])
titles = [x["title"] for x in f]
for label, needle in [
    ("missing security headers", "security headers missing"),
    ("server version disclosure", "Server version disclosed"),
    ("X-Powered-By disclosure", "X-Powered-By"),
    ("directory listing", "Directory listing"),
    ("dangerous methods", "Dangerous HTTP methods"),
    ("git repo exposed", "Git repository exposed"),
    ("env file exposed", "Environment file exposed"),
    ("server-status exposed", "server-status"),
    ("phpinfo exposed", "phpinfo"),
]:
    check(label, any(needle in t for t in titles), str(titles)[:120])
check(".env rated critical",
      any(x["severity"] == "critical" for x in f if "Environment" in x["title"]))
check("git repo rated high",
      any(x["severity"] == "high" for x in f if "Git" in x["title"]))
check("every finding has remediation", all(x.get("remediation") for x in f))
check("every finding names its source", all(x.get("source") for x in f))

print("\n--- soft-404 does not become a false positive ---")
check("unmatched paths not reported",
      not any(".DS_Store" in t or "actuator" in t for t in titles),
      str([t for t in titles if "DS_Store" in t or "actuator" in t]))

print("\n--- hardened server produces no noise ---")
f2, _ = run([W(PORT_CLEAN)], ["web_assessment", "web_paths"])
t2 = [x["title"] for x in f2]
check("no missing-header finding", not any("security headers missing" in t for t in t2), str(t2))
check("no server disclosure", not any("Server version" in t for t in t2))
check("no dangerous methods", not any("Dangerous HTTP" in t for t in t2))
check("no path findings", not any("exposed" in t.lower() for t in t2), str(t2))
check("hardened host is clean", len(f2) == 0, str(t2))

print("\n--- scanner safety against a hostile server ---")
t0 = time.time()
got = http_request("127.0.0.1", PORT_HUGE, False, "/")
elapsed = time.time() - t0
check("oversized response capped", got is not None and len(got[2]) <= MAX_BODY,
      f"{len(got[2]) if got else 'None'} bytes")
check("capped read is fast", elapsed < 10, f"{elapsed:.1f}s")

t0 = time.time()
got = http_request("127.0.0.1", PORT_SILENT, False, "/")
elapsed = time.time() - t0
check("silent server times out, returns None", got is None)
check("timeout is bounded", elapsed < 15, f"{elapsed:.1f}s")

check("closed port returns None", http_request("127.0.0.1", 19999, False) is None)
check("TLS request to plain port returns None",
      http_request("127.0.0.1", PORT_VULN, True) is None)

print("\n--- datastore probes key on identity, not port ---")
f3, _ = run([{"ip": "127.0.0.1", "port": PORT_REDIS, "proto": "tcp",
              "name": "redis", "product": "Redis"}], ["datastore_exposure"])
check("Redis found on a non-standard port",
      any("Redis" in x["title"] for x in f3), str([x["title"] for x in f3]))
check("Redis rated critical", f3 and f3[0]["severity"] == "critical")
check("Redis finding is confirmed", f3 and f3[0]["confidence"] == "confirmed")

f4, _ = run([{"ip": "127.0.0.1", "port": PORT_REDIS, "proto": "tcp",
              "name": "http", "product": "nginx"}], ["datastore_exposure"])
check("nmap naming something else suppresses the probe", len(f4) == 0)

f5, _ = run([{"ip": "127.0.0.1", "port": PORT_REDIS, "proto": "tcp"}],
            ["datastore_exposure"])
check("unidentified service on a non-default port not probed", len(f5) == 0)

f6, _ = run([{"ip": "127.0.0.1", "port": PORT_VULN, "proto": "tcp",
              "name": "redis"}], ["datastore_exposure"])
check("service that doesn't answer the protocol yields nothing", len(f6) == 0)

print("\n--- scope enforcement ---")
f7, _ = run([{"ip": "8.8.8.8", "port": 80, "proto": "tcp", "name": "http"}],
            ["web_assessment", "web_paths", "datastore_exposure", "tls_certificate"])
check("out-of-scope host never probed", len(f7) == 0)

print("\n--- graceful skip ---")
_, res = run([], ["web_assessment", "web_paths", "tls_certificate",
                  "datastore_exposure"])
check("all web stages skip cleanly with no services",
      all(r.skipped and r.ok for r in res), str([(r.name, r.skipped) for r in res]))

_, res = run([{"ip": "127.0.0.1", "port": 22, "proto": "tcp", "name": "ssh"}],
             ["web_assessment", "datastore_exposure"])
check("non-web service skips web stages", all(r.skipped for r in res))

print("\n--- TLS detection helper ---")
check("port 443 is TLS", _is_tls({"port": 443, "name": "http"}))
check("tunnel=ssl is TLS", _is_tls({"port": 9999, "tunnel": "ssl"}))
check("name https is TLS", _is_tls({"port": 9999, "name": "https"}))
check("plain http is not TLS", not _is_tls({"port": 80, "name": "http"}))

print("\n--- pipeline wiring ---")
declared = {n for _, _, ns in Pipeline.PHASES for n in ns}
registered = {n for n, _ in Pipeline.STAGES}
check("every stage sits in exactly one phase", declared == registered,
      str(declared ^ registered))
check("all stage methods exist",
      all(hasattr(Pipeline, m) for _, m in Pipeline.STAGES))
check("web stages in STANDARD",
      {"web-assessment", "web-exposed-paths", "tls-certificate",
       "datastore-exposure"} <= Pipeline.STANDARD)
check("web stages not in QUICK", not ({"web-assessment"} & Pipeline.QUICK))
check("Web Assessment phase exists",
      any(t == "Web Assessment" for t, _, _ in Pipeline.PHASES))
check("no duplicate stage names", len(registered) == len(Pipeline.STAGES))

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
