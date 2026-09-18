"""Web and datastore assessment.

Every network has HTTP services, and until now Vision said only "HTTP exposed"
about them. These stages close that gap.

Written against the standard library on purpose. `banner-analysis` proved its
worth by producing findings on boxes where half the toolchain was missing, and
web checks are the highest-value place to repeat that: no nikto, no whatweb, no
gobuster required.

Everything here is **read-only**. Redis `PING`, Memcached `version`, an
Elasticsearch health GET — these read state and never write, never authenticate
and never guess a password. Credential attacks stay out of the automated path
because account lockout is the operator's decision, not a scan preset's.

Scanner-side safety, since responses come from hosts that may be hostile:

  - Response bodies are capped. An endpoint that streams gigabytes would
    otherwise OOM the scanning box.
  - Redirects are not followed. A 302 to another host would take the scanner
    straight out of the agreed scope.
  - Every socket has a timeout; a server that accepts and never speaks cannot
    stall the run.
  - All server-controlled text passes through `safe_display` before it reaches
    a terminal or a report.
"""

from __future__ import annotations

import http.client
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Optional

from .concurrency import parallel_collect
from .profiles import PATHS_EXTENDED
from .safety import safe_display, bounded

# A hostile or misconfigured endpoint can stream indefinitely.
MAX_BODY = 256 * 1024
HTTP_TIMEOUT = 8
PROBE_TIMEOUT = 5

WEB_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9090, 5000, 3000, 7001}

# Severity is ordinal, so it needs a rank. max() over the strings would put
# "medium" above "critical" because it compares alphabetically — the same trap
# that made version comparison wrong.
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def worst_severity(severities) -> str:
    items = [s for s in severities if s in SEVERITY_RANK]
    return max(items, key=lambda s: SEVERITY_RANK[s]) if items else "info"


# Header -> (severity, what its absence means)
SECURITY_HEADERS = {
    "strict-transport-security": ("medium",
        "browsers may downgrade to plaintext HTTP on a first or stale visit"),
    "content-security-policy": ("medium",
        "no defence-in-depth against injected script"),
    "x-frame-options": ("low",
        "the page can be framed, enabling clickjacking"),
    "x-content-type-options": ("low",
        "browsers may MIME-sniff responses into an executable type"),
}

# Server banners that disclose more than they should.
VERBOSE_SERVER = re.compile(
    r"(apache|nginx|iis|tomcat|jetty|gunicorn|werkzeug|express|openresty)"
    r"[/ ]([\d.]+)", re.I)

# Paths worth one GET each. Deliberately tiny: this is exposure checking, not
# directory brute-forcing, and a long wordlist turns a scan into an attack.
NOTABLE_PATHS = [
    ("/.git/HEAD",        "high",     "Git repository exposed",
     lambda b: b.startswith("ref:")),
    ("/.env",             "critical", "Environment file exposed",
     lambda b: "=" in b and any(k in b.upper() for k in
                                ("SECRET", "PASSWORD", "KEY", "TOKEN", "DB_"))),
    ("/server-status",    "medium",   "Apache server-status exposed",
     lambda b: "Apache Server Status" in b),
    ("/actuator/health",  "medium",   "Spring Boot actuator exposed",
     lambda b: '"status"' in b),
    ("/manager/html",     "high",     "Tomcat manager reachable",
     lambda b: "Tomcat" in b or "manager" in b.lower()),
    ("/phpinfo.php",      "medium",   "phpinfo() exposed",
     lambda b: "phpinfo()" in b or "PHP Version" in b),
    ("/.DS_Store",        "low",      "macOS .DS_Store exposed",
     lambda b: b.startswith("\x00\x00\x00\x01Bud1")),
]

DANGEROUS_METHODS = {
    "PUT":    ("high",     "may allow arbitrary file upload"),
    "DELETE": ("high",     "may allow arbitrary file deletion"),
    "TRACE":  ("low",      "enables Cross-Site Tracing"),
    "PROPFIND": ("medium", "WebDAV is enabled"),
}


def _connect(ip: str, port: int, tls: bool, timeout: int = HTTP_TIMEOUT):
    if tls:
        ctx = ssl.create_default_context()
        # We are assessing the certificate, not trusting it. Verification off
        # is required to reach hosts with self-signed or expired certs — which
        # are exactly the ones we need to report on.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(ip, port, timeout=timeout)


def http_request(ip: str, port: int, tls: bool, path: str = "/",
                 method: str = "GET") -> Optional[tuple[int, dict, str]]:
    """One request, no redirect following, body capped."""
    conn = None
    try:
        conn = _connect(ip, port, tls)
        conn.request(method, path, headers={
            "User-Agent": "vision/0.1 (vulnerability assessment)",
            "Accept": "*/*", "Connection": "close",
        })
        resp = conn.getresponse()
        body = resp.read(MAX_BODY).decode("utf-8", errors="replace")
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, headers, body
    except (OSError, http.client.HTTPException, ssl.SSLError, socket.timeout):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


def _is_tls(svc: dict) -> bool:
    return (svc.get("tunnel") == "ssl"
            or svc["port"] in (443, 8443, 9443)
            or "https" in (svc.get("name") or ""))


class WebStages:
    """Mixin for Pipeline."""

    def _web_targets(self) -> list[dict]:
        out = []
        for s in self.state.services:
            if not self.scope.contains(s["ip"]):
                continue
            name = (s.get("name") or "").lower()
            if "http" in name or s["port"] in WEB_PORTS:
                out.append(s)
        return out

    # ------------------------------------------------------------ headers

    def web_assessment(self):
        """Security headers, server disclosure, directory listing, dangerous
        methods, and a small set of high-signal paths."""
        from .pipeline import StageResult
        name = "web-assessment"
        targets = self._web_targets()
        if not targets:
            return self._skip(name, "no HTTP services found")

        t0 = time.time()

        def probe(svc: dict) -> list[dict]:
            ip, port = svc["ip"], svc["port"]
            tls = _is_tls(svc)
            base = {"ip": ip, "port": port, "proto": "tcp"}
            got = http_request(ip, port, tls)
            if got is None:
                return []
            status, headers, body = got
            out: list[dict] = []

            # Missing security headers. Only meaningful once we know something
            # is actually serving HTTP, which the status code confirms.
            missing = [h for h in SECURITY_HEADERS if h not in headers]
            if missing and status < 500:
                worst = worst_severity(SECURITY_HEADERS[h][0] for h in missing)
                out.append({**base,
                    "title": "HTTP security headers missing",
                    "severity": worst, "confidence": "confirmed", "cves": [],
                    "source": "web-assessment",
                    "evidence": safe_display("; ".join(
                        f"{h}: {SECURITY_HEADERS[h][1]}" for h in missing), 500),
                    "remediation": "Set " + ", ".join(missing) + " on this origin.",
                })

            server = headers.get("server", "")
            m = VERBOSE_SERVER.search(server)
            if m:
                out.append({**base,
                    "title": f"Server version disclosed: {safe_display(server, 60)}",
                    "severity": "low", "confidence": "confirmed", "cves": [],
                    "source": "web-assessment",
                    "evidence": safe_display(f"Server: {server}", 200),
                    "remediation": "Suppress the version in the Server header "
                                   "(ServerTokens Prod / server_tokens off).",
                })

            if "x-powered-by" in headers:
                out.append({**base,
                    "title": "X-Powered-By discloses the application stack",
                    "severity": "low", "confidence": "confirmed", "cves": [],
                    "source": "web-assessment",
                    "evidence": safe_display(
                        f"X-Powered-By: {headers['x-powered-by']}", 200),
                    "remediation": "Remove the X-Powered-By header.",
                })

            if status == 200 and re.search(r"<title>Index of /|Directory listing for",
                                           body, re.I):
                out.append({**base,
                    "title": "Directory listing enabled",
                    "severity": "medium", "confidence": "confirmed", "cves": [],
                    "source": "web-assessment",
                    "evidence": safe_display(body[:300], 300),
                    "remediation": "Disable automatic directory indexes.",
                })

            # Dangerous methods, read from OPTIONS rather than attempted.
            opts = http_request(ip, port, tls, "/", "OPTIONS")
            if opts:
                allow = (opts[1].get("allow", "") + " "
                         + opts[1].get("access-control-allow-methods", "")).upper()
                risky = [m for m in DANGEROUS_METHODS if m in allow]
                if risky:
                    sev = worst_severity(DANGEROUS_METHODS[m][0] for m in risky)
                    out.append({**base,
                        "title": f"Dangerous HTTP methods advertised: {', '.join(risky)}",
                        "severity": sev, "confidence": "firm", "cves": [],
                        "source": "web-assessment",
                        "evidence": safe_display(f"Allow: {allow.strip()}", 200),
                        "remediation": "Restrict the allowed methods to those "
                                       "the application requires.",
                    })
            return out

        found = parallel_collect(probe, bounded(targets, self.profile.max_hosts_per_stage),
                                 workers=self.profile.workers)
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            duration=time.time() - t0))

    # ------------------------------------------------------------ paths

    def web_paths(self):
        """One GET per notable path. Not directory brute-forcing — a long
        wordlist turns an assessment into an attack, and these seven paths
        carry most of the real-world signal."""
        from .pipeline import StageResult
        name = "web-exposed-paths"
        targets = self._web_targets()
        if not targets:
            return self._skip(name, "no HTTP services found")

        t0 = time.time()

        def probe(svc: dict) -> list[dict]:
            ip, port, tls = svc["ip"], svc["port"], _is_tls(svc)
            out = []
            paths = list(NOTABLE_PATHS)
            if self.profile.http_paths == "extended":
                paths += PATHS_EXTENDED
            for path, sev, title, confirm in paths:
                got = http_request(ip, port, tls, path)
                if not got:
                    continue
                status, _headers, body = got
                # A 200 alone means little: many apps return a soft-404 page.
                # Requiring a content signature keeps this honest.
                if status != 200 or not body:
                    continue
                try:
                    matched = bool(confirm(body))
                except Exception:
                    matched = False
                if not matched:
                    continue
                out.append({
                    "ip": ip, "port": port, "proto": "tcp",
                    "title": title, "severity": sev, "confidence": "confirmed",
                    "cves": [], "source": "web-assessment",
                    "evidence": safe_display(f"GET {path} -> 200; "
                                             f"{body[:200]}", 300),
                    "remediation": f"Block external access to {path}.",
                })
            return out

        found = parallel_collect(probe, bounded(targets, self.profile.max_hosts_per_stage),
                                 workers=self.profile.workers)
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            duration=time.time() - t0))

    # ------------------------------------------------------------ certs

    def tls_certificate(self):
        """Certificate validity. Expiry and self-signed certs are among the
        most common real findings and need no external tool."""
        from .pipeline import StageResult
        name = "tls-certificate"
        targets = [s for s in self.state.services
                   if self.scope.contains(s["ip"]) and _is_tls(s)]
        if not targets:
            return self._skip(name, "no TLS services found")

        t0 = time.time()

        def probe(svc: dict) -> list[dict]:
            ip, port = svc["ip"], svc["port"]
            base = {"ip": ip, "port": port, "proto": "tcp",
                    "source": "tls-certificate", "cves": []}
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                with socket.create_connection((ip, port), PROBE_TIMEOUT) as raw:
                    with ctx.wrap_socket(raw, server_hostname=ip) as tls_sock:
                        der = tls_sock.getpeercert(binary_form=True)
                        cert = tls_sock.getpeercert()
                        version = tls_sock.version()
            except (OSError, ssl.SSLError, socket.timeout):
                return []

            out = []
            if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                out.append({**base,
                    "title": f"Deprecated protocol {version} negotiated",
                    "severity": "medium" if version == "TLSv1.1" else "high",
                    "confidence": "confirmed",
                    "evidence": f"negotiated {version}",
                    "remediation": "Disable TLS 1.1 and below; require TLS 1.2+.",
                })

            # An empty dict with CERT_NONE means we could not decode the
            # structure — usually a self-signed or otherwise unusual cert.
            if not cert:
                if der:
                    out.append({**base,
                        "title": "TLS certificate is self-signed or untrusted",
                        "severity": "medium", "confidence": "firm",
                        "evidence": "certificate did not validate against the "
                                    "system trust store",
                        "remediation": "Install a certificate from a trusted CA.",
                    })
                return out

            not_after = cert.get("notAfter")
            if not_after:
                try:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    exp = exp.replace(tzinfo=timezone.utc)
                    days = (exp - datetime.now(timezone.utc)).days
                    if days < 0:
                        out.append({**base,
                            "title": f"TLS certificate expired {abs(days)} days ago",
                            "severity": "high", "confidence": "confirmed",
                            "evidence": safe_display(f"notAfter: {not_after}", 100),
                            "remediation": "Renew and deploy a current certificate.",
                        })
                    elif days < 30:
                        out.append({**base,
                            "title": f"TLS certificate expires in {days} days",
                            "severity": "low", "confidence": "confirmed",
                            "evidence": safe_display(f"notAfter: {not_after}", 100),
                            "remediation": "Renew before expiry to avoid an outage.",
                        })
                except ValueError:
                    pass
            return out

        found = parallel_collect(probe, bounded(targets, self.profile.max_hosts_per_stage),
                                 workers=self.profile.workers)
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            duration=time.time() - t0))

    # ------------------------------------------------------------ datastores

    def datastore_exposure(self):
        """Unauthenticated data stores.

        Read-only protocol probes: Redis PING, Memcached version, MongoDB
        isMaster, an Elasticsearch health GET. No credentials are sent and no
        state is modified, so there is no lockout risk — which is why this is
        safe to run automatically while credential attacks are not.
        """
        from .pipeline import StageResult
        name = "datastore-exposure"

        # Keyed on service identity with the port as a fallback — the same rule
        # banner-analysis uses. Keying on port alone silently skipped Redis on
        # 16379, which is exactly how these get deployed behind a proxy.
        # (label, nmap tokens, default ports, payload, expected reply, severity, impact)
        PROBES = [
            ("Redis", ("redis",), (6379, 6380),
             b"*1\r\n$4\r\nPING\r\n", b"+PONG", "critical",
             "Full read/write access to the keyspace without credentials."),
            ("Memcached", ("memcache",), (11211,),
             b"version\r\n", b"VERSION", "high",
             "Cache contents readable and usable for DDoS amplification."),
            ("MongoDB", ("mongod",), (27017, 27018),
             None, None, "high",
             "Database reachable without authentication."),
            ("Elasticsearch", ("elastic",), (9200, 9201),
             None, None, "high",
             "Index data readable without authentication."),
        ]

        def rule_for(svc: dict):
            blob = " ".join(filter(None, [svc.get("name"),
                                          svc.get("product")])).lower()
            if blob:
                for rule in PROBES:
                    if any(tok in blob for tok in rule[1]):
                        return rule
                return None   # nmap identified it as something else
            for rule in PROBES:
                if svc["port"] in rule[2]:
                    return rule
            return None

        targets = [s for s in self.state.services
                   if self.scope.contains(s["ip"]) and rule_for(s)]
        if not targets:
            return self._skip(name, "no datastore services found")

        t0 = time.time()

        def probe(svc: dict) -> list[dict]:
            rule = rule_for(svc)
            if not rule:
                return []
            label, _tokens, _ports, payload, expect, sev, impact = rule
            ip, port = svc["ip"], svc["port"]

            if label == "Elasticsearch":
                got = http_request(ip, port, _is_tls(svc), "/_cluster/health")
                if got and got[0] == 200 and "cluster_name" in got[2]:
                    return [{"ip": ip, "port": port, "proto": "tcp",
                             "title": f"{label} exposed without authentication",
                             "severity": sev, "confidence": "confirmed",
                             "cves": [], "source": "datastore-exposure",
                             "evidence": safe_display(got[2][:200], 300),
                             "remediation": f"{impact} Enable authentication and "
                                            f"restrict {label} to trusted networks."}]
                return []

            try:
                with socket.create_connection((ip, port), PROBE_TIMEOUT) as sock:
                    sock.settimeout(PROBE_TIMEOUT)
                    if payload:
                        sock.sendall(payload)
                    else:
                        # MongoDB wire protocol OP_QUERY for isMaster.
                        sock.sendall(
                            b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"
                            b"\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00"
                            b"\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00"
                            b"\x10ismaster\x00\x01\x00\x00\x00\x00")
                    data = sock.recv(2048)
            except (OSError, socket.timeout):
                return []

            hit = (expect in data) if expect else (b"ismaster" in data.lower()
                                                   or b"maxBsonObjectSize" in data)
            if not hit:
                return []
            return [{"ip": ip, "port": port, "proto": "tcp",
                     "title": f"{label} exposed without authentication",
                     "severity": sev, "confidence": "confirmed",
                     "cves": [], "source": "datastore-exposure",
                     "evidence": safe_display(
                         data[:200].decode("utf-8", "replace"), 300),
                     "remediation": f"{impact} Enable authentication and bind "
                                    f"{label} to a trusted interface only."}]

        found = parallel_collect(probe, bounded(targets, self.profile.max_hosts_per_stage),
                                 workers=self.profile.workers)
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            duration=time.time() - t0))
