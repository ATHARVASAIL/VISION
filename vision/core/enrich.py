"""Enrichment stages — the tools that turn open ports into actual findings.

Each stage here is non-destructive: enumeration, banner analysis, and
anonymous-access checks that a normal client would consider in-scope for a
vulnerability assessment. Nothing here brute-forces, floods, or writes to a
target. Credential attacks (hydra, kerbrute) are deliberately absent from the
automated path — lockout policies make them an operator decision.

Every stage:
  - skips cleanly when its tool is missing
  - is bounded by its own timeout so one slow service can't stall the run
  - re-checks scope before touching a host
  - emits findings in the shared schema so dedupe works across tools
"""

from __future__ import annotations

import time

from .concurrency import parallel_collect
from .profiles import snmp_communities
from .parsers import (
    parse_smbmap_shares, smbmap_has_write, parse_rpcclient_users,
    parse_showmount_exports, export_is_world_readable, snmp_responded,
    ike_aggressive_mode, parse_ldap_contexts, ldap_bind_succeeded,
    parse_searchsploit, searchsploit_cves,
)
from .safety import safe_arg, safe_display, safe_filename, bounded
from .toolchain import resolve as _tool
from .version import major_minor, older_than






class EnrichmentStages:
    """Mixin for Pipeline. Expects self.scope, self.state, self._record,
    self._skip, self._merge_findings, self.workdir."""

    # ------------------------------------------------------------- SNMP

    def snmp_enum(self):
        """Default SNMP community strings leak the full device inventory and
        often the running config. Very common, very high impact, trivially
        checkable."""
        from .pipeline import StageResult, _run
        name = "snmp-enumeration"
        binary = _tool("onesixtyone") or _tool("snmpwalk")
        if not binary:
            return self._skip(name, "onesixtyone/snmpwalk not installed")

        # Prefer hosts where the UDP scan actually saw 161 open. The fallback
        # exists because udp-scan needs root and is often skipped; probing every
        # live host is wasteful but better than reporting nothing.
        discovered = sorted({s["ip"] for s in self.state.services
                             if s["port"] == 161 and s.get("proto") == "udp"})
        udp_hosts = discovered or self.state.live_hosts[:40]
        if not udp_hosts:
            return self._skip(name, "no hosts to probe")

        t0 = time.time()
        walker = _tool("snmpwalk")
        if not walker:
            return self._skip(name, "snmpwalk not installed")

        def probe(ip: str) -> list[dict]:
            if not self.scope.contains(ip):
                return []
            for community in snmp_communities(self.profile):
                code, out, _ = _run(
                    [walker, "-v2c", "-c", safe_arg(community, 32),
                     "-t", "2", "-r", "1", ip, "1.3.6.1.2.1.1.1.0"], 15)
                if snmp_responded(out, code):
                    # First working community is enough — trying the rest only
                    # adds noise to the target's logs.
                    return [{
                        "ip": ip, "port": 161, "proto": "udp",
                        "title": f"SNMP readable with default community '{community}'",
                        "severity": "high", "confidence": "confirmed",
                        "cves": [], "source": "snmpwalk",
                        "evidence": safe_display(out, 400),
                        "remediation": "Change the community string, restrict "
                                       "by source IP, or move to SNMPv3.",
                    }]
            return []

        found = parallel_collect(probe, bounded(udp_hosts, self.profile.max_hosts_per_stage),
                                 workers=self.profile.workers)
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            hosts=len(udp_hosts), duration=time.time() - t0))

    # ------------------------------------------------------------- SMB shares

    def smb_shares(self):
        """Null-session readable shares. The single most common finding on an
        internal engagement."""
        from .pipeline import StageResult, _run
        name = "smb-shares"
        binary = _tool("smbmap")
        if not binary:
            return self._skip(name, "smbmap not installed")
        hosts = sorted({s["ip"] for s in self.state.services
                        if s["port"] in (139, 445)})
        if not hosts:
            return self._skip(name, "no SMB services found")

        t0 = time.time()

        def probe(ip: str) -> list[dict]:
            if not self.scope.contains(ip):
                return []
            code, out, err = _run([binary, "-H", ip, "-u", "", "-p", ""], 180)
            if code != 0:
                # A timeout or crash is not "no shares". Reporting it as a
                # clean result is the worst failure an assessment tool has:
                # a real run against Metasploitable timed out at 60s and the
                # stage said "0 findings, ok".
                return [{
                    "ip": ip, "port": 445, "proto": "tcp",
                    "title": "SMB share enumeration did not complete",
                    "severity": "info", "confidence": "tentative", "cves": [],
                    "source": "smbmap",
                    "evidence": safe_display(err or "no output", 200),
                    "remediation": "Re-run share enumeration by hand — this "
                                   "host was not assessed for anonymous share "
                                   "access.",
                    "incomplete": True,
                }]
            shares = parse_smbmap_shares(out)
            if not shares:
                return []
            readable = [f"{name} ({perm})" for name, perm in shares]
            writable = smbmap_has_write(shares)
            return [{
                "ip": ip, "port": 445, "proto": "tcp",
                "title": "SMB shares accessible without authentication",
                "severity": "critical" if writable else "high",
                "confidence": "confirmed", "cves": [], "source": "smbmap",
                "evidence": safe_display("; ".join(readable), 500),
                "remediation": "Remove anonymous access; require "
                               "authentication on all shares.",
            }]

        found = parallel_collect(probe, bounded(hosts, self.profile.max_hosts_per_stage),
                                 workers=self.profile.workers)
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            hosts=len(hosts), duration=time.time() - t0))

    # ------------------------------------------------------------- RPC / users

    def rpc_enum(self):
        """Null-session RPC lets you pull the domain user list, which feeds
        password spraying and is itself a reportable exposure."""
        from .pipeline import StageResult, _run
        name = "rpc-enumeration"
        binary = _tool("rpcclient")
        if not binary:
            return self._skip(name, "rpcclient not installed")
        hosts = sorted({s["ip"] for s in self.state.services
                        if s["port"] in (139, 445)})
        if not hosts:
            return self._skip(name, "no SMB/RPC services found")

        t0 = time.time()

        def probe(ip: str) -> list[dict]:
            if not self.scope.contains(ip):
                return []
            code, out, _ = _run(
                [binary, "-U", "", "-N", ip, "-c", "enumdomusers"], 40)
            users = parse_rpcclient_users(out)
            if users:
                return [{
                    "ip": ip, "port": 445, "proto": "tcp",
                    "title": "Domain users enumerable via null RPC session",
                    "severity": "medium", "confidence": "confirmed",
                    "cves": [], "source": "rpcclient",
                    "evidence": safe_display(
                        f"{len(users)} users: " + ", ".join(users[:15]), 400),
                    "remediation": "Set RestrictAnonymous / disable null "
                                   "sessions on this host.",
                }]
            return []

        found = parallel_collect(probe, bounded(hosts, self.profile.max_hosts_per_stage),
                                 workers=self.profile.workers)
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            hosts=len(hosts), duration=time.time() - t0))

    # ------------------------------------------------------------- NFS

    def nfs_enum(self):
        """World-readable NFS exports. Often holds backups and home dirs."""
        from .pipeline import StageResult, _run
        name = "nfs-exports"
        binary = _tool("showmount")
        if not binary:
            return self._skip(name, "showmount not installed")
        hosts = sorted({s["ip"] for s in self.state.services
                        if s["port"] in (111, 2049)})
        if not hosts:
            return self._skip(name, "no NFS/portmap services found")

        t0 = time.time()

        def probe(ip: str) -> list[dict]:
            if not self.scope.contains(ip):
                return []
            code, out, _ = _run([binary, "-e", ip], 30)
            parsed = parse_showmount_exports(out)
            exports = [f"{path} {clients}".strip() for path, clients in parsed]
            world = [p for p, c in parsed if export_is_world_readable(c)]
            if exports:
                return [{
                    "ip": ip, "port": 2049, "proto": "tcp",
                    "title": "NFS exports world-readable" if world
                             else "NFS exports enumerable",
                    "severity": "high" if world else "medium",
                    "confidence": "confirmed", "cves": [], "source": "showmount",
                    "evidence": safe_display("; ".join(exports[:12]), 500),
                    "remediation": "Restrict exports to specific hosts; "
                                   "avoid the * wildcard.",
                }]
            return []

        found = parallel_collect(probe, bounded(hosts, self.profile.max_hosts_per_stage),
                                 workers=self.profile.workers)
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            hosts=len(hosts), duration=time.time() - t0))

    # ------------------------------------------------------------- LDAP

    def ldap_enum(self):
        """Anonymous LDAP bind exposes the directory structure and often
        userPassword-adjacent attributes."""
        from .pipeline import StageResult, _run
        name = "ldap-anonymous-bind"
        binary = _tool("ldapsearch")
        if not binary:
            return self._skip(name, "ldapsearch not installed")
        targets = [(s["ip"], s["port"]) for s in self.state.services
                   if s["port"] in (389, 636, 3268)]
        if not targets:
            return self._skip(name, "no LDAP services found")

        t0 = time.time()

        def probe(target: tuple) -> list[dict]:
            ip, port = target
            if not self.scope.contains(ip):
                return []
            code, out, _ = _run(
                [binary, "-x", "-H", f"ldap://{ip}:{port}", "-s", "base",
                 "-b", "", "namingContexts"], 30)
            if ldap_bind_succeeded(out, code):
                ctx = parse_ldap_contexts(out)
                return [{
                    "ip": ip, "port": port, "proto": "tcp",
                    "title": "LDAP allows anonymous bind",
                    "severity": "medium", "confidence": "confirmed",
                    "cves": [], "source": "ldapsearch",
                    "evidence": safe_display("; ".join(c.strip() for c in ctx[:6]), 400),
                    "remediation": "Disable anonymous bind; require "
                                   "authenticated LDAP queries.",
                }]
            return []

        found = parallel_collect(probe, bounded(targets, self.profile.max_hosts_per_stage),
                                 workers=self.profile.workers)
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            duration=time.time() - t0))

    # ------------------------------------------------------------- deep TLS

    def testssl_scan(self):
        """testssl.sh finds far more than sslscan — Heartbleed, ROBOT, weak DH,
        certificate problems — but it is slow, so the host count is capped."""
        from .pipeline import StageResult, _run
        import json
        name = "tls-deep"
        binary = _tool("testssl.sh")
        if not binary:
            return self._skip(name, "testssl.sh not installed")
        targets = [s for s in self.state.services
                   if self.scope.contains(s["ip"])
                   and (s.get("tunnel") == "ssl"
                        or s["port"] in (443, 8443, 993, 995, 465, 636, 990))]
        if not targets:
            return self._skip(name, "no TLS services found")

        t0 = time.time()

        def probe(svc: dict) -> list[dict]:
            ip, port = svc["ip"], svc["port"]
            # Each probe needs its own output file: run concurrently, a shared
            # path would have hosts overwriting each other's results.
            outfile = self.workdir / f"testssl-{safe_filename(f'{ip}-{port}')}.json"
            _run([binary, "--jsonfile-pretty", str(outfile), "--quiet",
                  "--severity", "MEDIUM", "--fast", f"{ip}:{port}"], 300)
            if not outfile.exists():
                return []
            try:
                entries = json.loads(outfile.read_text())
            except (ValueError, OSError):
                return []
            finally:
                outfile.unlink(missing_ok=True)
            if isinstance(entries, dict):
                entries = entries.get("scanResult", [])
            out = []
            for e in (entries if isinstance(entries, list) else []):
                sev = str(e.get("severity", "")).lower()
                if sev not in ("medium", "high", "critical"):
                    continue
                cve = [c.strip() for c in str(e.get("cve", "")).split()
                       if c.strip().upper().startswith("CVE-")]
                finding_id = str(e.get("id", "")) or "TLS issue"
                out.append({
                    "ip": ip, "port": port, "proto": "tcp",
                    "title": safe_display(e.get("finding", finding_id), 120),
                    "severity": sev, "confidence": "firm", "cves": cve,
                    "source": "testssl.sh",
                    "evidence": safe_display(e.get("finding", ""), 400),
                    # Previously absent: every other stage supplies remediation,
                    # and a report line with no fix is not actionable.
                    "remediation": f"Review the TLS configuration on {ip}:{port} "
                                   f"and address '{finding_id}'.",
                })
            return out

        found = parallel_collect(probe, bounded(targets, self.profile.tls_hosts),
                                 workers=max(2, self.profile.workers // 3))
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            duration=time.time() - t0))


    def searchsploit_correlate(self):
        """Correlate detected product+version against Exploit-DB.

        Two accuracy problems this solves over the naive version:

        - **Query dedup.** Twenty hosts running the same Apache produced twenty
          identical 40-second subprocess calls. The result depends only on the
          product+version string, so it is cached per run.
        - **Version sanity.** An unparseable version is not searched at all
          rather than producing a query like `nginx unknown` that matches
          everything and reports a false positive.
        """
        from .pipeline import StageResult, _run
        name = "exploitdb-correlation"
        binary = _tool("searchsploit")
        if not binary:
            return self._skip(name, "searchsploit not installed")

        versioned = [s for s in self.state.services
                     if s.get("product") and s.get("version")
                     and self.scope.contains(s["ip"])]
        if not versioned:
            return self._skip(name, "no versioned services to correlate")

        t0 = time.time()
        import threading

        cache: dict[str, list] = {}
        cache_lock = threading.Lock()

        def query(term: str) -> list:
            with cache_lock:
                if term in cache:
                    return cache[term]
            code, out, _ = _run([binary, "--json", "-w", term], 40)
            hits = parse_searchsploit(out) if code == 0 else []
            with cache_lock:
                cache[term] = hits
            return hits

        def probe(svc: dict) -> list[dict]:
            product = safe_arg(svc["product"], max_len=48)
            # major.minor only — Exploit-DB does not index build numbers, and
            # a full version string returns nothing rather than the real hits.
            ver = major_minor(svc["version"])
            if not product or not ver:
                return []
            term = f"{product} {ver}"
            hits = query(term)
            if not hits:
                return []
            titles = [h.get("Title", "") for h in hits[:6]]
            cves = searchsploit_cves(hits)
            return [{
                "ip": svc["ip"], "port": svc["port"],
                "proto": svc.get("proto", "tcp"),
                "title": f"Public exploits available for {term}",
                "severity": "high" if len(hits) > 2 else "medium",
                # Always tentative: a version match is not proof the specific
                # build is affected, and claiming otherwise burns report trust.
                "confidence": "tentative",
                "cves": cves, "source": "searchsploit",
                "evidence": safe_display(
                    f"{len(hits)} Exploit-DB entries: " + "; ".join(titles), 450),
                "remediation": f"Upgrade {svc['product']} past {svc['version']}.",
            }]

        found = parallel_collect(probe, bounded(versioned, self.profile.max_hosts_per_stage * 2),
                                 workers=self.profile.workers)
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            duration=time.time() - t0,
            reason=f"{len(cache)} unique queries for {len(versioned)} services"))

    # ------------------------------------------------------------- IKE / VPN

    def ike_scan(self):
        """IKE aggressive mode leaks the group name and a crackable hash."""
        from .pipeline import StageResult, _run
        name = "ike-vpn"
        binary = _tool("ike-scan")
        if not binary:
            return self._skip(name, "ike-scan not installed")
        hosts = sorted({s["ip"] for s in self.state.services if s["port"] == 500})
        if not hosts:
            return self._skip(name, "no IKE services found")

        t0 = time.time()

        def probe(ip: str) -> list[dict]:
            if not self.scope.contains(ip):
                return []
            code, out, _ = _run([binary, "-M", "-A", ip], 40)
            if ike_aggressive_mode(out):
                return [{
                    "ip": ip, "port": 500, "proto": "udp",
                    "title": "IPsec VPN supports IKE aggressive mode",
                    "severity": "high", "confidence": "confirmed",
                    "cves": [], "source": "ike-scan",
                    "evidence": safe_display(out, 400),
                    "remediation": "Disable aggressive mode; use main mode "
                                   "with certificate authentication.",
                }]
            return []

        found = parallel_collect(probe, bounded(hosts, self.profile.max_hosts_per_stage),
                                 workers=self.profile.workers)
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            duration=time.time() - t0))

    # ------------------------------------------------------------- banner rules

    def banner_analysis(self):
        """Rule pass over collected service data. No external tool, so it
        always runs — useful on a stripped box where half the toolchain is
        missing.

        Accuracy note: rules key on the *service identity* nmap reported, not
        on the port number alone. Port 6379 is usually Redis, but flagging
        "unauthenticated Redis" on whatever someone happened to bind there is
        exactly the kind of false positive that gets a report rejected. When
        nmap identified the service we require it to agree; when nmap could
        not identify it, the finding is emitted at reduced confidence.
        """
        from .pipeline import StageResult
        name = "banner-analysis"
        if not self.state.services:
            return self._skip(name, "no services to analyse")

        t0 = time.time()
        found = []

        # Rules key on *service identity*, with the well-known port only as a
        # fallback. Keying on port alone missed FTP on 2121, HTTP on 8080 and
        # Telnet on 2323 — all common in real environments — while also
        # mislabelling whatever happened to be bound to a familiar port.
        #
        # (label, nmap service tokens, well-known ports, severity, why)
        CLEARTEXT = [
            ("FTP",    ("ftp",),              (21, 2121),             "high",
             "credentials traverse the network in cleartext"),
            ("Telnet", ("telnet", "telnetd"), (23, 2323, 992),        "high",
             "all traffic including credentials is unencrypted"),
            ("SMTP",   ("smtp",),             (25, 587, 2525),        "medium",
             "verify STARTTLS is enforced"),
            ("HTTP",   ("http", "http-alt"),  (80, 8080, 8000, 8888), "medium",
             "unencrypted web traffic"),
            ("POP3",   ("pop3",),             (110,),                 "high",
             "credentials in cleartext"),
            ("IMAP",   ("imap",),             (143,),                 "high",
             "credentials in cleartext"),
            ("rexec",  ("exec",),             (512,),                 "high",
             "legacy r-service, unauthenticated"),
            ("rlogin", ("rlogin", "login"),   (513,),                 "high",
             "legacy r-service, trust-based auth"),
            ("rsh",    ("rsh", "shell"),      (514,),                 "high",
             "legacy r-service, no encryption"),
        ]
        RISKY = [
            ("Ingreslock",    ("ingreslock",),  (1524,),            "critical",
             "commonly a bind-shell backdoor"),
            ("NFS",           ("nfs",),         (2049,),            "medium",
             "verify export restrictions"),
            ("VNC",           ("vnc",),         (5900, 5901, 5902), "high",
             "check for missing or weak authentication"),
            ("X11",           ("x11",),         (6000, 6001),       "high",
             "may allow keylogging and screen capture"),
            ("RDP",           ("ms-wbt", "rdp"),(3389,),            "medium",
             "verify NLA is enforced"),
            ("Memcached",     ("memcache",),    (11211,),           "high",
             "often unauthenticated and amplifiable"),
            ("Redis",         ("redis",),       (6379,),            "critical",
             "frequently unauthenticated"),
            ("MongoDB",       ("mongod",),      (27017, 27018),     "high",
             "check for missing authentication"),
            ("Elasticsearch", ("elastic",),     (9200, 9300),       "high",
             "often exposed without auth"),
            ("rsync",         ("rsync",),       (873,),             "medium",
             "check for anonymous module access"),
        ]

        # product -> (fixed-in version, severity, why). Compared numerically.
        EOL = [
            ("vsftpd",  "2.3.5", "critical", "2.3.4 shipped with a backdoor (CVE-2011-2523)"),
            ("openssh", "7.4",   "medium",   "pre-7.4 has known user-enumeration issues"),
            ("samba",   "4.0",   "high",     "3.x is long past end of life"),
            ("mysql",   "5.6",   "medium",   "5.5 and earlier are end of life"),
            ("apache",  "2.4.51","medium",   "verify patch level against recent path-traversal CVEs"),
            ("proftpd", "1.3.6", "high",     "pre-1.3.6 mod_copy allows unauthenticated file write"),
        ]

        def identify(svc: dict, tokens: tuple, ports: tuple) -> tuple[bool, str]:
            """Decide whether a rule applies, and how sure we are.

            Returns (applies, confidence). nmap naming the service is strong
            evidence and works regardless of port — that is what catches FTP on
            2121 or Telnet on 2323. The port number alone is a guess: worth
            reporting, but flagged tentative so the operator knows.
            """
            blob = " ".join(filter(None, [svc.get("name"),
                                          svc.get("product")])).lower()
            if blob:
                named = any(tok in blob for tok in tokens)
                # nmap identified it. Trust that over the port number in both
                # directions: match on any port, and never override with a
                # port-based guess when nmap says it's something else.
                return (True, "firm") if named else (False, "")
            # Unidentified service sitting on a well-known port.
            return (True, "tentative") if svc["port"] in ports else (False, "")

        for svc in self.state.services:
            if not self.scope.contains(svc["ip"]):
                continue
            port = svc["port"]

            for table, is_cleartext in ((CLEARTEXT, True), (RISKY, False)):
                for label, tokens, ports, sev, why in table:
                    # A TLS-wrapped service isn't cleartext.
                    if is_cleartext and svc.get("tunnel") == "ssl":
                        continue
                    applies, conf = identify(svc, tokens, ports)
                    if not applies:
                        continue
                    title = (f"{label} exposed without transport encryption"
                             if is_cleartext else f"{label} service exposed")
                    note = why if conf == "firm" else (
                        f"{why} (inferred from port {port}; nmap did not confirm)")
                    found.append({
                        "ip": svc["ip"], "port": port,
                        "proto": svc.get("proto", "tcp"),
                        "title": title, "severity": sev, "confidence": conf,
                        "cves": [], "source": "banner-analysis",
                        "evidence": safe_display(note, 300),
                        "remediation": f"Restrict {label} to trusted networks, "
                                       "require authentication, or disable it.",
                    })
                    break   # at most one rule per table per service

            product = (svc.get("product") or "").lower()
            version = svc.get("version")
            if not product or not version:
                continue
            for needle, fixed_in, sev, why in EOL:
                if needle not in product:
                    continue
                # Numeric comparison. String comparison put 2.3.10 below 2.3.4.
                if older_than(version, fixed_in):
                    found.append({
                        "ip": svc["ip"], "port": port,
                        "proto": svc.get("proto", "tcp"),
                        "title": f"Outdated {svc['product']} {version}",
                        "severity": sev, "confidence": "firm", "cves": [],
                        "source": "banner-analysis",
                        "evidence": safe_display(
                            f"{why}; fixed in {fixed_in}", 300),
                        "remediation": f"Upgrade to {fixed_in} or later.",
                    })
                break

        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            duration=time.time() - t0))
