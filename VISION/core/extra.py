"""Stages for tools that were registered but never executed.

Vision knew about 55 tools and actually ran 13. The rest fell into three
honest categories, and only one of them belongs here.

**Automatable.** Sweeps and enumeration that take a target list and return
structured output: masscan, fping, arp-scan, nbtscan, enum4linux-ng, smbclient,
sslyze, kerbrute user enumeration. Those are the stages in this file.

**Operator-driven.** chisel, ligolo-ng, proxychains, socat, evil-winrm,
mssqlclient, msfvenom, tcpdump, bettercap, hashcat, john. These need a foothold,
credentials, or a human deciding what to pivot where. Wrapping them in an
automated stage would produce a stage that always skips, which is worse than
not having it — it looks like coverage and delivers none. They live in the
manual playbook instead, where the operator gets the exact command.

**Needs a server.** nessuscli and gvm-cli talk to a Nessus or Greenbone
installation Vision does not manage.

The credential tools deserve their own note. `kerbrute userenum` is here because
Kerberos pre-authentication failures for a non-existent user are distinguishable
from a wrong password *without ever submitting one* — no account can lock out.
Password spraying with hydra, medusa or ncrack is not here and will not be: the
lockout decision belongs to an operator who has read the client's policy, not to
a scan preset.
"""

from __future__ import annotations

import re
import time

from .concurrency import parallel_collect
from .safety import bounded, safe_arg, safe_display
from .toolchain import resolve as _tool




# NetBIOS suffixes that identify what a host actually is.
_NBT_ROLE = {
    "<00>": "workstation", "<20>": "file server",
    "<1c>": "domain controller", "<1b>": "domain master browser",
}


class ExtraStages:
    """Mixin for Pipeline."""

    # ------------------------------------------------------------ masscan

    def masscan_sweep(self):
        """Fast SYN sweep to seed the port scan.

        nmap's own top-1000 pass is fine for a /24 and painful for a /16.
        masscan finds the open ports far faster; nmap then does the version
        detection it is actually good at. Only worth it on a large scope, so
        the stage skips itself on small ones rather than adding a dependency
        for no gain.
        """
        from .pipeline import StageResult, _run
        name = "masscan-sweep"
        binary = _tool("masscan")
        if not binary:
            return self._skip(name, "masscan not installed")
        if not self.state.live_hosts:
            return self._skip(name, "no live hosts from discovery")
        if len(self.state.live_hosts) < 32:
            return self._skip(
                name, f"only {len(self.state.live_hosts)} hosts — nmap alone is "
                      "faster below ~32")
        import os
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            return self._skip(name, "masscan needs root for raw sockets")

        t0 = time.time()
        out = self.workdir / "masscan.json"
        targets = self.workdir / "live-hosts.txt"
        rate = str(min(self.profile.min_rate * 2, 10000))
        _run([binary, "-iL", str(targets), "-p1-65535", "--rate", rate,
              "-oJ", str(out), "--wait", "3"], min(self.timeout, 900))
        if not out.exists():
            return self._record(StageResult(name, True, skipped=True,
                                            reason="masscan produced no output"))

        import json
        found = 0
        try:
            text = out.read_text(errors="replace").strip().rstrip(",")
            entries = json.loads("[" + text.strip("[]") + "]") if text else []
        except (ValueError, OSError):
            entries = []
        known = {(s["ip"], s["port"], s.get("proto", "tcp"))
                 for s in self.state.services}
        for e in entries if isinstance(entries, list) else []:
            if not isinstance(e, dict):
                continue
            ip = e.get("ip")
            for port in e.get("ports", []):
                num = port.get("port")
                if not ip or not num or not self.scope.contains(ip):
                    continue
                key = (ip, int(num), "tcp")
                if key in known:
                    continue
                known.add(key)
                self.state.services.append({
                    "ip": ip, "port": int(num), "proto": "tcp",
                    "state": "open", "name": None, "source": "masscan",
                })
                found += 1
        return self._record(StageResult(name, True, services=found,
                                        duration=time.time() - t0,
                                        artifact=str(out)))

    # ------------------------------------------------------------ layer 2

    def arp_discovery(self):
        """Layer-2 sweep. Finds hosts that drop ICMP and every TCP probe —
        firewalled workstations, printers and appliances that an L3 sweep
        misses entirely. Only meaningful on the local segment."""
        from .pipeline import StageResult, _run
        name = "arp-discovery"
        binary = _tool("arp-scan")
        if not binary:
            return self._skip(name, "arp-scan not installed")
        import os
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            return self._skip(name, "arp-scan needs root for raw sockets")

        t0 = time.time()
        added = 0
        for net in self.scope.allow:
            if net.version != 4 or net.prefixlen < 22:
                continue   # arp-scan is a local-segment tool
            code, out, _ = _run([binary, "--retry=2", "--timeout=200",
                                 str(net)], min(self.timeout, 300))
            for line in out.splitlines():
                m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s*(.*)$",
                             line.strip(), re.I)
                if not m:
                    continue
                ip = m.group(1)
                if not self.scope.contains(ip) or ip in self.state.live_hosts:
                    continue
                self.state.live_hosts.append(ip)
                added += 1
        self.state.live_hosts = sorted(set(self.state.live_hosts))
        return self._record(StageResult(
            name, True, hosts=added, duration=time.time() - t0,
            reason=f"{added} host(s) an L3 sweep missed" if added else ""))

    def fast_ping(self):
        """fping sweep alongside nmap's. Different hosts answer different
        probes, and a host missed at discovery is invisible to every stage
        after it — the cheapest place to buy coverage."""
        from .pipeline import StageResult, _run
        name = "icmp-sweep"
        binary = _tool("fping")
        if not binary:
            return self._skip(name, "fping not installed")

        t0 = time.time()
        targets = [str(n) for n in self.scope.allow if n.num_addresses <= 65536]
        if not targets:
            return self._skip(name, "scope too large for an fping sweep")
        code, out, err = _run([binary, "-a", "-q", "-r", "1", "-g", *targets]
                              if len(targets) == 1 and "/" not in targets[0]
                              else [binary, "-a", "-q", "-r", "1", "-g"] + targets,
                              min(self.timeout, 300))
        added = 0
        for line in (out + err).splitlines():
            ip = line.strip().split()[0] if line.strip() else ""
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip) and \
                    self.scope.contains(ip) and ip not in self.state.live_hosts:
                self.state.live_hosts.append(ip)
                added += 1
        self.state.live_hosts = sorted(set(self.state.live_hosts))
        return self._record(StageResult(name, True, hosts=added,
                                        duration=time.time() - t0))

    # ------------------------------------------------------------ netbios

    def nbt_scan(self):
        """NetBIOS names. Cheap, and it labels a host as a domain controller
        or file server — which changes how everything after it is prioritised."""
        from .pipeline import StageResult, _run
        name = "netbios-scan"
        binary = _tool("nbtscan")
        if not binary:
            return self._skip(name, "nbtscan not installed")
        hosts = [h for h in self.state.live_hosts if self.scope.contains(h)]
        if not hosts:
            return self._skip(name, "no live hosts")

        t0 = time.time()
        found = []
        for net in bounded([str(n) for n in self.scope.allow], 8):
            code, out, _ = _run([binary, "-r", "-s", ":", net],
                                min(self.timeout, 240))
            for line in out.splitlines():
                parts = line.strip().split(":")
                if len(parts) < 3 or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+",
                                                      parts[0]):
                    continue
                ip = parts[0]
                if not self.scope.contains(ip):
                    continue
                roles = [_NBT_ROLE[k] for k in _NBT_ROLE if k in line.lower()]
                if "domain controller" in roles:
                    found.append({
                        "ip": ip, "port": 137, "proto": "udp",
                        "title": "Domain controller identified via NetBIOS",
                        "severity": "info", "confidence": "firm", "cves": [],
                        "source": "nbtscan",
                        "evidence": safe_display(line.strip(), 200),
                        "remediation": "Restrict NetBIOS name service to "
                                       "trusted networks; it identifies the "
                                       "highest-value hosts to an attacker.",
                    })
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            duration=time.time() - t0))

    # ------------------------------------------------------------ AD / SMB

    def enum4linux(self):
        """enum4linux-ng returns far more than the individual SMB stages:
        password policy, group membership, OS build and the RID cycle in one
        pass. The password policy in particular is what tells an operator
        whether spraying is survivable."""
        from .pipeline import StageResult, _run
        name = "smb-deep-enum"
        binary = _tool("enum4linux-ng")
        if not binary:
            return self._skip(name, "enum4linux-ng not installed")
        hosts = sorted({s["ip"] for s in self.state.services
                        if s["port"] in (139, 445) and self.scope.contains(s["ip"])})
        if not hosts:
            return self._skip(name, "no SMB services found")

        t0 = time.time()

        def probe(ip: str) -> list[dict]:
            code, out, err = _run([binary, "-A", "-u", "", "-p", "", ip],
                                  min(self.timeout, 300))
            out = (out or "") + (err or "")
            results = []

            # Kali ships classic enum4linux (Perl, v0.9.x) as well as
            # enum4linux-ng, and Vision will pick up whichever is on PATH. They
            # produce completely different output: a real run against
            # Metasploitable dumped a full null session and this stage found
            # nothing, because the parser only knew the -ng format.
            if re.search(r"allows sessions using username '', password ''", out):
                results.append({
                    "ip": ip, "port": 445, "proto": "tcp",
                    "title": "SMB null session permitted",
                    "severity": "medium", "confidence": "confirmed", "cves": [],
                    "source": "enum4linux",
                    "evidence": safe_display(
                        "server accepts a session with an empty username and "
                        "password", 200),
                    "remediation": "Set RestrictAnonymous / disable null "
                                   "sessions. They expose users, groups, "
                                   "shares and policy without credentials.",
                })
            wg = re.search(r"Got domain/workgroup name:\s*(\S+)", out)
            if wg:
                results.append({
                    "ip": ip, "port": 445, "proto": "tcp",
                    "title": f"Workgroup/domain disclosed anonymously "
                             f"({wg.group(1)})",
                    "severity": "info", "confidence": "confirmed", "cves": [],
                    "source": "enum4linux",
                    "evidence": safe_display(wg.group(0), 120),
                    "remediation": "Restrict anonymous SMB enumeration.",
                })
            for share, perm in re.findall(
                    r"^\s*(\S+)\s+Disk\s*(.*)$", out, re.M):
                if share.upper() in ("IPC$", "PRINT$"):
                    continue
                results.append({
                    "ip": ip, "port": 445, "proto": "tcp",
                    "title": f"Share '{share}' listed without credentials",
                    "severity": "medium", "confidence": "confirmed", "cves": [],
                    "source": "enum4linux",
                    "evidence": safe_display(f"{share} {perm}".strip(), 200),
                    "remediation": f"Remove anonymous visibility of '{share}' "
                                   "or restrict it to authenticated users.",
                })
            users = re.findall(r"user:\[([^\]]+)\]", out)
            if users:
                results.append({
                    "ip": ip, "port": 445, "proto": "tcp",
                    "title": f"{len(users)} local accounts enumerable anonymously",
                    "severity": "medium", "confidence": "confirmed", "cves": [],
                    "source": "enum4linux",
                    "evidence": safe_display(", ".join(sorted(set(users))[:20]), 400),
                    "remediation": "Restrict anonymous enumeration; a user list "
                                   "is the first half of a password attack.",
                })

            m = re.search(r"Minimum password length:\s*(\d+)", out, re.I)
            if m and int(m.group(1)) < 8:
                results.append({
                    "ip": ip, "port": 445, "proto": "tcp",
                    "title": f"Weak minimum password length ({m.group(1)})",
                    "severity": "medium", "confidence": "confirmed", "cves": [],
                    "source": "enum4linux-ng",
                    "evidence": safe_display(m.group(0), 120),
                    "remediation": "Raise the minimum password length to at "
                                   "least 12 characters.",
                })
            lock = re.search(r"Account Lockout Threshold:\s*(\S+)", out, re.I)
            if lock and lock.group(1).lower() in ("none", "0", "disabled"):
                results.append({
                    "ip": ip, "port": 445, "proto": "tcp",
                    "title": "No account lockout threshold configured",
                    "severity": "medium", "confidence": "confirmed", "cves": [],
                    "source": "enum4linux-ng",
                    "evidence": safe_display(lock.group(0), 120),
                    "remediation": "Set a lockout threshold; without one, "
                                   "password guessing is unlimited.",
                })
            if re.search(r"Domain Name:\s*\S+", out) and \
                    re.search(r"^\s*\d+:\s", out, re.M):
                results.append({
                    "ip": ip, "port": 445, "proto": "tcp",
                    "title": "Domain information enumerable without credentials",
                    "severity": "low", "confidence": "confirmed", "cves": [],
                    "source": "enum4linux-ng",
                    "evidence": safe_display(out[:400], 400),
                    "remediation": "Restrict anonymous enumeration on the "
                                   "domain controller.",
                })
            return results

        found = parallel_collect(probe, bounded(hosts, self.profile.max_hosts_per_stage))
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            hosts=len(hosts), duration=time.time() - t0))

    def smb_readable_files(self):
        """Listing a share is not reading it. smbclient walks the root of each
        readable share so the report can say what is actually exposed rather
        than that something is."""
        from .pipeline import StageResult, _run
        name = "smb-file-listing"
        binary = _tool("smbclient")
        if not binary:
            return self._skip(name, "smbclient not installed")
        shares = [f for f in self.state.findings
                  if "shares accessible without" in (f.get("title") or "")]
        if not shares:
            return self._skip(name, "no anonymously readable shares found")

        t0 = time.time()

        def probe(finding: dict) -> list[dict]:
            ip = finding.get("ip")
            if not ip or not self.scope.contains(ip):
                return []
            names = re.findall(r"^([^\s(]+)", finding.get("evidence", ""), re.M)
            out_findings = []
            for share in bounded([n for n in names if n], 6):
                code, out, _ = _run(
                    [binary, "-N", f"//{ip}/{safe_arg(share, 40)}",
                     "-c", "ls"], 60)
                files = [l.strip() for l in (out or "").splitlines()
                         if re.match(r"^\s+\S+\s+[AHSDNR]+\s+\d+", l)]
                interesting = [f for f in files if re.search(
                    r"\.(kdbx|ps1|bat|cmd|config|xml|ini|bak|sql|pem|key|vbs|"
                    r"txt|csv|xlsx?|docx?)\b", f, re.I)]
                if interesting:
                    out_findings.append({
                        "ip": ip, "port": 445, "proto": "tcp",
                        "title": f"Readable files in anonymous share '{share}'",
                        "severity": "high", "confidence": "confirmed",
                        "cves": [], "source": "smbclient",
                        "evidence": safe_display(
                            "; ".join(interesting[:12]), 500),
                        "remediation": f"Remove anonymous read access to "
                                       f"'{share}' and review what it holds.",
                    })
            return out_findings

        found = parallel_collect(probe, bounded(shares, 40))
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            duration=time.time() - t0))

    # ------------------------------------------------------------ kerberos

    def kerberos_userenum(self):
        """Kerberos user enumeration.

        A pre-auth failure for a user that does not exist is distinguishable
        from one for a user that does — without ever submitting a password. No
        authentication attempt is made, so no account can lock out. That is why
        this is here and password spraying is not.
        """
        from .pipeline import StageResult, _run
        name = "kerberos-userenum"
        binary = _tool("kerbrute")
        if not binary:
            return self._skip(name, "kerbrute not installed")
        dcs = sorted({s["ip"] for s in self.state.services
                      if s["port"] in (88, 464) and self.scope.contains(s["ip"])})
        if not dcs:
            return self._skip(name, "no Kerberos service found")

        wordlist = None
        for path in ("/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
                     "/usr/share/wordlists/metasploit/unix_users.txt"):
            import pathlib
            if pathlib.Path(path).exists():
                wordlist = path
                break
        if not wordlist:
            return self._skip(name, "no username wordlist available")

        t0 = time.time()

        def probe(ip: str) -> list[dict]:
            code, out, err = _run([binary, "userenum", "-d", "DOMAIN",
                                   "--dc", ip, wordlist],
                                  min(self.timeout, 300))
            valid = re.findall(r"VALID USERNAME:\s+(\S+)", (out or "") + (err or ""))
            if valid:
                return [{
                    "ip": ip, "port": 88, "proto": "tcp",
                    "title": "Kerberos accounts enumerable without credentials",
                    "severity": "medium", "confidence": "confirmed", "cves": [],
                    "source": "kerbrute",
                    "evidence": safe_display(
                        f"{len(valid)} valid: " + ", ".join(valid[:15]), 400),
                    "remediation": "Kerberos pre-authentication reveals which "
                                   "accounts exist; monitor for enumeration and "
                                   "ensure lockout and alerting are in place.",
                }]
            return []

        found = parallel_collect(probe, bounded(dcs, 8))
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            duration=time.time() - t0))

    # ------------------------------------------------------------ tls

    def sslyze_scan(self):
        """sslyze gives structured JSON where sslscan gives text — better for
        certificate chain problems and renegotiation, and it complements rather
        than duplicates the sslscan stage."""
        from .pipeline import StageResult, _run
        name = "tls-structured"
        binary = _tool("sslyze")
        if not binary:
            return self._skip(name, "sslyze not installed")
        targets = [s for s in self.state.services
                   if self.scope.contains(s["ip"])
                   and (s.get("tunnel") == "ssl"
                        or s["port"] in (443, 8443, 993, 995, 465, 636))]
        if not targets:
            return self._skip(name, "no TLS services found")

        t0 = time.time()
        out_path = self.workdir / "sslyze.json"
        args = [f"{s['ip']}:{s['port']}" for s in bounded(targets, 32)]
        _run([binary, "--json_out", str(out_path), "--certinfo",
              "--reneg", "--compression", *args], min(self.timeout, 600))
        if not out_path.exists():
            return self._record(StageResult(name, True, skipped=True,
                                            reason="sslyze produced no output"))
        import json
        try:
            data = json.loads(out_path.read_text(errors="replace"))
        except (ValueError, OSError):
            return self._record(StageResult(name, True, skipped=True,
                                            reason="sslyze output unparseable"))

        found = []
        for res in (data.get("server_scan_results") or []):
            loc = res.get("server_location") or {}
            ip = loc.get("ip_address") or loc.get("hostname")
            port = loc.get("port")
            if not ip or not self.scope.contains(ip):
                continue
            scan = res.get("scan_result") or {}
            reneg = ((scan.get("session_renegotiation") or {}).get("result")
                     or {})
            if reneg.get("is_vulnerable_to_client_renegotiation_dos"):
                found.append({
                    "ip": ip, "port": port, "proto": "tcp",
                    "title": "TLS client-initiated renegotiation permitted",
                    "severity": "medium", "confidence": "confirmed", "cves": [],
                    "source": "sslyze",
                    "evidence": "client-initiated renegotiation accepted",
                    "remediation": "Disable client-initiated renegotiation.",
                })
            comp = (scan.get("tls_compression") or {}).get("result") or {}
            if comp.get("supports_compression"):
                found.append({
                    "ip": ip, "port": port, "proto": "tcp",
                    "title": "TLS compression enabled (CRIME)",
                    "severity": "medium", "confidence": "confirmed",
                    "cves": ["CVE-2012-4929"], "source": "sslyze",
                    "evidence": "TLS compression supported",
                    "remediation": "Disable TLS compression.",
                })
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            duration=time.time() - t0, artifact=str(out_path)))
