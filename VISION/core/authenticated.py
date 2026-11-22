"""Authenticated enumeration.

These stages only run when the operator has supplied a credential. Each one
looks for something an anonymous scan cannot see: which shares an ordinary user
can actually read, where that account is a local administrator, whether the
password policy is survivable, which service accounts are Kerberoastable.

Every stage here is **read-only**. Enumerating where an account has admin rights
is not the same as using them, and Vision does not cross that line — executing
commands on a host is an exploitation decision, and exploitation stays behind
the confirmation gate where it has always been.

Two operational cautions are enforced rather than documented:

  - Nothing here submits a password it was not given. A supplied credential is
    used; no guessing, no spraying, no lockout risk introduced by a scan.
  - The credential is never written. Commands that must carry it in argv are
    redacted before the run log sees them, and the evidence files are written
    from output that has already been sanitised.
"""

from __future__ import annotations

import re
import time
from typing import Optional

from .concurrency import parallel_collect
from .credentials import Credential, nxc_args
from .safety import bounded, safe_display
from .toolchain import resolve as _tool




# netexec prints "(Pwn3d!)" when the account is a local administrator.
_PWNED = re.compile(r"\(Pwn3d!\)", re.I)
_SHARE_ROW = re.compile(
    r"^\s*SMB\s+\S+\s+\d+\s+\S+\s+(\S.*?)\s{2,}(READ|WRITE|READ,WRITE)", re.I | re.M)


class AuthenticatedStages:
    """Mixin for Pipeline. Skips entirely without a credential."""

    def _cred(self) -> Optional[Credential]:
        return getattr(self, "credential", None)

    # ------------------------------------------------------------ admin sprawl

    def auth_admin_sprawl(self):
        """Where does this one account have local administrator rights?

        The single most useful authenticated question on an internal network.
        A helpdesk account that is local admin on 200 workstations is a
        finding no anonymous scan can produce, and it usually surprises the
        client more than anything else in the report.
        """
        from .pipeline import StageResult, _run
        name = "auth-admin-sprawl"
        cred = self._cred()
        if not cred:
            return self._skip(name, "no credential supplied")
        binary = _tool("netexec")
        if not binary:
            return self._skip(name, "netexec not installed")
        hosts = sorted({s["ip"] for s in self.state.services
                        if s["port"] in (139, 445) and self.scope.contains(s["ip"])})
        if not hosts:
            return self._skip(name, "no SMB services found")

        t0 = time.time()

        def probe(ip: str) -> list[dict]:
            code, out, err = _run([binary, "smb", ip, *nxc_args(cred)], 60)
            blob = (out or "") + (err or "")
            if not _PWNED.search(blob):
                return []
            return [{
                "ip": ip, "port": 445, "proto": "tcp",
                "title": f"Account '{cred.display}' is local administrator",
                "severity": "high", "confidence": "confirmed", "cves": [],
                "source": "netexec:auth",
                "evidence": safe_display(blob.strip(), 300),
                "remediation": "Review why this account holds local admin here. "
                               "Widespread local admin lets one compromised "
                               "account move laterally across the estate.",
            }]

        found = parallel_collect(probe, bounded(hosts, self.profile.max_hosts_per_stage))
        before = len(self.state.findings)
        self._merge_findings(found)

        # The estate-wide picture matters more than any single host.
        if len(found) > 1:
            self._merge_findings([{
                "ip": found[0]["ip"], "port": 445, "proto": "tcp",
                "title": f"Local admin rights on {len(found)} hosts from one account",
                "severity": "critical" if len(found) >= 5 else "high",
                "confidence": "confirmed", "cves": [], "source": "netexec:auth",
                "evidence": safe_display(
                    "admin on: " + ", ".join(f["ip"] for f in found[:20]), 500),
                "remediation": "Break up shared local administrator access. One "
                               "stolen credential currently reaches every host "
                               "listed here.",
            }])
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            hosts=len(hosts), duration=time.time() - t0))

    # ------------------------------------------------------------ shares

    def auth_share_access(self):
        """What can an ordinary user actually read?

        Anonymous share enumeration finds what is open to everyone.
        Authenticated enumeration finds the much larger set that is open to
        anyone with a login — which is where the payroll folder usually is.
        """
        from .pipeline import StageResult, _run
        name = "auth-share-access"
        cred = self._cred()
        if not cred:
            return self._skip(name, "no credential supplied")
        binary = _tool("netexec")
        if not binary:
            return self._skip(name, "netexec not installed")
        hosts = sorted({s["ip"] for s in self.state.services
                        if s["port"] in (139, 445) and self.scope.contains(s["ip"])})
        if not hosts:
            return self._skip(name, "no SMB services found")

        t0 = time.time()
        SENSITIVE = re.compile(
            r"payroll|finance|hr\b|backup|admin|IT\b|confidential|secret|"
            r"password|salary|export|archive", re.I)

        def probe(ip: str) -> list[dict]:
            code, out, err = _run(
                [binary, "smb", ip, *nxc_args(cred), "--shares"], 90)
            blob = (out or "") + (err or "")
            writable, readable = [], []
            for share, perm in _SHARE_ROW.findall(blob):
                share = share.strip()
                if share.upper() in ("IPC$", "PRINT$"):
                    continue
                (writable if "WRITE" in perm.upper() else readable).append(share)

            results = []
            if writable:
                results.append({
                    "ip": ip, "port": 445, "proto": "tcp",
                    "title": "Writable shares available to a standard user",
                    "severity": "high", "confidence": "confirmed", "cves": [],
                    "source": "netexec:auth",
                    "evidence": safe_display("; ".join(writable[:12]), 400),
                    "remediation": "Restrict write access to the groups that "
                                   "need it. A writable share is a route to "
                                   "planting content every user can reach.",
                })
            flagged = [s for s in readable + writable if SENSITIVE.search(s)]
            if flagged:
                results.append({
                    "ip": ip, "port": 445, "proto": "tcp",
                    "title": "Sensitively named shares readable by any user",
                    "severity": "medium", "confidence": "firm", "cves": [],
                    "source": "netexec:auth",
                    "evidence": safe_display("; ".join(flagged[:12]), 400),
                    "remediation": "Review the contents and permissions of "
                                   "these shares — the names suggest data that "
                                   "should not be readable estate-wide.",
                })
            return results

        found = parallel_collect(probe, bounded(hosts, self.profile.max_hosts_per_stage))
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            hosts=len(hosts), duration=time.time() - t0))

    # ------------------------------------------------------------ policy

    def auth_password_policy(self):
        """The real password policy, which is only readable once logged in.

        This is also what tells an operator whether spraying is survivable
        later — read the lockout threshold before touching authentication, not
        after.
        """
        from .pipeline import StageResult, _run
        name = "auth-password-policy"
        cred = self._cred()
        if not cred:
            return self._skip(name, "no credential supplied")
        binary = _tool("netexec")
        if not binary:
            return self._skip(name, "netexec not installed")
        hosts = sorted({s["ip"] for s in self.state.services
                        if s["port"] in (139, 445) and self.scope.contains(s["ip"])})
        if not hosts:
            return self._skip(name, "no SMB services found")

        t0 = time.time()
        found = []
        for ip in bounded(hosts, 4):    # policy is domain-wide; a few is plenty
            code, out, err = _run(
                [binary, "smb", ip, *nxc_args(cred), "--pass-pol"], 60)
            blob = (out or "") + (err or "")
            m = re.search(r"Minimum password length:\s*(\d+)", blob, re.I)
            if m and int(m.group(1)) < 12:
                found.append({
                    "ip": ip, "port": 445, "proto": "tcp",
                    "title": f"Minimum password length is {m.group(1)}",
                    "severity": "medium" if int(m.group(1)) >= 8 else "high",
                    "confidence": "confirmed", "cves": [],
                    "source": "netexec:auth",
                    "evidence": safe_display(m.group(0), 120),
                    "remediation": "Require at least 12 characters, or move to "
                                   "passphrases with a longer minimum.",
                })
            lock = re.search(r"Account Lockout Threshold:\s*(\S+)", blob, re.I)
            if lock and lock.group(1).lower() in ("none", "0", "disabled"):
                found.append({
                    "ip": ip, "port": 445, "proto": "tcp",
                    "title": "No account lockout threshold",
                    "severity": "high", "confidence": "confirmed", "cves": [],
                    "source": "netexec:auth",
                    "evidence": safe_display(lock.group(0), 120),
                    "remediation": "Set a lockout threshold. Without one, an "
                                   "attacker can guess passwords indefinitely.",
                })
            if found:
                break   # one authoritative read of a domain-wide policy
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            duration=time.time() - t0))

    # ------------------------------------------------------------ kerberoast

    def auth_kerberoast(self):
        """Service accounts with an SPN.

        Requesting a service ticket is a normal, logged Kerberos operation that
        any domain user may perform. The resulting ticket is encrypted with the
        service account's password hash, so a weak password becomes crackable
        entirely offline — no further traffic to the client, no lockout.

        Vision reports that the accounts are roastable. It does not crack them:
        that is an operator decision about time and hardware, and the playbook
        has the hashcat command.
        """
        from .pipeline import StageResult, _run
        name = "auth-kerberoast"
        cred = self._cred()
        if not cred or not cred.domain:
            return self._skip(name, "needs a domain credential")
        import shutil
        binary = (shutil.which("impacket-GetUserSPNs")
                  or shutil.which("GetUserSPNs.py"))
        if not binary:
            return self._skip(name, "impacket-GetUserSPNs not installed")
        dcs = sorted({s["ip"] for s in self.state.services
                      if s["port"] in (88, 389, 445)
                      and self.scope.contains(s["ip"])})
        if not dcs:
            return self._skip(name, "no domain controller found")

        t0 = time.time()
        found = []
        for ip in bounded(dcs, 3):
            target = f"{cred.domain}/{cred.username}:{cred.secret}"
            code, out, err = _run([binary, target, "-dc-ip", ip], 120)
            blob = (out or "") + (err or "")
            spns = re.findall(r"^\s*(\S+/\S+)\s+(\S+)\s", blob, re.M)
            if spns:
                found.append({
                    "ip": ip, "port": 88, "proto": "tcp",
                    "title": f"{len(spns)} Kerberoastable service account(s)",
                    "severity": "high", "confidence": "confirmed", "cves": [],
                    "source": "impacket:auth",
                    "evidence": safe_display(
                        "; ".join(f"{s[1]} ({s[0]})" for s in spns[:10]), 450),
                    "remediation": "Use managed service accounts, or give these "
                                   "accounts long random passwords. Any domain "
                                   "user can request their tickets and crack "
                                   "them offline.",
                })
                break
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            duration=time.time() - t0))
