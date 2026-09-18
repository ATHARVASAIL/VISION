"""Control framework mapping.

Clients do not ask "is SMB signing off"; they ask which requirement that
breaches. Every serious assessment report carries this mapping, and doing it by
hand across a hundred findings is where transcription errors creep in.

**This is indicative, not an audit.** A mapping says "this finding is evidence
relevant to that control", which is what an assessment report needs. It is not
a determination of compliance: that requires scope definition, compensating
controls, and an assessor. The wording throughout is chosen to keep that
distinction visible, because a tool that implies a PCI pass/fail it cannot
justify creates real liability for whoever signs the report.

Mappings are deliberately conservative. Where a finding could arguably touch
five controls, it lists the one or two an assessor would actually cite. An
over-broad mapping makes every finding look like it breaches everything, which
is worse than no mapping at all.

Framework versions pinned here: MITRE ATT&CK Enterprise, CIS Critical Security
Controls v8, PCI DSS v4.0, OWASP Top 10 (2021). These get revised — check the
current release before quoting a control ID in a deliverable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

FRAMEWORK_VERSIONS = {
    "attack": "MITRE ATT&CK Enterprise",
    "cis": "CIS Critical Security Controls v8",
    "pci": "PCI DSS v4.0",
    "owasp": "OWASP Top 10 (2021)",
}


@dataclass(frozen=True)
class Control:
    framework: str
    id: str
    title: str
    url: str = ""

    @property
    def label(self) -> str:
        return f"{self.id} {self.title}"


# --------------------------------------------------------------------------
# Control definitions
# --------------------------------------------------------------------------

def _attack(tid: str, title: str) -> Control:
    path = tid.replace(".", "/")
    return Control("attack", tid, title,
                   f"https://attack.mitre.org/techniques/{path}/")


ATTACK = {
    "T1046": _attack("T1046", "Network Service Discovery"),
    "T1190": _attack("T1190", "Exploit Public-Facing Application"),
    "T1210": _attack("T1210", "Exploitation of Remote Services"),
    "T1557.001": _attack("T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay"),
    "T1110.003": _attack("T1110.003", "Password Spraying"),
    "T1087": _attack("T1087", "Account Discovery"),
    "T1040": _attack("T1040", "Network Sniffing"),
    "T1552.001": _attack("T1552.001", "Credentials In Files"),
    "T1021.002": _attack("T1021.002", "SMB/Windows Admin Shares"),
    "T1213": _attack("T1213", "Data from Information Repositories"),
    "T1078": _attack("T1078", "Valid Accounts"),
    "T1082": _attack("T1082", "System Information Discovery"),
    "T1006": _attack("T1006", "Direct Volume Access"),
    "T1133": _attack("T1133", "External Remote Services"),
    "T1592": _attack("T1592", "Gather Victim Host Information"),
    "T1595": _attack("T1595", "Active Scanning"),
}

CIS = {
    "3.10": Control("cis", "3.10", "Encrypt sensitive data in transit"),
    "4.1":  Control("cis", "4.1", "Establish and maintain a secure configuration process"),
    "4.6":  Control("cis", "4.6", "Securely manage enterprise assets and software"),
    "4.8":  Control("cis", "4.8", "Uninstall or disable unnecessary services"),
    "5.2":  Control("cis", "5.2", "Use unique passwords"),
    "6.2":  Control("cis", "6.2", "Establish an access revoking process"),
    "7.1":  Control("cis", "7.1", "Establish and maintain a vulnerability management process"),
    "7.3":  Control("cis", "7.3", "Perform automated operating system patch management"),
    "7.4":  Control("cis", "7.4", "Perform automated application patch management"),
    "12.2": Control("cis", "12.2", "Establish and maintain a secure network architecture"),
    "12.6": Control("cis", "12.6", "Use secure network management and communication protocols"),
    "13.4": Control("cis", "13.4", "Perform traffic filtering between network segments"),
    "16.11": Control("cis", "16.11", "Leverage vetted modules for application security"),
    "3.3":  Control("cis", "3.3", "Configure data access control lists"),
}

PCI = {
    "1.3":   Control("pci", "1.3", "Network access to and from the CDE is restricted"),
    "2.2":   Control("pci", "2.2", "System components are configured and managed securely"),
    "2.2.4": Control("pci", "2.2.4", "Unnecessary services and protocols are disabled"),
    "2.2.5": Control("pci", "2.2.5", "Insecure services and protocols are justified and secured"),
    "2.2.7": Control("pci", "2.2.7", "Non-console administrative access is encrypted"),
    "2.3":   Control("pci", "2.3", "Wireless environments are configured securely"),
    "4.2.1": Control("pci", "4.2.1", "Strong cryptography protects data in transit"),
    "6.3.3": Control("pci", "6.3.3", "Security patches are installed within a defined window"),
    "6.4.1": Control("pci", "6.4.1", "Public-facing web applications are protected"),
    "7.2.1": Control("pci", "7.2.1", "Access is assigned based on least privilege"),
    "8.3.1": Control("pci", "8.3.1", "Strong authentication is required for all access"),
    "11.3.1": Control("pci", "11.3.1", "Internal vulnerability scans are performed and resolved"),
}

OWASP = {
    "A01": Control("owasp", "A01:2021", "Broken Access Control",
                   "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
    "A02": Control("owasp", "A02:2021", "Cryptographic Failures",
                   "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
    "A05": Control("owasp", "A05:2021", "Security Misconfiguration",
                   "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
    "A06": Control("owasp", "A06:2021", "Vulnerable and Outdated Components",
                   "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"),
    "A07": Control("owasp", "A07:2021", "Identification and Authentication Failures",
                   "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"),
}


# --------------------------------------------------------------------------
# Mapping rules
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Mapping:
    pattern: str
    controls: tuple[Control, ...]
    note: str = ""
    _rx: Optional[re.Pattern] = field(default=None, compare=False, repr=False)


MAPPINGS: list[Mapping] = [
    Mapping(r"SMB signing",
            (ATTACK["T1557.001"], CIS["4.1"], PCI["2.2"]),
            "Unsigned SMB is the precondition for relay attacks."),
    Mapping(r"MS17-010|EternalBlue|CVE-2017-014",
            (ATTACK["T1210"], CIS["7.3"], PCI["6.3.3"], PCI["11.3.1"]),
            "A missing patch for a remotely exploitable service."),
    Mapping(r"shares accessible without auth|anonymous.*share",
            (ATTACK["T1021.002"], CIS["3.3"], PCI["7.2.1"], OWASP["A01"]),
            "Unauthenticated access to stored data."),
    Mapping(r"users enumerable|enumdomusers|anonymous bind",
            (ATTACK["T1087"], CIS["6.2"], PCI["7.2.1"]),
            "Account disclosure supporting later authentication attacks."),
    Mapping(r"(FTP|Telnet|POP3|IMAP|rlogin|rsh).*without transport encryption",
            (ATTACK["T1040"], CIS["3.10"], CIS["12.6"], PCI["2.2.5"], PCI["4.2.1"]),
            "Credentials and data recoverable by anyone on the path."),
    Mapping(r"SNMP readable with default community",
            (ATTACK["T1082"], CIS["4.6"], CIS["12.6"], PCI["2.2"], PCI["8.3.1"]),
            "Default credentials exposing device configuration."),
    Mapping(r"NFS exports",
            (ATTACK["T1213"], CIS["3.3"], PCI["7.2.1"]),
            "Unrestricted access to a shared filesystem."),
    Mapping(r"Redis|Memcached|MongoDB|Elasticsearch.*without auth",
            (ATTACK["T1213"], CIS["4.8"], PCI["8.3.1"], PCI["1.3"]),
            "A data store reachable with no authentication."),
    Mapping(r"Environment file exposed|Git repository exposed",
            (ATTACK["T1552.001"], CIS["16.11"], PCI["6.4.1"], OWASP["A05"]),
            "Application secrets retrievable over HTTP."),
    Mapping(r"security headers missing",
            (CIS["4.1"], PCI["6.4.1"], OWASP["A05"]),
            "Missing defence-in-depth headers on a web origin."),
    Mapping(r"Directory listing",
            (ATTACK["T1213"], CIS["4.1"], OWASP["A05"], PCI["6.4.1"]),
            "Unintended disclosure of served content."),
    Mapping(r"Server version disclosed|X-Powered-By|phpinfo|server-status",
            (ATTACK["T1592"], CIS["4.1"], OWASP["A05"]),
            "Information disclosure aiding target selection."),
    Mapping(r"Dangerous HTTP methods|WebDAV",
            (ATTACK["T1190"], CIS["4.8"], OWASP["A05"], PCI["6.4.1"]),
            "Methods enabled beyond what the application requires."),
    Mapping(r"certificate expired|certificate expires|self-signed",
            (CIS["3.10"], PCI["4.2.1"], OWASP["A02"]),
            "Transport encryption cannot be validated by clients."),
    Mapping(r"Deprecated protocol|TLSv1\.0|TLSv1\.1|SSLv[23]",
            (CIS["3.10"], PCI["4.2.1"], PCI["2.2.5"], OWASP["A02"]),
            "Protocol versions no longer considered strong cryptography."),
    Mapping(r"Public exploits available|Outdated ",
            (ATTACK["T1210"], CIS["7.4"], PCI["6.3.3"], OWASP["A06"]),
            "A component with known published vulnerabilities."),
    Mapping(r"Tomcat manager",
            (ATTACK["T1190"], CIS["4.8"], PCI["2.2.4"], OWASP["A05"]),
            "An administrative deployment interface reachable from the network."),
    Mapping(r"IKE aggressive mode",
            (ATTACK["T1133"], CIS["12.6"], PCI["4.2.1"]),
            "VPN negotiation exposing a crackable pre-shared key hash."),
    Mapping(r"password authentication",
            (ATTACK["T1110.003"], CIS["5.2"], PCI["8.3.1"], OWASP["A07"]),
            "Password-based access exposed to guessing."),
    Mapping(r"VNC|X11|RDP.*exposed",
            (ATTACK["T1133"], CIS["4.8"], CIS["13.4"], PCI["1.3"]),
            "Remote access service reachable from the assessed network."),
]

# Pre-compile once; MAPPINGS is module-level and matched against every finding.
_COMPILED = [(re.compile(m.pattern, re.I), m) for m in MAPPINGS]


def map_finding(finding: dict) -> list[Control]:
    """Controls relevant to a single finding. Deduplicated, order preserved."""
    text = " ".join(str(finding.get(k) or "") for k in
                    ("title", "description", "evidence"))
    out: list[Control] = []
    seen: set[tuple[str, str]] = set()
    for rx, mapping in _COMPILED:
        if not rx.search(text):
            continue
        for c in mapping.controls:
            key = (c.framework, c.id)
            if key not in seen:
                seen.add(key)
                out.append(c)
    return out


def coverage(findings: Iterable[dict]) -> dict[str, list[tuple[Control, int]]]:
    """Controls touched by this assessment, with how many findings hit each.

    This is the table an assessor wants: not "did you pass", but "here is the
    evidence gathered against each control, and how much of it there is".
    """
    tally: dict[tuple[str, str], tuple[Control, int]] = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        for c in map_finding(f):
            key = (c.framework, c.id)
            control, count = tally.get(key, (c, 0))
            tally[key] = (control, count + 1)

    grouped: dict[str, list[tuple[Control, int]]] = {}
    for (framework, _cid), (control, count) in tally.items():
        grouped.setdefault(framework, []).append((control, count))
    for framework in grouped:
        grouped[framework].sort(key=lambda pair: (-pair[1], pair[0].id))
    return grouped


def summary(findings: Iterable[dict]) -> dict:
    findings = [f for f in findings if isinstance(f, dict)]
    cov = coverage(findings)
    mapped = sum(1 for f in findings if map_finding(f))
    return {
        "findings": len(findings),
        "mapped": mapped,
        "unmapped": len(findings) - mapped,
        "frameworks": {k: len(v) for k, v in cov.items()},
        "controls_touched": sum(len(v) for v in cov.values()),
    }
