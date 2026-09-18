"""Attack path correlation.

A scanner produces a flat list. An assessment explains what the list *means*
together: an exposed `.env` is a medium on its own, but an exposed `.env` on a
host that also runs an internet-reachable database is a straight line to the
data. Analysts do this chaining in their heads and then write it into the
report; this module does the first pass so nothing obvious gets missed at 2am
on the last day of an engagement.

Design decisions worth knowing:

**Rules are declarative and conservative.** Each chain names its preconditions
as predicates over findings. A chain fires only when every precondition is
present, and its confidence is capped by the *weakest* link — a chain built on
a version-banner guess is itself a guess, no matter how alarming the
conclusion. Overstating a chain is worse than missing one, because a report
that cries wolf gets ignored entirely.

**Chains do not invent severity.** A chain's rating reflects the outcome it
enables, but it is never promoted above what the evidence supports. If every
step is `tentative`, the chain is reported as a lead to verify, not a finding.

**Nothing here touches the network.** This is pure analysis over findings
already collected, so it is safe to re-run, safe to run offline, and cannot
add load to a client's systems.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CONFIDENCE_RANK = {"tentative": 0, "firm": 1, "confirmed": 2}
RANK_CONFIDENCE = {v: k for k, v in CONFIDENCE_RANK.items()}

Predicate = Callable[[dict], bool]


# --------------------------------------------------------------------------
# Predicate builders — small, readable, reusable
# --------------------------------------------------------------------------

def title_matches(pattern: str) -> Predicate:
    rx = re.compile(pattern, re.I)
    return lambda f: bool(rx.search(f.get("title") or ""))


def has_cve(*cves: str) -> Predicate:
    wanted = {c.upper() for c in cves}
    return lambda f: bool(wanted & {c.upper() for c in (f.get("cves") or [])})


def on_port(*ports: int) -> Predicate:
    allowed = set(ports)
    return lambda f: f.get("port") in allowed


def any_of(*predicates: Predicate) -> Predicate:
    return lambda f: any(p(f) for p in predicates)


def all_of(*predicates: Predicate) -> Predicate:
    return lambda f: all(p(f) for p in predicates)


# --------------------------------------------------------------------------
# Chain definitions
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Step:
    """One precondition of a chain.

    `load_bearing` distinguishes the steps that carry the risk claim from the
    ones that merely establish context. "MySQL 5.5 detected" is tentative about
    the *version*, but the port being open is not in doubt — letting that drag
    a chain built on confirmed evidence down to tentative would understate real
    risk. Only load-bearing steps constrain the chain's confidence.
    """
    label: str
    match: Predicate
    load_bearing: bool = True


@dataclass(frozen=True)
class ChainRule:
    id: str
    name: str
    outcome: str            # what an attacker gets at the end
    severity: str           # ceiling, capped by evidence quality
    steps: tuple[Step, ...]
    narrative: str          # how the steps connect
    remediation: str
    scope: str = "host"     # "host" = one machine, "network" = across hosts
    references: tuple[str, ...] = ()


CHAINS: list[ChainRule] = [

    ChainRule(
        id="smb-relay",
        name="NTLM relay to authenticated SMB access",
        outcome="Authenticated access to file shares, and often code execution",
        severity="high",
        scope="network",
        steps=(
            Step("SMB signing not enforced", title_matches(r"SMB signing")),
            Step("Name-resolution poisoning surface present",
                 any_of(title_matches(r"LLMNR|NBT-NS|mDNS"),
                        title_matches(r"SMB shares accessible"))),
        ),
        narrative=(
            "With SMB signing unenforced, an authentication attempt captured "
            "via name-resolution poisoning can be relayed to this host instead "
            "of being cracked offline. The relay inherits the victim's "
            "privileges, so a single mistyped hostname on the network becomes "
            "authenticated access here."
        ),
        remediation=(
            "Enforce SMB signing on all hosts, and disable LLMNR and NBT-NS "
            "via Group Policy so there is nothing to poison."
        ),
        references=("https://attack.mitre.org/techniques/T1557/001/",),
    ),

    ChainRule(
        id="eternalblue-system",
        name="Unauthenticated SYSTEM via MS17-010",
        outcome="SYSTEM-level code execution without credentials",
        severity="critical",
        steps=(
            Step("MS17-010 present",
                 any_of(has_cve("CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145"),
                        title_matches(r"MS17-010|EternalBlue"))),
        ),
        narrative=(
            "MS17-010 grants SYSTEM on the target with no credentials and no "
            "user interaction. On a domain-joined host this is usually the "
            "shortest path from network access to domain compromise, since "
            "SYSTEM can read cached credentials and machine account secrets."
        ),
        remediation=(
            "Apply MS17-010. If the host cannot be patched, disable SMBv1 and "
            "isolate it at the network layer."
        ),
        references=("https://attack.mitre.org/techniques/T1210/",),
    ),

    ChainRule(
        id="redis-rce",
        name="Unauthenticated Redis to remote code execution",
        outcome="Command execution as the Redis service account",
        severity="critical",
        steps=(
            Step("Redis reachable without authentication",
                 title_matches(r"Redis exposed without auth")),
        ),
        narrative=(
            "An unauthenticated Redis instance accepts CONFIG SET, which lets "
            "an attacker relocate the dump file and write arbitrary content to "
            "disk — commonly an SSH authorized_keys entry or a cron job. This "
            "converts read access to the keyspace into code execution as "
            "whatever account Redis runs under."
        ),
        remediation=(
            "Set requirepass, bind Redis to localhost or a trusted interface, "
            "and enable protected-mode. Rename or disable CONFIG in production."
        ),
    ),

    ChainRule(
        id="secrets-to-data",
        name="Exposed application secrets to backing data store",
        outcome="Direct authenticated access to the application's database",
        severity="critical",
        steps=(
            Step("Application secrets exposed over HTTP",
                 any_of(title_matches(r"Environment file exposed"),
                        title_matches(r"Git repository exposed"))),
            Step("Database service reachable on the same host",
                 on_port(3306, 5432, 1433, 27017, 6379, 9200, 1521),
                 load_bearing=False),
        ),
        narrative=(
            "The exposed file typically contains the credentials the "
            "application uses for its own database, and that database is "
            "reachable on this host. Retrieving the file and connecting is two "
            "steps with no exploitation required — this is a configuration "
            "error that yields the data directly."
        ),
        remediation=(
            "Block external access to dotfiles and version-control metadata at "
            "the web server, rotate every credential that was exposed, and "
            "restrict the database to application hosts only."
        ),
    ),

    ChainRule(
        id="anon-share-write",
        name="Anonymous write access to a file share",
        outcome="Arbitrary file placement, and code execution where shares are executed",
        severity="critical",
        steps=(
            Step("Writable share without authentication",
                 all_of(title_matches(r"SMB shares accessible without auth"),
                        lambda f: "WRITE" in (f.get("evidence") or "").upper())),
        ),
        narrative=(
            "A writable anonymous share allows content to be placed on the "
            "host. Where the share backs a web root, a scripts directory, or a "
            "startup path, that becomes execution. Even where it does not, it "
            "enables planting lures for credential capture."
        ),
        remediation=(
            "Remove anonymous access and require authentication on every share. "
            "Audit the filesystem paths the writable shares expose."
        ),
    ),

    ChainRule(
        id="snmp-to-config",
        name="SNMP disclosure to device credentials",
        outcome="Device configuration, and frequently credentials in cleartext",
        severity="high",
        steps=(
            Step("SNMP readable with a default community",
                 title_matches(r"SNMP readable with default community")),
        ),
        narrative=(
            "A default community string exposes the full device MIB. On network "
            "equipment this routinely includes the running configuration, which "
            "carries local account hashes, SNMP write communities, and shared "
            "keys reused across the estate."
        ),
        remediation=(
            "Replace default community strings, restrict SNMP by source "
            "address, and migrate to SNMPv3 with authentication and privacy."
        ),
    ),

    ChainRule(
        id="userenum-to-spray",
        name="User enumeration to password spraying",
        outcome="A validated user list suitable for low-and-slow spraying",
        severity="medium",
        steps=(
            Step("Account names enumerable",
                 any_of(title_matches(r"users enumerable|enumdomusers"),
                        title_matches(r"LDAP allows anonymous bind"))),
            Step("An authentication service is reachable",
                 on_port(22, 445, 3389, 389, 636, 88, 1433),
                 load_bearing=False),
        ),
        narrative=(
            "Anonymous enumeration produces a confirmed account list, which "
            "removes the noisiest part of a spraying attack. An attacker can "
            "then try one common password across every account per lockout "
            "window — slow enough to avoid lockout, and effective at scale."
        ),
        remediation=(
            "Set RestrictAnonymous, disable anonymous LDAP bind, and enforce a "
            "lockout policy with monitoring for distributed failures."
        ),
        references=("https://attack.mitre.org/techniques/T1110/003/",),
    ),

    ChainRule(
        id="cleartext-credential-capture",
        name="Cleartext protocol to credential capture and reuse",
        outcome="Captured credentials, usable wherever they are reused",
        severity="high",
        scope="network",
        steps=(
            Step("Credentials traverse the network in cleartext",
                 title_matches(r"(FTP|Telnet|POP3|IMAP|rlogin|rsh) exposed "
                               r"without transport encryption")),
            Step("A second host accepts the same credentials in principle",
                 on_port(21, 22, 23, 445, 3389, 110, 143),
                 load_bearing=False),
        ),
        narrative=(
            "Credentials sent over these protocols are recoverable by anyone "
            "positioned on the path. Because administrators reuse credentials "
            "across systems, a single capture typically unlocks more than the "
            "service it was taken from."
        ),
        remediation=(
            "Retire cleartext protocols in favour of SSH, SFTP and TLS-wrapped "
            "equivalents, and rotate any credential that has traversed them."
        ),
    ),

    ChainRule(
        id="nfs-key-drop",
        name="World-readable NFS export to credential material",
        outcome="Access to home directories, SSH keys and backups",
        severity="high",
        steps=(
            Step("NFS exports readable without restriction",
                 title_matches(r"NFS exports world-readable")),
        ),
        narrative=(
            "Unrestricted exports commonly contain home directories, which "
            "carry SSH private keys and shell history. With no_root_squash "
            "they also allow writing an authorized_keys file directly."
        ),
        remediation=(
            "Restrict exports to specific hosts, enable root_squash, and avoid "
            "exporting home directories where possible."
        ),
    ),

    ChainRule(
        id="tomcat-war-deploy",
        name="Reachable Tomcat manager to application deployment",
        outcome="Code execution via WAR deployment once credentials are known",
        severity="high",
        steps=(
            Step("Tomcat manager reachable",
                 title_matches(r"Tomcat manager")),
        ),
        narrative=(
            "The manager application deploys arbitrary WAR files. Reaching it "
            "from the network means the only remaining barrier is its "
            "credentials, which are frequently left at vendor defaults or "
            "shared across an estate."
        ),
        remediation=(
            "Restrict the manager application to localhost or a management "
            "network, and ensure its accounts use unique strong passwords."
        ),
    ),
]


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------

@dataclass
class AttackPath:
    rule: ChainRule
    host: Optional[str]
    findings: list[dict] = field(default_factory=list)
    matched_steps: list[tuple[str, dict]] = field(default_factory=list)
    load_bearing: list[dict] = field(default_factory=list)

    @property
    def confidence(self) -> str:
        """A chain is only as sound as its weakest *load-bearing* link."""
        basis = self.load_bearing or self.findings
        if not basis:
            return "tentative"
        worst = min(CONFIDENCE_RANK.get(f.get("confidence", "tentative"), 0)
                    for f in basis)
        return RANK_CONFIDENCE[worst]

    @property
    def severity(self) -> str:
        """Chain severity, capped by evidence quality.

        A chain assembled entirely from version-banner guesses describes a
        possibility, not a finding, so it is not allowed to claim critical.
        """
        ceiling = SEVERITY_RANK.get(self.rule.severity, 2)
        if self.confidence == "tentative":
            ceiling = min(ceiling, SEVERITY_RANK["medium"])
        elif self.confidence == "firm":
            ceiling = min(ceiling, SEVERITY_RANK["high"])
        for label, rank in sorted(SEVERITY_RANK.items(), key=lambda kv: -kv[1]):
            if rank == ceiling:
                return label
        return "medium"

    @property
    def score(self) -> float:
        """Ordering for operator attention: impact first, then how sure we are,
        then how much evidence supports it."""
        return (SEVERITY_RANK.get(self.severity, 0) * 100
                + CONFIDENCE_RANK.get(self.confidence, 0) * 20
                + min(len(self.findings), 5))

    @property
    def title(self) -> str:
        where = f" on {self.host}" if self.host else " across the network"
        return f"{self.rule.name}{where}"

    def as_finding(self) -> dict:
        """Render as a normal finding so it flows through report and export
        without any special-casing downstream."""
        steps = " → ".join(label for label, _ in self.matched_steps)
        evidence_lines = [f"{label}: {f.get('title', '')}"
                          for label, f in self.matched_steps]
        cves = sorted({c for f in self.findings for c in (f.get("cves") or [])})
        return {
            "ip": self.host or (self.findings[0].get("ip") if self.findings else ""),
            "port": self.findings[0].get("port") if self.findings else None,
            "proto": "tcp",
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "cves": cves,
            "description": f"{self.rule.narrative}\n\nOutcome: {self.rule.outcome}",
            "evidence": f"Chain: {steps}\n" + "\n".join(evidence_lines),
            "remediation": self.rule.remediation,
            "references": list(self.rule.references),
            "source": f"correlation:{self.rule.id}",
        }


def _match_host(rule: ChainRule, findings: list[dict]) -> Optional[AttackPath]:
    matched: list[tuple[str, dict]] = []
    load_bearing: list[dict] = []
    used: set[int] = set()
    for step in rule.steps:
        hit = None
        for i, f in enumerate(findings):
            # Load-bearing steps each need their own finding: two steps
            # satisfied by one piece of evidence is one observation dressed up
            # as a chain. Contextual steps may reuse a finding, because "and a
            # database is reachable here" often describes the same record the
            # load-bearing step matched.
            if i in used and step.load_bearing:
                continue
            try:
                if step.match(f):
                    hit = (i, f)
                    break
            except Exception:
                # A malformed finding must not take the whole correlation down.
                continue
        if hit is None:
            return None
        if step.load_bearing:
            used.add(hit[0])
            load_bearing.append(hit[1])
        matched.append((step.label, hit[1]))
    return AttackPath(rule=rule, host=None,
                      findings=[f for _, f in matched], matched_steps=matched,
                      load_bearing=load_bearing)


def correlate(findings: Iterable[dict],
              rules: Iterable[ChainRule] | None = None) -> list[AttackPath]:
    """Derive attack paths from a flat findings list.

    Host-scoped chains match within a single host. Network-scoped chains may
    draw their steps from different hosts, because lateral movement is the
    whole point of them.
    """
    findings = [f for f in findings if isinstance(f, dict)]
    rules = list(rules if rules is not None else CHAINS)

    by_host: dict[str, list[dict]] = {}
    for f in findings:
        ip = f.get("ip")
        if ip:
            by_host.setdefault(ip, []).append(f)

    paths: list[AttackPath] = []
    for rule in rules:
        if rule.scope == "network":
            path = _match_host(rule, findings)
            if path:
                hosts = {f.get("ip") for f in path.findings if f.get("ip")}
                path.host = next(iter(hosts)) if len(hosts) == 1 else None
                paths.append(path)
            continue
        for host, host_findings in by_host.items():
            path = _match_host(rule, host_findings)
            if path:
                path.host = host
                paths.append(path)

    paths.sort(key=lambda p: -p.score)
    return paths


def summary(paths: list[AttackPath]) -> dict:
    by_sev: dict[str, int] = {}
    for p in paths:
        by_sev[p.severity] = by_sev.get(p.severity, 0) + 1
    return {
        "paths": len(paths),
        "hosts": len({p.host for p in paths if p.host}),
        "by_severity": by_sev,
        "confirmed": sum(1 for p in paths if p.confidence == "confirmed"),
    }
