"""Coverage audit: what was seen but never assessed.

A finding count answers "what did you find". It does not answer "did you look
everywhere", and those are different questions — the second is the one a client
is really asking and the one an assessor has to be able to defend.

Three ways a service goes unassessed, and all three look identical in a
findings list:

  1. The stage that would cover it never ran, because its tool was missing.
  2. The stage ran but the service is one no stage knows how to handle.
  3. The stage ran, covered it, and there was genuinely nothing wrong.

Only the third is a clean result. The first two are gaps, and reporting them as
clean is how an assessment misses something that was sitting in the port list
the whole time. A real Metasploitable run had rpcbind on 111 open with no
finding of any kind against it — visible in the services table, invisible in
the report.

This module makes the distinction explicit rather than leaving it to whoever
reads the output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

# Which stage is responsible for a service, so an unassessed port can name the
# stage that should have covered it rather than just being flagged.
STAGE_FOR_SERVICE: list[tuple[tuple[str, ...], tuple[int, ...], str]] = [
    (("ftp",), (21, 2121), "banner-analysis"),
    (("ftps", "ftp-data"), (990,), "banner-analysis"),
    (("ssh",), (22,), "banner-analysis"),
    (("telnet",), (23, 2323), "banner-analysis"),
    (("smtp", "smtps", "submission"), (25, 465, 587), "banner-analysis"),
    (("domain", "dns"), (53,), "banner-analysis"),
    (("http", "http-alt", "https", "http-proxy", "https-alt"),
     (80, 443, 8080, 8443, 8000, 8888, 8180, 8081, 8443, 9443, 3000, 5000),
     "web-assessment"),
    (("netbios-ssn", "microsoft-ds", "smb", "netbios-dgm", "netbios-ns"),
     (137, 138, 139, 445), "smb-enumeration"),
    (("msrpc", "epmap", "dcerpc"), (135,), "rpc-enumeration"),
    (("rpcbind", "nfs", "mountd"), (111, 2049), "nfs-exports"),
    (("snmp", "snmptrap"), (161, 162), "snmp-enumeration"),
    (("ldap", "ldaps", "globalcat", "globalcatLDAPssl"),
     (389, 636, 3268, 3269), "ldap-anonymous-bind"),
    (("kerberos", "kerberos-sec", "kpasswd", "kpasswd5"),
     (88, 464), "kerberos-userenum"),
    (("isakmp", "ipsec-nat-t"), (500, 4500), "ike-vpn"),
    (("exec", "login", "shell", "rexec", "rlogin", "rsh"),
     (512, 513, 514), "banner-analysis"),
    (("mysql", "mysql-alt"), (3306, 33060), "exploitdb-correlation"),
    (("postgresql", "postgres"), (5432,), "exploitdb-correlation"),
    (("ms-sql-s", "ms-sql-m", "mssql"), (1433, 1434), "exploitdb-correlation"),
    (("oracle", "oracle-tns", "tns"), (1521, 1522), "exploitdb-correlation"),
    (("vnc", "vnc-http"), (5800, 5900, 5901, 5902), "banner-analysis"),
    (("rdp", "ms-wbt-server", "ms-term-serv"), (3389,), "banner-analysis"),
    (("x11",), (6000, 6001), "banner-analysis"),
    (("redis", "memcached", "mongodb", "elasticsearch", "cassandra",
      "couchdb", "riak"),
     (6379, 11211, 27017, 9200, 9042, 5984, 8087), "datastore-exposure"),
    (("winrm", "wsman"), (5985, 5986), "banner-analysis"),
    (("irc", "ircs"), (6667, 6697), "banner-analysis"),
    (("sip", "sip-tls"), (5060, 5061), "banner-analysis"),
    (("ajp13",), (8009,), "web-assessment"),
    (("docker", "docker-s"), (2375, 2376), "datastore-exposure"),
    (("rmiregistry", "java-rmi"), (1099,), "exploitdb-correlation"),
]


@dataclass
class ServiceCoverage:
    ip: str
    port: int
    name: str
    findings: int = 0
    expected_stage: Optional[str] = None
    stage_ran: bool = True
    stage_reason: str = ""

    @property
    def assessed(self) -> bool:
        """Covered if something reported on it, or the responsible stage ran
        and found nothing. Not covered if the stage never ran."""
        return self.findings > 0 or (self.stage_ran and
                                     self.expected_stage is not None)

    @property
    def why(self) -> str:
        if self.findings:
            return f"{self.findings} finding(s)"
        if self.expected_stage and not self.stage_ran:
            return f"{self.expected_stage} did not run — {self.stage_reason}"
        if self.expected_stage:
            return f"{self.expected_stage} ran, nothing found"
        return "no stage covers this service"


@dataclass
class Audit:
    services: list = field(default_factory=list)
    skipped_for_tools: list = field(default_factory=list)
    incomplete_stages: list = field(default_factory=list)

    @property
    def unassessed(self) -> list:
        return [s for s in self.services if not s.assessed]

    @property
    def silent(self) -> list:
        """Assessed, but produced nothing. Worth showing separately: an
        operator may want to look by hand."""
        return [s for s in self.services if s.assessed and not s.findings]

    @property
    def percent(self) -> int:
        if not self.services:
            return 100
        return round(100 * (len(self.services) - len(self.unassessed))
                     / len(self.services))

    @property
    def is_clean(self) -> bool:
        return (not self.unassessed and not self.skipped_for_tools
                and not self.incomplete_stages)

    def summary(self) -> str:
        bits = [f"{self.percent}% of services assessed"]
        if self.unassessed:
            bits.append(f"{len(self.unassessed)} not covered by any stage")
        if self.skipped_for_tools:
            bits.append(f"{len(self.skipped_for_tools)} stage(s) missing tools")
        if self.incomplete_stages:
            bits.append(f"{len(self.incomplete_stages)} stage(s) timed out")
        return " · ".join(bits)


def expected_stage(service: dict) -> Optional[str]:
    """Which stage should have covered this service. Matches on the service
    name first and the port second — the same rule the stages themselves use,
    so a service on a non-standard port is still attributed correctly."""
    name = (service.get("name") or "").lower()
    product = (service.get("product") or "").lower()
    blob = f"{name} {product}"
    port = service.get("port")
    for names, ports, stage in STAGE_FOR_SERVICE:
        if any(n in blob for n in names):
            return stage
    for names, ports, stage in STAGE_FOR_SERVICE:
        if port in ports:
            return stage
    return None


def audit(services: Iterable[dict], findings: Iterable[dict],
          stages: Iterable[dict] | None = None) -> Audit:
    """Cross-check every discovered service against what was reported."""
    stages = list(stages or [])
    findings = list(findings)

    ran, reasons = {}, {}
    for st in stages:
        name = st.get("name")
        if not name:
            continue
        # A stage that ran at least once counts as having run, since a rescan
        # appends rather than replaces.
        ran[name] = ran.get(name, False) or not st.get("skipped")
        if st.get("skipped"):
            reasons.setdefault(name, str(st.get("reason", "")))

    by_target: dict = {}
    for f in findings:
        key = (f.get("ip"), f.get("port"))
        by_target[key] = by_target.get(key, 0) + 1

    out = []
    for svc in services:
        ip, port = svc.get("ip"), svc.get("port")
        stage = expected_stage(svc)
        out.append(ServiceCoverage(
            ip=ip, port=port, name=svc.get("name") or "unknown",
            findings=by_target.get((ip, port), 0),
            expected_stage=stage,
            stage_ran=ran.get(stage, True) if stage else True,
            stage_reason=reasons.get(stage, ""),
        ))

    missing_tools = sorted({
        str(st.get("reason", "")).replace(" not installed", "")
        for st in stages
        if st.get("skipped") and "not installed" in str(st.get("reason", ""))
    })
    incomplete = sorted({st.get("name") for st in stages
                         if st.get("incomplete")})
    return Audit(services=out, skipped_for_tools=missing_tools,
                 incomplete_stages=[i for i in incomplete if i])
