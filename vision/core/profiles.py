"""Scan intensity profiles.

Aggression in a network assessment is a set of trade-offs, not a single dial:
speed against accuracy, coverage against noise, thoroughness against the risk of
knocking over something fragile. A single `--aggressive` boolean hid all of that
behind one word.

Each profile below states what it changes and what it costs. Two things are
worth knowing before turning it up:

**Faster is less accurate.** nmap's `-T5` shortens timeouts to the point where a
loaded or rate-limited host starts reporting closed ports that are open. A scan
that finishes in a third of the time and misses a service is not a better scan.
`aggressive` uses `-T4`, which is the fastest timing most practitioners trust on
a real network.

**Aggressive is loud.** Higher rates, full port ranges and version probing on
every port will appear in the target's IDS, and on a fragile embedded device or
a legacy SCADA host, sustained probing can degrade the service. That is a
client-impacting outcome, so the profile says so and the console warns before
running it.

Aggression here means *finding more* and *finding it faster*. It never means
exploiting more: the exploit gates are unchanged at every intensity, because
"how thoroughly do I enumerate" and "may I fire this module" are different
decisions and only one of them is safe to put behind a speed setting.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Impact:
    """One consequence of running a profile.

    `serious` means client-impacting: an outage, an incident ticket, or a
    conversation with the client's legal team. Those are itemised rather than
    summarised, because "may be disruptive" is exactly the phrasing an operator
    skims past.
    """
    level: str      # info | caution | serious
    text: str


@dataclass(frozen=True)
class Profile:
    name: str
    summary: str
    impacts: tuple = ()

    # nmap
    timing: str = "-T4"
    min_rate: int = 1000
    max_retries: int = 2
    version_intensity: int = 7      # 0 (light) .. 9 (all probes)
    tcp_ports: str = "--top-ports=1000"
    udp_ports: str = "53,67,69,123,137,161,500,623,1434,1900,5353"
    host_timeout: str = ""
    scripts: bool = True            # -sC default script set

    # vision
    workers: int = 12               # concurrent per-host probes
    max_hosts_per_stage: int = 128
    http_paths: str = "standard"    # standard | extended
    snmp_communities: str = "common"    # common | extended
    tls_hosts: int = 16             # cap for the slow testssl stage
    nuclei_severity: str = "low,medium,high,critical"

    @property
    def is_loud(self) -> bool:
        return self.min_rate >= 5000 or self.tcp_ports == "-p-"

    @property
    def serious_impacts(self) -> list:
        return [i for i in self.impacts if i.level == "serious"]

    @property
    def needs_typed_confirmation(self) -> bool:
        """A y/N is muscle memory. Where a profile can take a device offline,
        the operator types the word instead."""
        return bool(self.serious_impacts)

    def nmap_flags(self) -> list[str]:
        flags = [self.timing, "--min-rate", str(self.min_rate),
                 "--max-retries", str(self.max_retries),
                 "--version-intensity", str(self.version_intensity)]
        if self.host_timeout:
            flags += ["--host-timeout", self.host_timeout]
        return flags

    def describe(self) -> list[str]:
        rows = [
            ("ports", "all 65535" if self.tcp_ports == "-p-" else "top 1000"),
            ("timing", f"{self.timing}  ·  {self.min_rate} pkt/s min rate"),
            ("version probes", f"intensity {self.version_intensity}/9"),
            ("concurrency", f"{self.workers} parallel probes"),
            ("web paths", self.http_paths),
            ("snmp strings", self.snmp_communities),
        ]
        return [f"{k.ljust(16)}{v}" for k, v in rows]


STEALTH = Profile(
    name="stealth",
    summary="Slow and quiet. Lower rates and fewer probes to stay under "
            "rate-based detection.",
    timing="-T2", min_rate=100, max_retries=1, version_intensity=2,
    impacts=(
        Impact("info", "Lowest footprint Vision offers — 200 ports, minimal "
                       "version probing, four concurrent connections."),
        Impact("caution", "Several times slower than normal. A /24 can take "
                          "hours."),
        Impact("caution", "Trades coverage for quiet: services outside the top "
                          "200 ports, and most web and TLS depth, are missed. "
                          "A clean result here is not evidence of a clean "
                          "network."),
    ),
    tcp_ports="--top-ports=200", udp_ports="161,500",
    host_timeout="30m", scripts=False,
    workers=4, max_hosts_per_stage=64, tls_hosts=8,
    nuclei_severity="medium,high,critical",
)

NORMAL = Profile(
    name="normal",
    summary="The default. Top 1000 TCP ports plus high-value extras, "
            "standard version detection.",
    impacts=(
        Impact("info", "Top 1000 TCP ports plus high-value extras that the "
                       "top-1000 misses, and a short UDP list."),
        Impact("info", "Anonymous-access checks only. No credentials are sent, "
                       "nothing is written to a target, no account can lock "
                       "out."),
        Impact("caution", "Visible in the target's logs: expect SMB, SNMP, "
                          "LDAP and HTTP connection attempts against every "
                          "live host."),
    ),
    timing="-T4", min_rate=1000, max_retries=2, version_intensity=7,
    tcp_ports="--top-ports=1000",
    workers=12, max_hosts_per_stage=128, tls_hosts=16,
)

AGGRESSIVE = Profile(
    name="aggressive",
    summary="All 65535 TCP ports, wider UDP, maximum version probing, "
            "double the concurrency, and an extended web path list.",
    impacts=(
        Impact("info", "The highest finding count Vision can produce. All 65535 "
                       "TCP ports, every stage, informational nuclei templates "
                       "included."),
        Impact("caution", "Version intensity 9 sends every probe nmap has at "
                          "each service — far more findings, and more tentative "
                          "ones needing manual verification."),
        Impact("caution", "5000 packets/second sustained for hours. On a slow "
                          "link, a congested VLAN or a WAN circuit this is "
                          "itself a performance problem for the client."),
        Impact("serious", "Intensive service probing can crash fragile "
                          "targets. Printers, IP cameras, VoIP handsets, "
                          "building-management controllers and industrial "
                          "equipment are known to hang or reboot under it. "
                          "This is the most common way an assessment causes an "
                          "outage — and it happens during scanning, not "
                          "exploitation."),
        Impact("serious", "Certain to trigger IDS, IPS and SOC alerting. "
                          "Without prior notice this will be handled as a live "
                          "intrusion, with the escalation that implies."),
        Impact("serious", "Appropriate only with written authorisation that "
                          "explicitly covers intensive scanning, and a named "
                          "client contact reachable while it runs."),
    ),
    timing="-T4", min_rate=5000, max_retries=2, version_intensity=9,
    tcp_ports="-p-",
    udp_ports="53,67,69,123,137,138,161,162,177,500,514,520,623,1434,"
              "1900,4500,5353,5060,11211",
    workers=24, max_hosts_per_stage=256,
    http_paths="extended", snmp_communities="extended", tls_hosts=32,
    # Informational templates included: at this intensity the operator has
    # asked for everything, and triage is the tool for the volume.
    nuclei_severity="info,low,medium,high,critical",
)

PROFILES = {p.name: p for p in (STEALTH, NORMAL, AGGRESSIVE)}
DEFAULT = NORMAL


def get(name: str | None) -> Profile:
    if not name:
        return DEFAULT
    try:
        return PROFILES[str(name).lower()]
    except KeyError:
        raise ValueError(
            f"unknown intensity {name!r} — choose one of "
            f"{', '.join(PROFILES)}") from None


# Community strings tried by the SNMP stage. The extended list is still a
# fixed set of documented vendor defaults, not a wordlist: checking known
# defaults is enumeration, whereas iterating a dictionary is a brute-force
# attack with a different risk profile and a different authorisation
# conversation.
SNMP_COMMON = ["public", "private", "manager", "cisco", "community"]
SNMP_EXTENDED = SNMP_COMMON + [
    "admin", "default", "read", "write", "monitor", "security", "secret",
    "snmp", "snmpd", "test", "guest", "all private", "cable-docsis",
    "ILMI", "TENmanUFactOryPOWER", "0392a0", "agent", "solaris",
]


def snmp_communities(profile: Profile) -> list[str]:
    return SNMP_EXTENDED if profile.snmp_communities == "extended" else SNMP_COMMON


# Paths the web stage checks. Extended is still deliberately short: this is
# exposure checking, and a directory brute-force turns an assessment into an
# attack, floods the target's logs, and buries real findings in 404s.
PATHS_EXTENDED = [
    ("/.git/config",       "high",     "Git config exposed",
     lambda b: "[core]" in b or "[remote" in b),
    ("/.svn/entries",      "medium",   "Subversion metadata exposed",
     lambda b: b.strip()[:2].isdigit() or "svn" in b.lower()),
    ("/config.json",       "high",     "Application config exposed",
     lambda b: b.lstrip().startswith("{") and any(
         k in b.lower() for k in ("password", "secret", "token", "key"))),
    ("/backup.zip",        "high",     "Backup archive exposed",
     lambda b: b[:2] == "PK"),
    ("/.well-known/security.txt", "info", "security.txt published",
     lambda b: "contact:" in b.lower()),
    ("/swagger.json",      "low",      "API schema exposed",
     lambda b: '"swagger"' in b or '"openapi"' in b),
    ("/metrics",           "medium",   "Prometheus metrics exposed",
     lambda b: b.startswith("# HELP") or "# TYPE" in b),
    ("/.aws/credentials",  "critical", "AWS credentials exposed",
     lambda b: "aws_access_key_id" in b.lower()),
    ("/wp-config.php.bak", "critical", "WordPress config backup exposed",
     lambda b: "DB_PASSWORD" in b),
]
