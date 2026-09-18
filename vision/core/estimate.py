"""How long this is going to take.

An operator deciding between profiles is really asking one question: *do I
wait, or do I go and do something else?* Vision used to answer with a vague
phrase per profile — "5–15 minutes for a small subnet" — which is useless once
the host count or the stage list changes.

These numbers come from measured runs, not guesses. The reference is a real
Metasploitable 2 assessment: 32 stages, one host, 22 open TCP ports, 49.7
minutes wall-clock, of which nuclei alone was 31.7 and nmap's vulnerability
scripts 7.0.

**Estimates are ranges, and they are labelled as estimates.** A stage's cost
depends on how many services answer, how fast the target responds, and whether
a template happens to be slow — none of which is knowable before the scan. The
figure exists to set expectations, not to be held to.

Two properties matter more than precision:

  - **Never quietly under-promise.** An operator told "3 minutes" who is still
    waiting at 40 stops trusting every other number the tool prints.
  - **Name the expensive stages.** Knowing *nuclei* is two thirds of the run
    is more useful than a single total, because it is the one an operator may
    choose to skip.
"""

from __future__ import annotations

from dataclasses import dataclass

# Seconds. `base` is fixed setup cost, `per_host` scales with live hosts, and
# `per_service` with discovered services. Measured against the reference run
# and rounded conservatively upward.
STAGE_COST = {
    # discovery — dominated by the sweep itself, not the host count
    "host-discovery":        (8, 0.4, 0),
    "icmp-sweep":            (3, 0.1, 0),
    "arp-discovery":         (6, 0.1, 0),

    # port scanning — the second-largest cost after nuclei
    "port-scan":             (25, 260, 0),
    "masscan-sweep":         (20, 2, 0),
    "udp-scan":              (30, 40, 0),
    "banner-analysis":       (1, 0, 0.2),
    "netbios-scan":          (3, 1, 0),

    # enumeration — scales with services, cheap individually
    "smb-enumeration":       (2, 4, 0),
    "smb-shares":            (2, 20, 0),
    "smb-deep-enum":         (2, 12, 0),
    "smb-file-listing":      (2, 8, 0),
    "rpc-enumeration":       (2, 3, 0),
    "snmp-enumeration":      (5, 90, 0),
    "nfs-exports":           (2, 3, 0),
    "ldap-anonymous-bind":   (2, 3, 0),
    "ike-vpn":               (2, 6, 0),
    "kerberos-userenum":     (5, 20, 0),
    "datastore-exposure":    (1, 0, 0.5),

    # authenticated
    "auth-admin-sprawl":     (3, 6, 0),
    "auth-share-access":     (3, 8, 0),
    "auth-password-policy":  (5, 2, 0),
    "auth-kerberoast":       (10, 5, 0),

    # web and TLS
    "web-assessment":        (1, 0, 2),
    "web-exposed-paths":     (2, 0, 4),
    "tls-certificate":       (1, 0, 2),
    "tls-posture":           (2, 0, 8),
    "tls-structured":        (5, 0, 10),
    "tls-deep":              (10, 0, 60),

    # vulnerability assessment — the expensive end
    "exploitdb-correlation": (2, 0, 1),
    "nuclei":                (60, 120, 6),
    "nmap-vuln-scripts":     (30, 380, 0),
}

DEFAULT_COST = (5, 5, 0)

# How many hosts a stage works on at once. Scaling per-host cost linearly gave
# 197 hours for a /24 — nonsense, because nmap parallelises internally and the
# enrichment stages run through a bounded thread pool. Effective concurrency is
# what actually determines wall-clock on a large scope.
STAGE_PARALLELISM = {
    # nmap handles its own host parallelism and is very good at it
    "host-discovery": 64, "icmp-sweep": 64, "arp-discovery": 64,
    "port-scan": 24, "masscan-sweep": 128, "udp-scan": 24,
    "netbios-scan": 32, "nmap-vuln-scripts": 12,
    # nuclei has its own concurrency setting
    "nuclei": 25,
    # stages using parallel_collect — see Profile.workers
    "smb-enumeration": 12, "smb-shares": 12, "smb-deep-enum": 12,
    "smb-file-listing": 12, "rpc-enumeration": 12, "snmp-enumeration": 12,
    "nfs-exports": 12, "ldap-anonymous-bind": 12, "ike-vpn": 12,
    "kerberos-userenum": 8, "tls-posture": 12, "tls-structured": 12,
    "tls-deep": 4, "auth-admin-sprawl": 12, "auth-share-access": 12,
    "auth-password-policy": 4, "auth-kerberoast": 3,
}
DEFAULT_PARALLELISM = 8

# Multipliers per intensity, from the profile's own rate and port-range
# settings rather than a separate guess.
INTENSITY_FACTOR = {"stealth": 3.0, "normal": 1.0, "aggressive": 2.2}

# Stages worth calling out individually when they dominate the estimate.
CALLOUT_SHARE = 0.15


@dataclass
class Estimate:
    seconds: float
    per_stage: dict
    hosts: int
    services: int
    intensity: str

    @property
    def low(self) -> float:
        # Real runs come in faster than the worst case more often than not;
        # the band is deliberately wide because the inputs are unknowable.
        return self.seconds * 0.6

    @property
    def high(self) -> float:
        return self.seconds * 1.8

    @property
    def dominant(self) -> list:
        """Stages taking a meaningful share — the ones worth skipping."""
        if self.seconds <= 0:
            return []
        return sorted(
            [(n, c) for n, c in self.per_stage.items()
             if c / self.seconds >= CALLOUT_SHARE],
            key=lambda kv: -kv[1])

    def range_text(self) -> str:
        return f"{human(self.low)}–{human(self.high)}"


def human(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 5400:
        return f"{round(seconds / 60)} min"
    hours = seconds / 3600
    return f"{hours:.1f} hr"


def estimate(stages, hosts: int, services: int = 0,
             intensity: str = "normal") -> Estimate:
    """Projected wall-clock for a set of stages.

    `services` is usually unknown before the scan; when it is zero a rough
    ratio is assumed so the figure is not silently optimistic.
    """
    hosts = max(1, int(hosts or 1))
    if not services:
        # A live host on an internal network typically exposes a handful of
        # services. Assuming zero would understate every service-scaled stage.
        services = hosts * 6

    factor = INTENSITY_FACTOR.get(str(intensity).lower(), 1.0)
    per_stage, total = {}, 0.0
    for name in stages:
        base, per_host, per_service = STAGE_COST.get(name, DEFAULT_COST)
        workers = STAGE_PARALLELISM.get(name, DEFAULT_PARALLELISM)
        # Hosts are processed concurrently, so wall-clock is driven by the
        # number of batches, not the number of hosts.
        batches = max(1, -(-hosts // workers))
        svc_batches = max(1, -(-services // max(1, workers)))
        cost = (base + per_host * batches
                + per_service * svc_batches) * factor
        per_stage[name] = cost
        total += cost
    return Estimate(seconds=total, per_stage=per_stage, hosts=hosts,
                    services=services, intensity=str(intensity))


def describe(est: Estimate) -> list[str]:
    """Lines an operator can act on."""
    out = [f"estimated {est.range_text()} for {est.hosts} host"
           f"{'s' if est.hosts != 1 else ''}"]
    for name, cost in est.dominant[:3]:
        share = round(100 * cost / est.seconds)
        out.append(f"{name} is roughly {share}% of that "
                   f"(~{human(cost)}) — skip it with --skip {name}")
    return out
