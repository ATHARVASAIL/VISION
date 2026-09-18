"""Scan comparison for retests.

The question a client asks after remediation is not "what did you find" but
"what did we actually fix". Answering that by hand across two JSON files is
tedious and error-prone, and the errors matter: telling a client an issue is
resolved when it moved to another port is worse than not checking.

Matching uses the same fingerprint the deduplication logic uses — host, port,
and CVE (or normalised title where there is no CVE) — so a finding that keeps
its identity across scans is recognised even if its wording, severity or
evidence changed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Iterable

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def fingerprint(f: dict) -> str:
    """Stable identity for a finding across scans.

    Deliberately excludes severity, confidence and evidence: those are
    properties that legitimately change between scans, and including them
    would report every re-rated finding as "fixed plus new".
    """
    cves = ",".join(sorted(c.upper() for c in (f.get("cves") or []) if c))
    basis = "|".join([
        str(f.get("ip") or ""),
        str(f.get("port") or ""),
        cves or (f.get("title") or "").lower().strip(),
    ])
    return hashlib.sha256(basis.encode()).hexdigest()[:16]


@dataclass
class Delta:
    resolved: list[dict] = field(default_factory=list)
    new: list[dict] = field(default_factory=list)
    unchanged: list[dict] = field(default_factory=list)
    worsened: list[tuple[dict, dict]] = field(default_factory=list)
    improved: list[tuple[dict, dict]] = field(default_factory=list)
    hosts_added: list[str] = field(default_factory=list)
    hosts_removed: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict:
        return {
            "resolved": len(self.resolved),
            "new": len(self.new),
            "unchanged": len(self.unchanged),
            "worsened": len(self.worsened),
            "improved": len(self.improved),
        }

    def remediation_rate(self) -> float:
        """Share of the original findings that are gone. The headline number a
        client wants, and the one worth being careful about — see
        `regressions` for the caveat that belongs alongside it."""
        baseline = len(self.resolved) + len(self.unchanged) + \
            len(self.worsened) + len(self.improved)
        return (len(self.resolved) / baseline * 100) if baseline else 0.0

    @property
    def regressions(self) -> list[dict]:
        """New findings that are high or critical.

        A high remediation rate means little if the retest surfaced fresh
        critical issues, so these are reported next to the percentage rather
        than buried in the new-findings list.
        """
        return [f for f in self.new
                if SEVERITY_RANK.get(f.get("severity", "info"), 0) >= 3]


def compare(baseline: Iterable[dict], current: Iterable[dict],
            baseline_hosts: Iterable[str] = (),
            current_hosts: Iterable[str] = ()) -> Delta:
    base = {fingerprint(f): f for f in baseline if isinstance(f, dict)}
    curr = {fingerprint(f): f for f in current if isinstance(f, dict)}

    delta = Delta()
    for fp, old in base.items():
        new = curr.get(fp)
        if new is None:
            delta.resolved.append(old)
            continue
        old_rank = SEVERITY_RANK.get(old.get("severity", "info"), 0)
        new_rank = SEVERITY_RANK.get(new.get("severity", "info"), 0)
        if new_rank > old_rank:
            delta.worsened.append((old, new))
        elif new_rank < old_rank:
            delta.improved.append((old, new))
        else:
            delta.unchanged.append(new)

    for fp, new in curr.items():
        if fp not in base:
            delta.new.append(new)

    b_hosts, c_hosts = set(baseline_hosts), set(current_hosts)
    delta.hosts_added = sorted(c_hosts - b_hosts)
    delta.hosts_removed = sorted(b_hosts - c_hosts)

    for bucket in (delta.resolved, delta.new, delta.unchanged):
        bucket.sort(key=lambda f: (-SEVERITY_RANK.get(f.get("severity", "info"), 0),
                                   f.get("ip", "")))
    return delta
