"""Manual findings.

The playbook tells an analyst what to run by hand. Without this, whatever they
find there has nowhere to go, and the report ends up containing only what the
automation happened to catch — which understates the engagement and leaves the
analyst maintaining a second list somewhere else.

Two design decisions worth stating.

**Manual findings are marked as manual, permanently.** A reviewer needs to know
which findings came from a tool and which came from a person, because the
follow-up questions are different: for a tool finding you ask about false
positives, for a manual one you ask how it was verified. Hiding the difference
would make the report harder to check, not easier.

**Scope is enforced here too.** A finding typed by hand is still a claim about a
host, and an engagement boundary that applies to the scanner but not to the
keyboard is not a boundary. The same rule everywhere is the only version anyone
can rely on.
"""

from __future__ import annotations

import time
from typing import Optional

from .safety import safe_display

SEVERITIES = ["critical", "high", "medium", "low", "info"]
CONFIDENCES = ["confirmed", "firm", "tentative"]

CONFIDENCE_HELP = {
    "confirmed": "you verified it yourself — exploited, read the data, saw the shell",
    "firm": "a tool or check confirmed it, but you did not prove impact",
    "tentative": "inferred from a version or banner; still needs verification",
}

MAX_TITLE = 120
MAX_TEXT = 4000


class InvalidFinding(ValueError):
    """The finding as entered cannot be recorded. Always says why."""


def build(ip: str, title: str, severity: str, *,
          port: Optional[int] = None,
          confidence: str = "confirmed",
          evidence: str = "",
          remediation: str = "",
          description: str = "",
          cves: Optional[list] = None,
          operator: str = "",
          scope=None) -> dict:
    """Validate and construct a manual finding.

    Raises InvalidFinding with a readable reason rather than silently
    recording something that will look wrong in the report six weeks later.
    """
    ip = (ip or "").strip()
    if not ip:
        raise InvalidFinding("a target address is required")
    if scope is not None and not scope.contains(ip):
        raise InvalidFinding(
            f"{ip} is outside the engagement scope — findings, typed or "
            "scanned, stay inside the boundary")

    title = safe_display(title, MAX_TITLE).strip()
    if len(title) < 5:
        raise InvalidFinding("give the finding a title of at least 5 characters")

    severity = (severity or "").strip().lower()
    if severity not in SEVERITIES:
        raise InvalidFinding(f"severity must be one of {', '.join(SEVERITIES)}")

    confidence = (confidence or "confirmed").strip().lower()
    if confidence not in CONFIDENCES:
        raise InvalidFinding(f"confidence must be one of {', '.join(CONFIDENCES)}")

    if port is not None:
        try:
            port = int(port)
        except (TypeError, ValueError):
            raise InvalidFinding("port must be a number") from None
        if not 0 < port < 65536:
            raise InvalidFinding("port must be between 1 and 65535")

    # A finding a client cannot act on is half a finding. This is a nudge in
    # the console rather than a hard rule, because sometimes the fix genuinely
    # is "investigate further".
    cleaned_cves = []
    for c in (cves or []):
        c = str(c).strip().upper()
        if c:
            if not c.startswith("CVE-"):
                raise InvalidFinding(f"{c!r} is not a CVE identifier")
            cleaned_cves.append(c)

    return {
        "ip": ip,
        "port": port,
        "proto": "tcp",
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "description": safe_display(description, MAX_TEXT),
        "evidence": safe_display(evidence, MAX_TEXT),
        "remediation": safe_display(remediation, MAX_TEXT),
        "cves": sorted(set(cleaned_cves)),
        # Namespaced so it is unmistakable in the report, the export and the
        # findings table. A reviewer must be able to tell tool output from
        # analyst judgement at a glance.
        "source": f"manual:{safe_display(operator, 40) or 'analyst'}",
        "manual": True,
        "recorded_at": time.time(),
    }


def is_manual(finding: dict) -> bool:
    return bool(finding.get("manual")) or \
        str(finding.get("source", "")).startswith("manual:")


def author(finding: dict) -> str:
    src = str(finding.get("source", ""))
    return src.split(":", 1)[1] if src.startswith("manual:") else ""
