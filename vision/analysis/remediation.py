"""Remediation planning.

A findings list is ordered for the assessor. A remediation plan is ordered for
whoever has to fix it, and those are different orderings.

The useful unit of work is the *action*, not the finding. "Enforce SMB signing"
is one change that closes seven findings across three hosts; listing it seven
times sorted by severity makes it look like seven jobs and hides that the
highest-severity item might be a single unpatched host nobody can reach anyway.
Grouping by action turns a report into a work plan.

Ranking is by worst severity first, then by how much the action closes.

Pure summed weight was tempting — it would let a change clearing nine mediums
across twelve hosts outrank one clearing a single high, which is arguably the
better use of a maintenance window. It was also wrong: it put three Telnet
findings above an unauthenticated Redis instance, and no assessor would hand a
client a plan that ranks a critical below a set of highs. An unauthenticated
remote-code-execution path is an active breach, not a scheduling problem.

Severity therefore dominates, and breadth orders within a tier. The "one change
fixes twelve hosts" view is still available, as `quick_wins`, where it can be
read as what it is rather than smuggled into the priority order.

Effort is not estimated. A tool cannot know whether a host is a spare VM or a
production controller with a six-week change process, and a made-up estimate
would be treated as real and then be wrong.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Text that varies per host but describes the same change, so it does not
# prevent two findings from grouping together.
_VARIABLE = re.compile(
    r"\b(\d{1,3}(?:\.\d{1,3}){3})\b"           # addresses
    r"|:\d{1,5}\b"                              # ports
    r"|\b\d+(?:\.\d+)+\b"                       # version numbers
    r"|'[^']{0,40}'", re.I)                     # quoted specifics

_NORMALISE = re.compile(r"[^a-z0-9 ]+")


def _action_key(text: str) -> str:
    """Collapse a remediation string to the change it describes.

    'Upgrade MySQL past 5.5.28' and 'Upgrade MySQL past 5.7.33' are the same
    action on two hosts; 'Disable Telnet' is a different one.
    """
    text = _VARIABLE.sub(" ", (text or "").lower())
    text = _NORMALISE.sub(" ", text)
    return " ".join(text.split())[:120]


@dataclass
class Action:
    """One remediation step and everything it closes."""
    text: str
    findings: list[dict] = field(default_factory=list)

    @property
    def hosts(self) -> list[str]:
        return sorted({f.get("ip") for f in self.findings if f.get("ip")})

    @property
    def severity(self) -> str:
        """The worst thing this action closes."""
        for sev in SEVERITY_ORDER:
            if any(f.get("severity") == sev for f in self.findings):
                return sev
        return "info"

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            sev = f.get("severity", "info")
            out[sev] = out.get(sev, 0) + 1
        return out

    @property
    def score(self) -> int:
        """Total severity weight closed. Orders actions *within* a severity
        tier — it never lifts one above a tier containing something worse."""
        return sum(SEVERITY_WEIGHT.get(f.get("severity", "info"), 0)
                   for f in self.findings)

    @property
    def cves(self) -> list[str]:
        return sorted({c for f in self.findings for c in (f.get("cves") or [])})

    @property
    def confidence(self) -> str:
        """Weakest confidence among the findings this closes — an action
        justified only by tentative findings should be verified before a change
        window is spent on it."""
        rank = {"tentative": 0, "firm": 1, "confirmed": 2}
        worst = min((rank.get(f.get("confidence", "tentative"), 0)
                     for f in self.findings), default=0)
        return ["tentative", "firm", "confirmed"][worst]

    def summary(self) -> str:
        bits = [f"{n} {sev}" for sev, n in
                sorted(self.counts.items(),
                       key=lambda kv: SEVERITY_ORDER.index(kv[0]))]
        return (f"{', '.join(bits)} across {len(self.hosts)} host"
                f"{'s' if len(self.hosts) != 1 else ''}")


def plan(findings: Iterable[dict], include_info: bool = False) -> list[Action]:
    """Group findings into remediation actions, highest impact first."""
    grouped: dict[str, Action] = {}
    unactionable: list[dict] = []

    for f in findings:
        if not isinstance(f, dict):
            continue
        if not include_info and f.get("severity") == "info":
            continue
        text = (f.get("remediation") or "").strip()
        if not text:
            unactionable.append(f)
            continue
        key = _action_key(text)
        if not key:
            unactionable.append(f)
            continue
        action = grouped.get(key)
        if action is None:
            grouped[key] = Action(text=text, findings=[f])
        else:
            action.findings.append(f)
            # Keep the shortest wording: per-host detail lives in the finding,
            # and the action should read as one instruction.
            if len(text) < len(action.text):
                action.text = text

    actions = sorted(
        grouped.values(),
        key=lambda a: (SEVERITY_ORDER.index(a.severity), -a.score,
                       -len(a.hosts), a.text))
    if unactionable:
        actions.append(Action(
            text="Review manually — no remediation was recorded for these.",
            findings=unactionable))
    return actions


def summary(actions: list[Action]) -> dict:
    return {
        "actions": len(actions),
        "findings_covered": sum(len(a.findings) for a in actions),
        "hosts": len({h for a in actions for h in a.hosts}),
        "top_score": actions[0].score if actions else 0,
    }


def quick_wins(actions: list[Action], limit: int = 3) -> list[Action]:
    """Actions that close findings on the most hosts at once.

    Distinct from the top of the plan, which is ranked by severity weight: a
    single change that fixes twelve hosts is often the first thing worth doing
    even when something scarier affects one.
    """
    return sorted([a for a in actions if len(a.hosts) > 1],
                  key=lambda a: (-len(a.hosts), -a.score))[:limit]
