"""Engagement metadata and the executive summary.

A findings list is not a deliverable. A client receives a document, and the
first page of that document is read by someone who will never look at the
second — a manager deciding whether to fund remediation. Without a client name,
dates, an authorisation reference and a plainly written summary, the HTML is a
scan dump with good typography.

**On the generated summary.** Vision drafts it from what it actually found:
counts, the worst issues, whether attack paths chain, how much of the toolchain
ran. It is deliberately factual and slightly dry, and it is labelled as a draft,
because an auto-written risk narrative that reads as polished prose invites
someone to ship it unread. The analyst is expected to replace it — there is a
field for exactly that, and when it is set the draft disappears entirely.

**Coverage is stated, not implied.** If half the toolchain was missing the
summary says so. A summary that reports four findings without mentioning that
eleven stages never ran is technically true and materially misleading.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, asdict
from typing import Optional

from .safety import safe_display

MAX_FIELD = 200
MAX_NARRATIVE = 8000

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@dataclass
class Engagement:
    """Who this assessment is for, and under what authority."""
    client: str = ""
    name: str = "Network vulnerability assessment"
    tester: str = ""
    reference: str = ""             # authorisation / statement of work
    started: str = ""
    finished: str = ""
    contact: str = ""               # who to call if something falls over
    # Analyst's own summary. When set, it replaces the generated draft.
    executive_summary: str = ""
    notes: str = ""

    def as_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict | None) -> "Engagement":
        d = d or {}
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: safe_display(v, MAX_NARRATIVE if k in
                                      ("executive_summary", "notes") else MAX_FIELD)
                      for k, v in d.items() if k in known and v is not None})

    @property
    def is_configured(self) -> bool:
        return bool(self.client or self.tester or self.reference)

    @property
    def dates(self) -> str:
        if self.started and self.finished:
            return (f"{self.started} – {self.finished}"
                    if self.started != self.finished else self.started)
        return self.started or self.finished or ""

    def stamp_start(self) -> None:
        if not self.started:
            self.started = time.strftime("%d %B %Y")

    def stamp_finish(self) -> None:
        self.finished = time.strftime("%d %B %Y")


def counts(findings: list[dict]) -> dict:
    out = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in out:
            out[sev] += 1
    return out


def coverage(stages: list[dict]) -> tuple[int, int, list[str]]:
    """(ran, skipped, reasons) — what the assessment actually covered."""
    ran = [s for s in stages if not s.get("skipped")]
    skipped = [s for s in stages if s.get("skipped")]
    missing_tools = sorted({
        str(s.get("reason", "")).replace(" not installed", "")
        for s in skipped if "not installed" in str(s.get("reason", ""))
    })
    return len(ran), len(skipped), missing_tools


def draft_summary(findings: list[dict], services: list[dict],
                  hosts: int, stages: list[dict] | None = None,
                  paths: int = 0) -> str:
    """A factual first draft of the executive summary.

    Written for someone who will not read the findings table: what was looked
    at, what the worst of it is, and what it means in one paragraph. Numbers
    only — no adjectives Vision cannot justify from the data.
    """
    c = counts(findings)
    total = sum(c.values())
    urgent = c["critical"] + c["high"]
    ran, skipped, missing = coverage(stages or [])

    para = []

    scope_line = (f"The assessment examined {hosts} live host"
                  f"{'s' if hosts != 1 else ''} and identified "
                  f"{len(services)} network service"
                  f"{'s' if len(services) != 1 else ''}.")
    if ran:
        scope_line += f" {ran} assessment stage{'s' if ran != 1 else ''} ran."
    para.append(scope_line)

    if total == 0:
        para.append("No issues were identified in the areas covered. This is "
                    "not the same as a clean network — see the coverage note "
                    "below for what was and was not examined.")
    elif urgent == 0:
        para.append(
            f"{total} finding{'s' if total != 1 else ''} were recorded, none "
            "rated high or critical. The issues identified are hardening "
            "opportunities rather than immediate exposures.")
    else:
        worst = next((s for s in SEVERITY_ORDER if c[s]), "info")
        para.append(
            f"{total} finding{'s' if total != 1 else ''} were recorded, of "
            f"which {urgent} {'are' if urgent != 1 else 'is'} rated high or "
            f"critical. The most severe {'issues are' if c[worst] != 1 else 'issue is'} "
            f"rated {worst}.")

    # Name the actual worst findings — a manager remembers "unauthenticated
    # database" and forgets "four critical findings".
    top = [f for f in findings if f.get("severity") == "critical"][:3]
    if not top:
        top = [f for f in findings if f.get("severity") == "high"][:3]
    if top:
        titles = "; ".join(safe_display(f.get("title", ""), 90) for f in top)
        para.append(f"Principal issues: {titles}.")

    if paths:
        # `paths` counts chains, not findings. Saying "N findings combine"
        # would overstate how much of the report is chained.
        para.append(
            f"These findings combine into {paths} attack path"
            f"{'s' if paths != 1 else ''} — sequence"
            f"{'s' if paths != 1 else ''} where one issue enables the next. "
            "Breaking any single step breaks the chain, so these are often the "
            "most efficient remediation to prioritise.")

    if missing:
        # "1 stage did not run, 1 of them because…" reads as though a machine
        # wrote it, which in a client-facing summary undermines the rest.
        tools = ", ".join(missing[:6])
        if len(missing) >= skipped:
            note = (f"Coverage note: {skipped} stage"
                    f"{'s' if skipped != 1 else ''} did not run because the "
                    f"required tooling was unavailable ({tools}).")
        else:
            note = (f"Coverage note: {skipped} stages did not run, "
                    f"{len(missing)} of them because the required tooling was "
                    f"unavailable ({tools}).")
        para.append(note + " A finding count is only meaningful alongside what "
                    "was examined to produce it.")
    elif skipped:
        para.append(
            f"Coverage note: {skipped} stage{'s' if skipped != 1 else ''} did "
            "not run, in each case because the relevant services were not "
            "present on the assessed hosts.")

    return "\n\n".join(para)


def summary_is_draft(engagement: Optional[Engagement]) -> bool:
    return not (engagement and engagement.executive_summary.strip())


def resolve_summary(engagement: Optional[Engagement], findings: list[dict],
                    services: list[dict], hosts: int,
                    stages: list[dict] | None = None,
                    paths: int = 0) -> tuple[str, bool]:
    """(text, is_draft). The analyst's own summary always wins."""
    if engagement and engagement.executive_summary.strip():
        return engagement.executive_summary.strip(), False
    return draft_summary(findings, services, hosts, stages, paths), True
