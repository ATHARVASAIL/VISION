"""Finding triage.

A scanner that cannot record "this is a false positive" forces the analyst to
keep the real assessment in a separate spreadsheet, and the report then
disagrees with the spreadsheet. Triage keeps the judgement attached to the
finding.

Four states, chosen to match what actually gets written in a report:

  new              not yet reviewed — the default
  confirmed        reviewed and real; goes in the report as-is
  false-positive   reviewed and wrong; excluded from the findings list and
                   disclosed in an appendix with the reason
  accepted-risk    real, but the client has accepted it; reported separately so
                   it does not read as an outstanding issue

False positives are *disclosed*, never silently dropped. A report that quietly
omits findings is indistinguishable from a scan that missed them, and the
reviewer has no way to check the analyst's reasoning. The appendix costs half a
page and makes the judgement auditable.

Triage is keyed on the finding fingerprint, so a decision survives a rescan: an
issue marked false-positive on Monday is still marked on Friday, even though the
scan that produced it ran again.
"""

from __future__ import annotations

import getpass
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .safety import safe_display

NEW = "new"
CONFIRMED = "confirmed"
FALSE_POSITIVE = "false-positive"
ACCEPTED_RISK = "accepted-risk"

STATES = {
    NEW: "not yet reviewed",
    CONFIRMED: "reviewed and real",
    FALSE_POSITIVE: "not a real issue — excluded, with the reason recorded",
    ACCEPTED_RISK: "real, but accepted by the client",
}

# States that keep a finding in the main body of the report.
REPORTABLE = {NEW, CONFIRMED}


@dataclass
class Decision:
    status: str
    note: str = ""
    by: str = ""
    at: float = field(default_factory=time.time)

    def as_dict(self) -> dict:
        return {"status": self.status, "note": self.note,
                "by": self.by, "at": self.at}

    @classmethod
    def from_dict(cls, d: dict) -> "Decision":
        return cls(status=str(d.get("status", NEW)),
                   note=str(d.get("note", "")),
                   by=str(d.get("by", "")),
                   at=float(d.get("at", 0) or 0))


class Triage:
    """Analyst decisions, keyed on finding fingerprint."""

    def __init__(self, data: dict | None = None, operator: str = ""):
        self.operator = operator or _who()
        self._by_fp: dict[str, Decision] = {}
        for fp, d in (data or {}).items():
            if isinstance(d, dict):
                self._by_fp[str(fp)] = Decision.from_dict(d)

    # ---------------------------------------------------------------- keys

    @staticmethod
    def key(finding: dict) -> str:
        """Same identity the retest diff uses, so a decision survives a rescan
        and can be carried between a baseline and its retest."""
        from ..analysis.diff import fingerprint
        return fingerprint(finding)

    # ---------------------------------------------------------------- state

    def status(self, finding: dict) -> str:
        d = self._by_fp.get(self.key(finding))
        return d.status if d else NEW

    def decision(self, finding: dict) -> Optional[Decision]:
        return self._by_fp.get(self.key(finding))

    def set(self, finding: dict, status: str, note: str = "") -> Decision:
        if status not in STATES:
            raise ValueError(f"unknown triage status: {status!r}")
        if status in (FALSE_POSITIVE, ACCEPTED_RISK) and not note.strip():
            # An unexplained exclusion is exactly what a reviewer will question,
            # and the analyst will not remember the reason six weeks later.
            raise ValueError(f"{status} requires a reason")
        d = Decision(status=status, note=safe_display(note, 400),
                     by=self.operator)
        self._by_fp[self.key(finding)] = d
        return d

    def clear(self, finding: dict) -> None:
        self._by_fp.pop(self.key(finding), None)

    # ---------------------------------------------------------------- views

    def reportable(self, findings: Iterable[dict]) -> list[dict]:
        """Findings that belong in the main body of the report."""
        return [f for f in findings if self.status(f) in REPORTABLE]

    def excluded(self, findings: Iterable[dict]) -> list[tuple[dict, Decision]]:
        """Findings held back, with the decision that held them back — this is
        what the report's appendix is built from."""
        out = []
        for f in findings:
            d = self._by_fp.get(self.key(f))
            if d and d.status not in REPORTABLE:
                out.append((f, d))
        return out

    def counts(self, findings: Iterable[dict]) -> dict[str, int]:
        out = {k: 0 for k in STATES}
        for f in findings:
            out[self.status(f)] = out.get(self.status(f), 0) + 1
        return out

    def annotate(self, findings: Iterable[dict]) -> list[dict]:
        """Attach the decision to each finding so exports carry it."""
        out = []
        for f in findings:
            f = dict(f)
            d = self._by_fp.get(self.key(f))
            f["triage"] = d.as_dict() if d else {"status": NEW}
            out.append(f)
        return out

    # ---------------------------------------------------------------- io

    def as_dict(self) -> dict:
        return {fp: d.as_dict() for fp, d in self._by_fp.items()}

    def __len__(self) -> int:
        return len(self._by_fp)


def _who() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "operator"
