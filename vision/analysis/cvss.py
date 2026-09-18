"""CVSS v3.1 base-score vectors.

Vision recorded severity as a bare word — "critical", "high" — and a client
reviewer had no way to see *why* a thing was critical, or to compare two criticals.
"critical" is a bucket; `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) is an
argument. This module turns a vector string into a validated, scored object so the
report can show the vector beside the word, and so a vector entered by hand or
arriving from enrichment is *checked* rather than trusted.

Scope is deliberately narrow: **base metrics only**, CVSS v3.1 (and v3.0, whose
base equations are identical). Temporal and environmental metrics are a separate
judgement an operator makes with the engagement in front of them — the same line
this tool draws everywhere else — and are out of scope here. The arithmetic is the
official specification (FIRST CVSS v3.1, section 7.1), implemented in pure stdlib.

No network, no dependencies. A vector this module cannot fully validate is
rejected with a reason, never silently coerced to a plausible-looking score — a
wrong CVSS number in a client report is worse than none.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional

# Metric weights, straight from the v3.1 specification. The Scope-dependent
# metrics (PR) are two-valued: the weight depends on whether Scope is Changed.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

# The eight mandatory base metrics, each with its allowed values. Order is the
# canonical order the spec prints them in, so a rebuilt vector round-trips.
_BASE_METRICS = [
    ("AV", set(_AV)),
    ("AC", set(_AC)),
    ("PR", {"N", "L", "H"}),
    ("UI", set(_UI)),
    ("S", {"U", "C"}),
    ("C", set(_CIA)),
    ("I", set(_CIA)),
    ("A", set(_CIA)),
]
_METRIC_ORDER = [m for m, _ in _BASE_METRICS]

_SEVERITY_BANDS = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "none"),
]


class CvssError(ValueError):
    """A vector string that is not a valid CVSS v3.1 base vector."""


def _roundup(x: float) -> float:
    """The specification's Roundup: round to one decimal, always up.

    Defined against integer hundredths to avoid binary-float drift — the naive
    `math.ceil(x * 10) / 10` misfires on values like 0.7000000000000001 that a
    plain multiply produces, scoring a 4.3 as 4.4.
    """
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000.0) + 1) / 10.0


def severity_for(score: float) -> str:
    """The qualitative band a base score falls in (v3.1 section 5)."""
    for threshold, label in _SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "none"


@dataclass(frozen=True)
class Cvss:
    """A parsed, scored CVSS v3.1 base vector."""
    metrics: dict           # canonical metric -> value, e.g. {"AV": "N", ...}
    base_score: float
    version: str = "3.1"

    @property
    def severity(self) -> str:
        return severity_for(self.base_score)

    @property
    def vector(self) -> str:
        """The canonical vector string, metrics in specification order."""
        body = "/".join(f"{m}:{self.metrics[m]}" for m in _METRIC_ORDER)
        return f"CVSS:{self.version}/{body}"

    def __str__(self) -> str:
        return f"{self.vector} ({self.base_score} {self.severity})"


def _score(metrics: dict) -> float:
    """Base score from validated metrics — the v3.1 equations verbatim."""
    scope_changed = metrics["S"] == "C"
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED

    iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * \
        (1 - _CIA[metrics["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * \
        pr_table[metrics["PR"]] * _UI[metrics["UI"]]

    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))


def parse(vector: str) -> Cvss:
    """Parse and score a CVSS v3.0/3.1 base vector string.

    Raises CvssError with a specific reason on anything that is not a complete,
    valid base vector — an unknown metric, a bad value, a missing mandatory
    metric, a duplicate, or a wrong prefix. Nothing is guessed or defaulted.
    """
    if not vector or not isinstance(vector, str):
        raise CvssError("empty CVSS vector")
    text = vector.strip()

    parts = text.split("/")
    head = parts[0].upper()
    if head in ("CVSS:3.1", "CVSS:3.0"):
        version = head.split(":", 1)[1]
        body = parts[1:]
    else:
        # Some sources emit the bare metric body with no CVSS:3.1 prefix.
        # Accept it, but score it as 3.1 (identical base equations) and say so
        # by materialising the prefix in the canonical output.
        version = "3.1"
        body = parts
        if not body or ":" not in body[0]:
            raise CvssError(f"not a CVSS vector: {vector!r}")

    seen: dict = {}
    allowed = dict(_BASE_METRICS)
    for token in body:
        if not token:
            continue
        if ":" not in token:
            raise CvssError(f"malformed metric {token!r} in {vector!r}")
        key, _, val = token.partition(":")
        key, val = key.upper().strip(), val.upper().strip()
        if key not in allowed:
            # Temporal/environmental metrics (E, RL, RC, CR, MAV, ...) are not
            # base metrics; naming one is a scope error, not a typo to absorb.
            raise CvssError(f"unknown or non-base metric {key!r} in {vector!r}")
        if key in seen:
            raise CvssError(f"duplicate metric {key!r} in {vector!r}")
        if val not in allowed[key]:
            raise CvssError(
                f"invalid value {val!r} for {key!r} in {vector!r} — "
                f"expected one of {sorted(allowed[key])}")
        seen[key] = val

    missing = [m for m in _METRIC_ORDER if m not in seen]
    if missing:
        raise CvssError(
            f"incomplete base vector {vector!r} — missing {', '.join(missing)}")

    return Cvss(metrics=seen, base_score=_score(seen), version=version)


def try_parse(vector: Optional[str]) -> Optional[Cvss]:
    """Parse if possible, else None. For callers enriching best-effort data
    where a missing or malformed vector should be dropped, not fatal."""
    if not vector:
        return None
    try:
        return parse(vector)
    except CvssError:
        return None
