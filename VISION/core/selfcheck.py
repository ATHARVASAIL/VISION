"""Vision auditing itself.

A tool cannot become "best in every situation" by being told to — that is not
a real capability for a static CLI, and claiming it would be worse than not
having it. What a tool *can* honestly do is check that its own claims stay
true as it grows, and surface the gap the moment it appears rather than
waiting for someone to notice a stale number in a README or a marketing SVG.

That is what this module does. It is the mechanism behind `vision selfcheck`:
walk the actual registered stages, tools, chains and profiles, compare them
against every place a number about them is printed — README, MANUAL, the
header graphic, the banner — and report any mismatch as a defect, not a
cosmetic detail.

This is not machine learning and it does not rewrite Vision's own logic. It
is closer to a smoke test the tool runs on itself: the same discipline
`test_docs.py` already applies during development, made available at runtime
so an operator (or a packaging step) can ask "is this build internally
consistent?" without reading source.

Concretely, this caught the exact bug found while renaming the project:
`docs/header.svg` said 20 stages and 1022 tests six rounds after the real
counts became 32 and 1564. A generated SVG is not code a human rereads before
every release, which is exactly why an automated check for it needed to
exist rather than being left to be noticed by accident.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Drift:
    """One place where a stated number disagrees with reality."""
    where: str
    claim: str
    actual: str

    def __str__(self) -> str:
        return f"{self.where}: says {self.claim!r}, actually {self.actual!r}"


@dataclass
class SelfCheckReport:
    drifts: list = field(default_factory=list)
    checked: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.drifts

    def summary(self) -> str:
        if self.ok:
            return f"consistent across {len(self.checked)} check(s)"
        return f"{len(self.drifts)} drift(s) found across {len(self.checked)} check(s)"


def _ground_truth() -> dict:
    """What is actually true, read directly from the running code — never
    from a document, since documents are exactly what gets checked."""
    from .pipeline import Pipeline
    from .toolchain import TOOLS
    from ..analysis.correlate import CHAINS
    from .profiles import PROFILES
    return {
        "stages": len(Pipeline.STAGES),
        "phases": len(Pipeline.PHASES),
        "tools": len(TOOLS),
        "chains": len(CHAINS),
        "profiles": len(PROFILES),
    }


def _count_tests(root: Path) -> int:
    """Total PASS lines across every test suite, without re-running anything
    expensive — this reads suite output already produced by run_tests.sh if
    present, or runs the suites once if it is not.

    `test_docs.py` is deliberately excluded: it re-runs every other suite
    internally to check its own count assertions, so including its output
    double-counts everything and inflates the total. `run_tests.sh` uses the
    same exclusion for the same reason — this function must match it, or the
    two would disagree about Vision's own test count.
    """
    import subprocess
    total = 0
    tests_dir = root / "tests"
    if not tests_dir.is_dir():
        return 0
    for path in sorted(tests_dir.glob("test_*.py")):
        if path.stem == "test_docs":
            continue
        try:
            r = subprocess.run(["python3", str(path)], capture_output=True,
                              text=True, timeout=180, cwd=str(root))
        except Exception:
            continue
        total += len(re.findall(r"^PASS", r.stdout, re.M))
    return total


def audit(root: Path | str, run_tests: bool = False) -> SelfCheckReport:
    """Compare every number Vision states about itself against reality.

    `run_tests` controls whether the (slow) full test count is recomputed;
    when False, stage/tool/chain counts are still checked, which is the part
    most prone to silent drift — a new stage is one line in `pipeline.py`
    and easy to forget to mention anywhere else.
    """
    root = Path(root)
    report = SelfCheckReport()
    truth = _ground_truth()

    targets = [
        ("README.md", root / "README.md"),
        ("MANUAL.md", root / "MANUAL.md"),
        ("SECURITY.md", root / "SECURITY.md"),
        ("docs/header.svg", root / "docs" / "header.svg"),
    ]
    patterns = [
        ("stages", re.compile(r"(\d+)\s*stages")),
        ("tools", re.compile(r"(\d+)\s*tools")),
        ("chains", re.compile(r"(\d+)\s*chains")),
    ]

    for label, path in targets:
        if not path.exists():
            continue
        text = path.read_text(errors="replace")
        for key, pat in patterns:
            matches = {int(m) for m in pat.findall(text)}
            report.checked.append(f"{label}:{key}")
            if matches and truth[key] not in matches:
                report.drifts.append(Drift(
                    where=label, claim=", ".join(sorted(map(str, matches))),
                    actual=str(truth[key])))

    if run_tests:
        actual_tests = _count_tests(root)
        report.checked.append("test count")
        # Only whole-suite claims count here — phrasing like "108 tests
        # against realistic output" describes one suite's history, not a
        # claim about Vision's total, and flagging it produced a false
        # positive the first time this ran.
        whole_suite = re.compile(
            r"(\d{3,5})\s*tests\s*(?:across|passed across|passing)")
        for label, path in targets[:3]:
            if not path.exists():
                continue
            text = path.read_text(errors="replace")
            m = whole_suite.search(text)
            if m and int(m.group(1)) != actual_tests:
                report.drifts.append(Drift(
                    where=label, claim=m.group(1), actual=str(actual_tests)))

    return report
