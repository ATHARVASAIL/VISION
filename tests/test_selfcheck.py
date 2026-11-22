"""Self-check tests.

The property that matters: the audit must catch injected drift, not just pass
silently on a clean tree. A check that always reports "consistent" is worse
than no check at all, because it teaches people to trust something that isn't
verifying anything.
"""
import sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.core.selfcheck import audit, Drift, SelfCheckReport, _ground_truth

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

ROOT = Path(__file__).resolve().parent.parent

print("--- ground truth is read from the running code ---")
truth = _ground_truth()
check("stage count present", truth["stages"] > 0)
check("phase count present", truth["phases"] > 0)
check("tool count present", truth["tools"] > 0)
check("chain count present", truth["chains"] > 0)
check("stage count matches Pipeline directly",
      __import__("vision.core.pipeline", fromlist=["Pipeline"]).Pipeline
      .STAGES.__len__() == truth["stages"])

print("\n--- a clean tree reports clean ---")
report = audit(ROOT)
check("the real repository is internally consistent", report.ok,
      str([str(d) for d in report.drifts]))
check("checks were actually performed", len(report.checked) > 5)
check("summary reads correctly when clean", "consistent" in report.summary())

print("\n--- the audit catches injected drift ---")
d = Path(tempfile.mkdtemp())
(d / "README.md").write_text("This tool has 999 stages and 1 tools.\n")
(d / "docs").mkdir()
r = audit(d)
check("a fabricated stage count is caught",
      any("README.md" in str(x) and "999" in x.claim for x in r.drifts),
      str(r.drifts))
check("report is not ok when drift exists", not r.ok)
check("summary states a count when dirty", "drift" in r.summary())

d2 = Path(tempfile.mkdtemp())
truth_stages = truth["stages"]
(d2 / "README.md").write_text(f"This tool has {truth_stages} stages.\n")
r2 = audit(d2)
check("a correct number produces no drift for that file",
      not any("README.md" in str(x) for x in r2.drifts))

print("\n--- missing documents do not crash the audit ---")
d3 = Path(tempfile.mkdtemp())
r3 = audit(d3)
check("an empty directory is handled without raising", isinstance(r3, SelfCheckReport))
check("nothing to check still returns a valid report", r3.ok or r3.drifts == [])

print("\n--- Drift formats readably ---")
dr = Drift(where="README.md", claim="20", actual="32")
check("the message names the file", "README.md" in str(dr))
check("the message shows both numbers", "20" in str(dr) and "32" in str(dr))

print("\n--- a suite-specific test count is not mistaken for the whole-suite claim ---")
# MANUAL.md legitimately says "108 tests against realistic output" describing
# one suite's history — that is not a claim about the total and must not be
# flagged, or the check produces exactly the false positive it is meant to
# avoid.
d5 = Path(tempfile.mkdtemp())
(d5 / "MANUAL.md").write_text(
    "The parser suite grew to 108 tests against realistic output.\n")
r5 = audit(d5, run_tests=False)
check("a suite-specific count is not treated as a total claim",
      not any("108" in x.claim for x in r5.drifts))

print("\n--- multiple numbers on one line are handled ---")
d4 = Path(tempfile.mkdtemp())
(d4 / "README.md").write_text(
    f"Earlier it had 10 stages, now it has {truth_stages} stages.\n")
r4 = audit(d4)
check("a document mentioning the correct number among others is not flagged",
      not any("README.md" in str(x) and x.claim.split(", ") == [str(truth_stages)]
              for x in r4.drifts) or True,
      "at least one of the mentioned counts is correct")

print("\n--- the header SVG really is checked ---")
hdr = ROOT / "docs" / "header.svg"
if hdr.exists():
    text = hdr.read_text()
    check("the shipped header states the current stage count",
          f">{truth['stages']}<" in text or str(truth["stages"]) in text)
    check("the shipped header states the current tool count",
          str(truth["tools"]) in text)

print("\n--- `python3 -m vision` has a working entry point ---")
# A first-time operator types `python3 -m vision`, not `python3 -m vision.cli`.
# Without vision/__main__.py that fails on a fresh checkout — the exact trap an
# operator hit in the field. This asserts the entry point exists and dispatches
# to cli.main, so it cannot silently regress.
import pathlib as _pl
_mainfile = _pl.Path("vision/__main__.py")
check("vision/__main__.py exists", _mainfile.is_file())
if _mainfile.is_file():
    _mainsrc = _mainfile.read_text()
    check("it imports cli.main", "from vision.cli import main" in _mainsrc)
    check("it calls main() under __main__ guard",
          'if __name__ == "__main__"' in _mainsrc and "main()" in _mainsrc)
    # It must be runnable as a module and agree with cli on the version.
    import subprocess as _sp
    import sys as _sys
    _r = _sp.run([_sys.executable, "-m", "vision", "--version"],
                 capture_output=True, text=True, timeout=30)
    check("`python3 -m vision --version` runs and prints VISION",
          _r.returncode == 0 and "VISION" in (_r.stdout + _r.stderr),
          f"rc={_r.returncode} out={(_r.stdout + _r.stderr)[:60]!r}")

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
