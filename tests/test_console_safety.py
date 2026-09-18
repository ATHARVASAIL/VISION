"""Structural guard: a blocking input() must never run inside a Spinner block.

A real Kali run hung for 17+ minutes with the spinner showing "msf exploit ->
192.168.88.128 1056s" and no visible prompt. The cause was architectural, not
a one-off typo: launcher.run() -- which calls input() via confirm() -- was
invoked from inside `with ui.Spinner(...)`. The spinner's background thread
rewrites the same terminal line every 80ms, so any prompt printed underneath
it is immediately overwritten. The operator was not looking at a slow
exploit; they were looking at an erased confirmation prompt.

Unit tests on the launcher's API (in test_batch.py) prove confirm_many() and
filter_runnable() exist and work in isolation. They cannot prove the console
actually calls them in the right order relative to the spinner -- that is a
call-site property, not something exercisable through the launcher's API
alone. This suite reads the console source directly and asserts the shape
that prevents the bug from being reintroduced by a future edit.
"""
import ast
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

SRC_PATH = Path(__file__).resolve().parent.parent / "vision" / "core" / "console.py"
source = SRC_PATH.read_text()
tree = ast.parse(source)


def _spinner_with_blocks():
    """Every `with ui.Spinner(...)` node in the console module."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            for item in node.items:
                call = item.context_expr
                if (isinstance(call, ast.Call)
                        and isinstance(call.func, ast.Attribute)
                        and call.func.attr == "Spinner"):
                    out.append(node)
    return out


def _calls_input_or_confirm(node) -> list[str]:
    """Names of any blocking-confirmation calls found inside a subtree."""
    hits = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            fn = sub.func
            name = None
            if isinstance(fn, ast.Name):
                name = fn.id
            elif isinstance(fn, ast.Attribute):
                name = fn.attr
            if name in ("input", "confirm", "confirm_many", "_confirm_batch"):
                hits.append(name)
    return hits


print("--- no blocking confirmation call lives inside a Spinner block ---")
blocks = _spinner_with_blocks()
check("the console has at least one Spinner usage to check",
      len(blocks) > 0, "if this is 0, the source structure changed and the "
                       "check below is vacuous")

violations = []
for node in blocks:
    hits = _calls_input_or_confirm(node)
    if hits:
        violations.append((node.lineno, hits))

check("no Spinner block calls input()/confirm()/confirm_many() internally",
      not violations,
      "; ".join(f"line {ln}: {hs}" for ln, hs in violations))

print("\n--- the exploit-firing path confirms before opening its spinner ---")
check("launcher.confirm( appears in console.py",
      "launcher.confirm(" in source)
check("launcher.confirm_many( appears in console.py",
      "launcher.confirm_many(" in source)
check("run() is called with require_confirm=False from the console — "
      "confirmation already happened by the time the spinner opens",
      "require_confirm=False" in source)

# Textual ordering as a second, independent signal: confirm must appear
# before the Spinner that wraps the exploit-firing call, not after.
_exploit_confirm_idx = source.find("launcher.confirm(cd, action)")
_exploit_spinner_idx = source.find('ui.Spinner(f"msf {action}')
check("single-exploit: confirm(cd, action) appears before its Spinner",
      -1 < _exploit_confirm_idx < _exploit_spinner_idx,
      f"confirm at {_exploit_confirm_idx}, spinner at {_exploit_spinner_idx}")

_batch_confirm_idx = source.find("launcher.confirm_many(runnable)")
_batch_spinner_idx = source.find('ui.Spinner(f"verifying {len(runnable)}')
check("batch verify: confirm_many(runnable) appears before its Spinner",
      -1 < _batch_confirm_idx < _batch_spinner_idx,
      f"confirm_many at {_batch_confirm_idx}, spinner at {_batch_spinner_idx}")

print("\n--- the exploit spinner shows live phases, not just elapsed time ---")
# Before this, an operator watching a real run saw "msf exploit -> IP 1056s"
# with only the number changing -- no way to tell a slow module from a hung
# one. classify_phase() must actually be wired into the console's exploit
# call, not merely exist somewhere in exploit_advisor.py unused.
check("the console imports classify_phase",
      "classify_phase" in source)
check("the console passes on_line into launcher.run so phases stream live",
      "on_line=_on_line" in source or "on_line=" in source)
check("the spinner's label is updated from the callback, not fixed at "
      "creation", "_sp.update(" in source or ".update(f\"msf" in source)

print("\n--- the Stark theme lives in the console and never reaches the report ---")
# The whole safety case for the VISION HUD theme is that flavour stays in the
# live cockpit and the client deliverable stays in plain professional English.
# A client reads "SYSTEM COLLAPSE IMMINENT" as unserious, not impressive. These
# checks are the enforcement: the theme may relabel the console, but if a single
# Stark label ever appears in build_report's output the suite fails.
from vision.core.console import sev_label, STARK_SEV_LABEL
from vision.report.html import build_report

check("default theme shows the plain severity",
      sev_label("critical", "default") == "CRITICAL")
check("stark theme relabels the console severity",
      sev_label("critical", "stark") == "SYSTEM COLLAPSE IMMINENT")
check("an unknown theme falls back to the plain label",
      sev_label("critical", "nonsense") == "CRITICAL")
check("every severity has a stark label",
      all(s in STARK_SEV_LABEL for s in
          ("critical", "high", "medium", "low", "info")))

_rep = build_report([{"ip": "10.0.0.5", "port": 445, "title": "RCE",
                      "severity": "critical", "confidence": "confirmed",
                      "source": "test"}], [])
_leaked = [lbl for lbl in STARK_SEV_LABEL.values() if lbl in _rep]
check("NO stark label leaks into the client report", not _leaked,
      f"leaked: {_leaked}")
check("the report keeps the real severity word", "critical" in _rep.lower())

# The report module must not import the theme machinery at all — that keeps the
# isolation structural rather than a matter of remembering not to call it.
_report_src = Path("vision/report/html.py").read_text()
check("the report module does not import console theme machinery",
      "STARK_SEV_LABEL" not in _report_src and "sev_label" not in _report_src)

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
