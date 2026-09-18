"""Manual finding tests.

Two properties matter most. A finding typed by hand must still respect the
engagement scope — a boundary that applies to the scanner but not the keyboard
is not a boundary. And it must stay visibly distinguishable from tool output,
because a reviewer asks different questions of each.
"""
import json, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.core.manual import (
    build, is_manual, author, InvalidFinding, SEVERITIES, CONFIDENCES,
    CONFIDENCE_HELP,
)
from vision.core.scope import Scope
from vision.core.pipeline import RunState
from vision.report.html import build_report
from vision.analysis.remediation import plan
from vision.core.triage import Triage, FALSE_POSITIVE

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

SCOPE = Scope.from_lists(["10.0.0.0/24"])
OK = dict(ip="10.0.0.5", title="Domain admin via delegation", severity="critical")

print("--- a valid finding ---")
f = build(**OK, port=445, evidence="Obtained TGT", remediation="Remove it.",
          operator="omkar", scope=SCOPE)
check("built", f["title"] == "Domain admin via delegation")
check("severity kept", f["severity"] == "critical")
check("port kept", f["port"] == 445)
check("defaults to confirmed", f["confidence"] == "confirmed")
check("marked manual", f["manual"] is True)
check("source is namespaced", f["source"] == "manual:omkar")
check("timestamped", f["recorded_at"] > 0)
check("serialisable", json.dumps(f) is not None)
check("carries every field the report expects",
      {"ip", "title", "severity", "confidence", "evidence", "remediation",
       "cves", "source"} <= set(f))

print("\n--- scope applies to typed findings too ---")
try:
    build(ip="8.8.8.8", title="Something real", severity="high", scope=SCOPE)
    check("out-of-scope target refused", False, "accepted")
except InvalidFinding as e:
    check("out-of-scope target refused", "outside the engagement scope" in str(e))
    check("refusal explains the rule", "boundary" in str(e))
check("in-scope neighbour accepted",
      build(ip="10.0.0.99", title="Something real", severity="low",
            scope=SCOPE)["ip"] == "10.0.0.99")
check("no scope object means no scope check",
      build(ip="8.8.8.8", title="Something real", severity="low")["ip"] == "8.8.8.8")

print("\n--- validation refuses what would look wrong later ---")
cases = [
    ("empty target", dict(ip="", title="A real title", severity="high")),
    ("blank target", dict(ip="   ", title="A real title", severity="high")),
    ("title too short", dict(ip="10.0.0.5", title="hi", severity="high")),
    ("empty title", dict(ip="10.0.0.5", title="", severity="high")),
    ("bad severity", dict(ip="10.0.0.5", title="A real title", severity="apocalyptic")),
    ("empty severity", dict(ip="10.0.0.5", title="A real title", severity="")),
]
for label, kw in cases:
    try:
        build(**kw)
        check(f"refuses {label}", False, "accepted")
    except InvalidFinding:
        check(f"refuses {label}", True)

for label, kw in [
    ("bad confidence", dict(**OK, confidence="vibes")),
    ("non-numeric port", dict(**OK, port="http")),
    ("port zero", dict(**OK, port=0)),
    ("port too high", dict(**OK, port=70000)),
    ("non-CVE identifier", dict(**OK, cves=["NOT-A-CVE"])),
]:
    try:
        build(**kw)
        check(f"refuses {label}", False, "accepted")
    except InvalidFinding:
        check(f"refuses {label}", True)

# Every refusal must say what to do about it, not just that it failed.
_messages = []
for _kw in [dict(ip="", title="A real title", severity="high"),
            dict(ip="10.0.0.5", title="hi", severity="high"),
            dict(ip="10.0.0.5", title="A real title", severity="nope"),
            dict(ip="10.0.0.5", title="A real title", severity="high", port=0),
            dict(ip="10.0.0.5", title="A real title", severity="high",
                 cves=["NOPE"])]:
    try:
        build(**_kw)
    except InvalidFinding as _e:
        _messages.append(str(_e))
check("every refusal produced a message", len(_messages) == 5, str(len(_messages)))
check("refusals are explanatory, not just 'invalid'",
      all(len(m) > 25 for m in _messages), str([m for m in _messages if len(m) <= 25]))
check("refusals name the offending field",
      all(any(w in m.lower() for w in
              ("address", "title", "severity", "port", "cve"))
          for m in _messages), str(_messages))

print("\n--- optional fields ---")
f2 = build(**OK)
check("port optional", f2["port"] is None)
check("evidence optional", f2["evidence"] == "")
check("remediation optional", f2["remediation"] == "")
check("cves default empty", f2["cves"] == [])
check("operator defaults", f2["source"] == "manual:analyst")
check("cves normalised and deduped",
      build(**OK, cves=["cve-2021-1234", "CVE-2021-1234"])["cves"]
      == ["CVE-2021-1234"])

print("\n--- hostile input is sanitised ---")
f3 = build(ip="10.0.0.5", title="\x1b[2Jfake clean\x1b[0m", severity="high",
           evidence="\x1b[31mred\x1b[0m", remediation="\x1b[Kx", operator="\x1b[2Jx")
check("ANSI stripped from title", "\x1b" not in f3["title"])
check("ANSI stripped from evidence", "\x1b" not in f3["evidence"])
check("ANSI stripped from remediation", "\x1b" not in f3["remediation"])
check("ANSI stripped from operator", "\x1b" not in f3["source"])
check("long title truncated", len(build(**{**OK, "title": "A" * 500})["title"]) <= 120)
check("long evidence truncated",
      len(build(**OK, evidence="A" * 99999)["evidence"]) <= 4000)

print("\n--- identification ---")
check("is_manual on a manual finding", is_manual(f))
check("is_manual on a tool finding", not is_manual({"source": "banner-analysis"}))
check("is_manual on a bare dict", not is_manual({}))
check("author extracted", author(f) == "omkar")
check("author empty for tool findings", author({"source": "nmap"}) == "")
check("survives a source-only record", is_manual({"source": "manual:x"}))

print("\n--- constants ---")
check("severities complete",
      SEVERITIES == ["critical", "high", "medium", "low", "info"])
check("confidences complete", set(CONFIDENCES) == {"confirmed", "firm", "tentative"})
check("every confidence is explained", set(CONFIDENCE_HELP) == set(CONFIDENCES))
check("explanations are useful",
      all(len(v) > 30 for v in CONFIDENCE_HELP.values()))

print("\n--- manual findings flow through everything downstream ---")
mixed = [
    build(ip="10.0.0.5", port=445, title="Domain admin via delegation",
          severity="critical", evidence="Got a TGT",
          remediation="Remove unconstrained delegation.", operator="omkar",
          scope=SCOPE),
    {"ip": "10.0.0.6", "port": 23, "title": "Telnet exposed", "severity": "high",
     "confidence": "firm", "cves": [], "source": "banner-analysis",
     "remediation": "Disable Telnet."},
]
h = build_report(mixed, [])
check("both appear in the report", h.count('class="finding"') == 2)
check("manual finding is labelled", "recorded manually" in h)
check("author shown", "omkar" in h)
check("tool finding is not mislabelled",
      h.count("recorded manually") == 1)
check("manual finding is escaped",
      "<script>" not in build_report(
          [build(ip="10.0.0.5", title="<script>alert(1)</script>",
                 severity="high")], [])[h.index("<body>") if "<body>" in h else 0:])

actions = plan(mixed)
check("manual finding reaches the remediation plan",
      any("delegation" in a.text for a in actions))
check("it ranks by its severity", actions[0].severity == "critical")

t = Triage()
t.set(mixed[0], FALSE_POSITIVE, "was my own test account")
check("manual findings can be triaged", t.status(mixed[0]) == FALSE_POSITIVE)
check("triaged-out manual finding leaves the main report",
      build_report(t.annotate(mixed), []).count('class="finding"') == 1)

print("\n--- persistence ---")
d = Path(tempfile.mkdtemp())
st = RunState(scope="t", workdir=str(d))
st.findings = mixed
st.save(d / "state.json")
st2 = RunState.load(d / "state.json")
check("manual finding survives save and load", len(st2.findings) == 2)
reloaded = [x for x in st2.findings if is_manual(x)]
check("still identifiable after reload", len(reloaded) == 1)
check("evidence preserved", reloaded[0]["evidence"] == "Got a TGT")
check("author preserved", author(reloaded[0]) == "omkar")

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
