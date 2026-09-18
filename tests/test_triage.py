"""Triage tests.

The failure that matters here is a report that silently omits findings. An
excluded finding must always be disclosed with its reason, because a report
missing a finding is indistinguishable from a scan that never found it.
"""
import json, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.core.triage import (
    Triage, STATES, REPORTABLE, NEW, CONFIRMED, FALSE_POSITIVE,
    ACCEPTED_RISK,
)
from vision.core.pipeline import RunState
from vision.report.html import build_report

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

def F(**kw):
    base = {"ip": "10.0.0.5", "port": 445, "title": "t", "severity": "high",
            "confidence": "confirmed", "cves": [], "source": "test"}
    base.update(kw); return base

print("--- states ---")
check("four states defined", set(STATES) ==
      {NEW, CONFIRMED, FALSE_POSITIVE, ACCEPTED_RISK})
check("new and confirmed are reportable", REPORTABLE == {NEW, CONFIRMED})
check("false positive is not reportable", FALSE_POSITIVE not in REPORTABLE)
check("accepted risk is not reportable", ACCEPTED_RISK not in REPORTABLE)
check("every state is described", all(len(v) > 10 for v in STATES.values()))

print("\n--- recording decisions ---")
t = Triage(operator="omkar")
f = F()
check("default is new", t.status(f) == NEW)
check("no decision initially", t.decision(f) is None)

t.set(f, CONFIRMED)
check("confirmed recorded", t.status(f) == CONFIRMED)
check("operator recorded", t.decision(f).by == "omkar")
check("timestamp recorded", t.decision(f).at > 0)
check("confirmed needs no reason", True)

t.set(f, FALSE_POSITIVE, "honeypot, agreed with client")
check("status updated", t.status(f) == FALSE_POSITIVE)
check("reason stored", "honeypot" in t.decision(f).note)

t.clear(f)
check("cleared back to new", t.status(f) == NEW)
check("decision removed", t.decision(f) is None)

print("\n--- exclusions require a reason ---")
for status in (FALSE_POSITIVE, ACCEPTED_RISK):
    try:
        t.set(F(), status, "")
        check(f"{status} rejects an empty reason", False, "accepted")
    except ValueError:
        check(f"{status} rejects an empty reason", True)
    try:
        t.set(F(), status, "   ")
        check(f"{status} rejects whitespace", False)
    except ValueError:
        check(f"{status} rejects whitespace", True)
try:
    t.set(F(), "invented-state", "x")
    check("unknown state rejected", False)
except ValueError:
    check("unknown state rejected", True)

print("\n--- identity survives a rescan ---")
t2 = Triage()
a = F(ip="10.0.0.5", port=445, cves=["CVE-2017-0144"], severity="high",
      title="One wording", evidence="x")
t2.set(a, FALSE_POSITIVE, "decoy host")
# Same issue, re-detected with different wording, severity and evidence.
b = F(ip="10.0.0.5", port=445, cves=["CVE-2017-0144"], severity="critical",
      title="Different wording", evidence="totally different")
check("decision survives re-wording and re-rating",
      t2.status(b) == FALSE_POSITIVE)
check("a different host is untouched",
      t2.status(F(ip="10.0.0.9", cves=["CVE-2017-0144"])) == NEW)
check("a different port is untouched",
      t2.status(F(port=139, cves=["CVE-2017-0144"])) == NEW)

print("\n--- views ---")
findings = [F(title="a"), F(title="b", port=139), F(title="c", port=80),
            F(title="d", port=22)]
t3 = Triage()
t3.set(findings[1], CONFIRMED)
t3.set(findings[2], FALSE_POSITIVE, "not applicable")
t3.set(findings[3], ACCEPTED_RISK, "client accepted")
check("reportable keeps new and confirmed", len(t3.reportable(findings)) == 2)
check("excluded returns the held-back ones", len(t3.excluded(findings)) == 2)
check("excluded carries the decision",
      all(d.note for _f, d in t3.excluded(findings)))
counts = t3.counts(findings)
check("counts by state", counts[NEW] == 1 and counts[CONFIRMED] == 1
      and counts[FALSE_POSITIVE] == 1 and counts[ACCEPTED_RISK] == 1, str(counts))

annotated = t3.annotate(findings)
check("annotate attaches triage to every finding",
      all("triage" in f for f in annotated))
check("annotate does not mutate the originals",
      all("triage" not in f for f in findings))
check("annotated output is serialisable", json.dumps(annotated) is not None)

print("\n--- persistence ---")
d = Path(tempfile.mkdtemp())
st = RunState(scope="t", workdir=str(d))
st.findings = findings
st.triage = t3.as_dict()
st.save(d / "state.json")
st2 = RunState.load(d / "state.json")
t4 = Triage(st2.triage)
check("triage survives save and load", len(t4) == 3)
check("statuses preserved", t4.status(findings[2]) == FALSE_POSITIVE)
check("reasons preserved", "not applicable" in t4.decision(findings[2]).note)
check("state without triage still loads",
      isinstance(Triage(RunState(scope="x", workdir=".").triage), Triage))
check("corrupt triage entries ignored",
      len(Triage({"abc": "not a dict", "def": {"status": CONFIRMED}})) == 1)

print("\n--- escape sequences in reasons ---")
t5 = Triage()
t5.set(F(), FALSE_POSITIVE, "\x1b[2Jclean\x1b[0m <script>alert(1)</script>")
note = t5.decision(F()).note
check("ANSI stripped from the reason", "\x1b" not in note)
check("reason text preserved", "clean" in note)

print("\n--- the report discloses, never drops ---")
report_findings = [
    {**F(ip="10.0.0.5", port=6379, title="Redis exposed", severity="critical"),
     "triage": {"status": CONFIRMED}},
    {**F(ip="10.0.0.6", port=23, title="Telnet exposed"),
     "triage": {"status": FALSE_POSITIVE, "note": "honeypot, agreed with client"}},
    {**F(ip="10.0.0.7", port=22, title="Password auth", severity="low"),
     "triage": {"status": ACCEPTED_RISK, "note": "compensating MFA in place"}},
    F(ip="10.0.0.8", port=80, title="Missing headers", severity="medium"),
]
h = build_report(report_findings, [])
check("only reportable findings in the main list",
      h.count('class="finding"') == 2, str(h.count('class="finding"')))
check("excluded section present", "Excluded findings" in h)
check("excluded count correct", "Excluded findings &middot; 2" in h)
check("false-positive reason disclosed", "honeypot, agreed with client" in h)
check("accepted-risk reason disclosed", "compensating MFA in place" in h)
check("excluded finding not duplicated in the main list",
      h.count("Telnet exposed") == 1)
check("decision shown alongside", "false-positive" in h and "accepted-risk" in h)
check("appendix explains itself",
      "checked rather than taken on trust" in h)

h2 = build_report([F(title="only one")], [])
check("no appendix when nothing excluded", "Excluded findings" not in h2)
check("untriaged findings still report", h2.count('class="finding"') == 1)

hostile = build_report(
    [{**F(title="x"), "triage": {"status": FALSE_POSITIVE,
                                 "note": "<script>alert(1)</script>"}}], [])
check("reason is escaped in the report",
      "<script>alert(1)</script>" not in hostile[hostile.index("<body>"):])
check("escaped reason still visible", "&lt;script&gt;" in hostile)

print("\n--- severity roll-up reflects exclusions ---")
h3 = build_report([
    {**F(severity="critical", title="a"), "triage": {"status": CONFIRMED}},
    {**F(severity="critical", title="b", port=1),
     "triage": {"status": FALSE_POSITIVE, "note": "n/a"}},
], [])
check("excluded findings are not counted in the posture",
      h3.count('class="finding"') == 1)

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
