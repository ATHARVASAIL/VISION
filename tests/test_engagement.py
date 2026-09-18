"""Engagement metadata and executive summary tests.

Two properties matter. The analyst's own summary must always beat the generated
one — a tool that quietly overwrites written prose is worse than one that never
drafts. And the draft must never claim coverage it does not have: a summary
reporting four findings without mentioning that eleven stages never ran is
technically true and materially misleading.
"""
import json, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.core.engagement import (
    Engagement, draft_summary, resolve_summary, summary_is_draft, counts,
    coverage,
)
from vision.core.pipeline import RunState
from vision.report.html import build_report

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

def F(**kw):
    return {"ip": "10.0.0.5", "title": "t", "severity": "medium",
            "confidence": "confirmed", "cves": [], "source": "x", **kw}

RAN = {"name": "port-scan", "ok": True, "skipped": False}
def SKIP(reason):
    return {"name": "x", "ok": True, "skipped": True, "reason": reason}

print("--- metadata ---")
m = Engagement()
check("unconfigured by default", not m.is_configured)
check("has a default assessment name", m.name)
m.client = "Acme Ltd"
check("configured once a client is set", m.is_configured)
m.started, m.finished = "1 Jan 2026", "3 Jan 2026"
check("date range rendered", m.dates == "1 Jan 2026 – 3 Jan 2026")
m.finished = m.started
check("single day is not a range", m.dates == "1 Jan 2026")
check("partial dates still render", Engagement(started="1 Jan").dates == "1 Jan")
check("no dates is empty", Engagement().dates == "")

m2 = Engagement()
m2.stamp_start()
check("start stamped", bool(m2.started))
first = m2.started
m2.stamp_start()
check("start is not overwritten on a rescan", m2.started == first)
m2.stamp_finish()
check("finish stamped", bool(m2.finished))

print("\n--- serialisation ---")
d = Engagement(client="Acme", tester="O.S.", reference="SOW-1").as_dict()
check("round-trips", Engagement.from_dict(d).client == "Acme")
check("json-safe", json.dumps(d) is not None)
check("unknown keys ignored",
      Engagement.from_dict({"client": "A", "bogus": "x"}).client == "A")
check("None input is safe", Engagement.from_dict(None).client == "")
check("ANSI stripped from fields",
      "\x1b" not in Engagement.from_dict({"client": "\x1b[2JAcme"}).client)
check("oversized field truncated",
      len(Engagement.from_dict({"client": "A" * 999}).client) <= 200)
check("narrative fields allow more room",
      len(Engagement.from_dict({"executive_summary": "A" * 5000})
          .executive_summary) > 200)

print("\n--- helpers ---")
c = counts([F(severity="critical"), F(severity="critical"), F(severity="low")])
check("counts by severity", c["critical"] == 2 and c["low"] == 1)
check("unknown severity ignored", counts([F(severity="spicy")])["info"] == 0)
ran, skipped, missing = coverage([RAN, SKIP("nuclei not installed"),
                                  SKIP("no SMB services found")])
check("ran counted", ran == 1)
check("skipped counted", skipped == 2)
check("missing tools extracted", missing == ["nuclei"])
check("service-absence is not a missing tool", "no SMB services found" not in missing)

print("\n--- the draft states what was found ---")
text = draft_summary(
    [F(severity="critical", title="Redis exposed without authentication"),
     F(severity="high", title="SMB shares accessible"),
     F(severity="low", title="Banner disclosure")],
    [{"ip": "10.0.0.5"}], hosts=4, stages=[RAN, RAN], paths=2)
check("host count stated", "4 live hosts" in text)
check("finding count stated", "3 findings" in text)
check("urgent count stated", "2 are rated high or critical" in text)
check("worst severity named", "rated critical" in text)
check("principal issues named", "Redis exposed without authentication" in text)
check("attack paths described", "2 attack paths" in text)
check("chains not conflated with findings",
      "2 of these findings combine" not in text,
      "paths counts chains, not findings")
check("explains why chains matter", "Breaking any single step" in text)

print("\n--- singular and plural read correctly ---")
one = draft_summary([F(severity="high", title="One thing")], [], hosts=1,
                    stages=[RAN], paths=1)
check("one host", "1 live host " in one and "1 live hosts" not in one)
check("one finding", "1 finding " in one and "1 findings" not in one)
check("one path", "1 attack path " in one and "1 attack paths" not in one)
check("is/are agrees", "1 is rated" in one)

print("\n--- coverage is never implied ---")
gapped = draft_summary([F(severity="critical")], [], hosts=2,
                       stages=[RAN, SKIP("nuclei not installed"),
                               SKIP("testssl.sh not installed")])
check("coverage note present", "Coverage note" in gapped)
check("missing tools named", "nuclei" in gapped and "testssl.sh" in gapped)
check("explains why it matters",
      "only meaningful alongside what was examined" in gapped)

service_gap = draft_summary([F()], [], hosts=1,
                            stages=[RAN, SKIP("no SMB services found")])
check("service-absence stated differently",
      "relevant services were not present" in service_gap)
check("no false tooling claim", "tooling was unavailable" not in service_gap)

clean = draft_summary([], [], hosts=3, stages=[RAN] * 4)
check("clean result does not claim a clean network",
      "not the same as a clean network" in clean)
check("clean result points at coverage", "what was and was not examined" in clean)

mild = draft_summary([F(severity="low"), F(severity="medium")], [], hosts=1,
                     stages=[RAN])
check("no urgent findings stated plainly", "none rated high or critical" in mild)
check("framed as hardening", "hardening opportunities" in mild)

print("\n--- the coverage note reads like a person wrote it ---")
# "1 stage did not run, 1 of them because..." is machine phrasing, and in a
# client-facing summary it undermines everything around it.
_equal = draft_summary([F(severity="high")], [], 1,
                       [RAN, SKIP("fping not installed")])
check("no redundant count when every skip is a missing tool",
      "1 of them" not in _equal, _equal[_equal.find("Coverage note"):][:80])
check("it still names the tool", "fping" in _equal)
check("singular stage reads correctly",
      "1 stage did not run because" in _equal)

_mixed = draft_summary([F(severity="high")], [], 1,
                       [RAN, SKIP("fping not installed"),
                        SKIP("nuclei not installed"),
                        SKIP("no SMB services found")])
check("the partial count is kept when it differs", "2 of them" in _mixed,
      _mixed[_mixed.find("Coverage note"):][:90])
check("plural reads correctly", "3 stages did not run" in _mixed)
check("both forms explain why coverage matters",
      "only meaningful alongside" in _equal and "only meaningful alongside" in _mixed)

print("\n--- the analyst's summary always wins ---")
own = Engagement(executive_summary="The estate is in reasonable shape.")
text, is_draft = resolve_summary(own, [F(severity="critical")], [], 5, [RAN], 3)
check("analyst text used", text == "The estate is in reasonable shape.")
check("not marked as a draft", not is_draft)
check("summary_is_draft agrees", not summary_is_draft(own))
blank = Engagement(executive_summary="   ")
check("whitespace is not a summary", summary_is_draft(blank))
_t, d2 = resolve_summary(blank, [F()], [], 1, [RAN], 0)
check("blank falls back to the draft", d2)
check("no engagement falls back to the draft",
      resolve_summary(None, [F()], [], 1, [RAN], 0)[1])

print("\n--- report integration ---")
meta = Engagement(client="Acme Manufacturing Ltd", tester="O. Sail",
                  reference="SOW-2026-014", started="11 August 2026",
                  finished="13 August 2026", contact="ops@acme.example")
h = build_report([F(severity="critical", title="Redis exposed",
                    remediation="Set requirepass.")],
                 [{"ip": "10.0.0.5", "port": 6379, "proto": "tcp"}],
                 scope="10.0.0.0/24", live_hosts=["10.0.0.5"],
                 stages=[RAN, SKIP("nuclei not installed")], meta=meta)
check("client shown", "Acme Manufacturing Ltd" in h)
check("assessor shown", "O. Sail" in h)
check("authorisation shown", "SOW-2026-014" in h)
check("dates shown", "11 August 2026" in h)
check("contact shown", "ops@acme.example" in h)
check("executive summary section present", "Executive summary" in h)
check("draft is labelled", "Replace it with your own assessment" in h)
check("summary precedes the findings",
      h.index("Executive summary") < h.index(">Findings<"))
check("summary precedes the remediation plan",
      h.index("Executive summary") < h.index("Remediation plan"))

written = Engagement(client="Acme", executive_summary="My own words entirely.")
h2 = build_report([F()], [], meta=written)
check("analyst summary rendered", "My own words entirely." in h2)
check("draft label absent when analyst wrote it",
      "Replace it with your own assessment" not in h2)

h3 = build_report([F()], [])
check("no engagement block without metadata", "Authorisation" not in h3)
check("summary still produced without metadata", "Executive summary" in h3)

hostile = build_report([F()], [], meta=Engagement(
    client="<script>alert(1)</script>",
    executive_summary="<img src=x onerror=alert(1)>"))
body = hostile[hostile.index("<body>"):]
check("client name escaped", "<script>alert(1)</script>" not in body)
check("summary escaped", "<img src=x onerror" not in body)
check("escaped text still visible", "&lt;script&gt;" in hostile)

print("\n--- persistence ---")
d = Path(tempfile.mkdtemp())
st = RunState(scope="10.0.0.0/24", workdir=str(d))
st.engagement = meta.as_dict()
st.save(d / "state.json")
reloaded = Engagement.from_dict(RunState.load(d / "state.json").engagement)
check("engagement survives save and load", reloaded.client == "Acme Manufacturing Ltd")
check("authorisation preserved", reloaded.reference == "SOW-2026-014")
check("dates preserved", reloaded.dates == "11 August 2026 – 13 August 2026")
check("state without engagement still loads",
      Engagement.from_dict(RunState(scope="x", workdir=".").engagement).client == "")

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
