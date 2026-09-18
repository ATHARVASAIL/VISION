"""Remediation plan tests.

The assertion that matters most: a critical must never rank below a group of
lesser findings. An earlier version scored purely on summed severity weight and
put three Telnet findings above an unauthenticated Redis instance — a plan
ordered that way could get a client breached while they work through it.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.analysis.remediation import (
    plan, summary, quick_wins, SEVERITY_WEIGHT,
    _action_key,
)
from vision.report.html import build_report

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

def F(**kw):
    base = {"ip": "10.0.0.1", "severity": "medium", "title": "t",
            "confidence": "confirmed", "cves": [], "remediation": "Do the thing."}
    base.update(kw); return base

print("--- grouping ---")
same = [F(ip=f"10.0.0.{i}", remediation="Enforce SMB signing.") for i in (1, 2, 3)]
acts = plan(same)
check("identical remediation groups into one action", len(acts) == 1)
check("all hosts collected", acts[0].hosts == ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
check("all findings retained", len(acts[0].findings) == 3)

check("different remediation stays separate",
      len(plan([F(remediation="Disable Telnet."),
                F(ip="10.0.0.2", remediation="Enforce SMB signing.")])) == 2)

print("\n--- per-host detail does not prevent grouping ---")
versioned = [F(ip="10.0.0.1", remediation="Upgrade MySQL past 5.5.28."),
             F(ip="10.0.0.2", remediation="Upgrade MySQL past 5.7.33.")]
check("version numbers normalised away", len(plan(versioned)) == 1)
addressed = [F(ip="10.0.0.1", remediation="Disable Telnet on 10.0.0.1."),
             F(ip="10.0.0.2", remediation="Disable Telnet on 10.0.0.2.")]
check("addresses normalised away", len(plan(addressed)) == 1)
ported = [F(ip="10.0.0.1", remediation="Close port :8080 on the firewall."),
          F(ip="10.0.0.2", remediation="Close port :9090 on the firewall.")]
check("ports normalised away", len(plan(ported)) == 1)
quoted = [F(ip="10.0.0.1", remediation="Change the community string 'public'."),
          F(ip="10.0.0.2", remediation="Change the community string 'private'.")]
check("quoted specifics normalised away", len(plan(quoted)) == 1)
check("genuinely different actions still separate",
      _action_key("Disable Telnet.") != _action_key("Enforce SMB signing."))
# Differently-worded instructions must NOT group: the normaliser strips
# per-host detail, not arbitrary extra words, or unrelated actions would merge.
check("different wording is a different action",
      len(plan([F(remediation="Disable Telnet."),
                F(ip="10.0.0.2",
                  remediation="Disable Telnet immediately please.")])) == 2)
# Where findings do group, the shortest wording becomes the instruction —
# per-host specifics belong on the finding, not in the action.
check("shortest wording kept as the instruction",
      plan([F(remediation="Upgrade MySQL past 5.7.33."),
            F(ip="10.0.0.2", remediation="Upgrade MySQL past 5.5.6.")]
           )[0].text == "Upgrade MySQL past 5.5.6.")

print("\n--- ranking: severity dominates breadth ---")
mixed = ([F(ip=f"10.0.0.{i}", severity="high", remediation="Disable Telnet.")
          for i in (4, 5, 6)]
         + [F(ip="10.0.0.9", severity="critical", remediation="Set requirepass.")]
         + [F(ip=f"10.0.0.{i}", severity="medium", remediation="Enforce signing.")
            for i in (1, 2, 3)])
ranked = plan(mixed)
check("a single critical outranks three highs",
      ranked[0].severity == "critical", ranked[0].severity)
check("highs come before mediums", ranked[1].severity == "high")
check("order is by severity tier",
      [a.severity for a in ranked] == ["critical", "high", "medium"])
check("summed weight still exceeds for the highs — and does not win",
      ranked[1].score > ranked[0].score,
      "the test is meaningless unless the high group scores higher")

print("\n--- breadth orders within a tier ---")
tier = ([F(ip=f"10.0.0.{i}", severity="high", remediation="Fix A.")
         for i in (1, 2, 3, 4)]
        + [F(ip="10.0.0.9", severity="high", remediation="Fix B.")])
t = plan(tier)
check("wider action first inside the same tier", len(t[0].hosts) == 4)
check("both retained", len(t) == 2)

print("\n--- action properties ---")
a = plan([F(severity="critical", cves=["CVE-2021-1"], remediation="Fix it."),
          F(ip="10.0.0.2", severity="low", cves=["CVE-2021-2"],
            remediation="Fix it.")])[0]
check("worst severity reported", a.severity == "critical")
check("score sums weights",
      a.score == SEVERITY_WEIGHT["critical"] + SEVERITY_WEIGHT["low"])
check("CVEs collected and sorted", a.cves == ["CVE-2021-1", "CVE-2021-2"])
check("counts by severity", a.counts == {"critical": 1, "low": 1})
check("summary reads naturally", "across 2 hosts" in a.summary())
check("single host is singular",
      "1 host" in plan([F(remediation="x.")])[0].summary()
      and "1 hosts" not in plan([F(remediation="x.")])[0].summary())

print("\n--- confidence is the weakest link ---")
weak = plan([F(remediation="Upgrade it.", confidence="confirmed"),
             F(ip="10.0.0.2", remediation="Upgrade it.", confidence="tentative")])
check("tentative drags the action down", weak[0].confidence == "tentative")
strong = plan([F(remediation="Upgrade it.", confidence="confirmed"),
               F(ip="10.0.0.2", remediation="Upgrade it.", confidence="firm")])
check("firm reported when that is the weakest", strong[0].confidence == "firm")

print("\n--- findings with no remediation ---")
mixed2 = [F(remediation="Fix it."), F(ip="10.0.0.2", remediation=""),
          F(ip="10.0.0.3", remediation="   ")]
acts2 = plan(mixed2)
check("unactionable findings are not dropped",
      sum(len(a.findings) for a in acts2) == 3)
check("they are grouped for manual review",
      any("Review manually" in a.text for a in acts2))
check("the review bucket sorts last", "Review manually" in acts2[-1].text)

print("\n--- informational findings ---")
info = [F(severity="info", remediation="Note it.")]
check("info excluded by default", plan(info) == [])
check("info included on request", len(plan(info, include_info=True)) == 1)

print("\n--- quick wins ---")
qw = plan([F(ip=f"10.0.0.{i}", severity="medium", remediation="Wide fix.")
           for i in range(1, 8)]
          + [F(ip="10.0.0.9", severity="critical", remediation="Narrow fix.")])
wins = quick_wins(qw)
check("quick wins favour breadth", wins and len(wins[0].hosts) == 7)
check("single-host actions excluded",
      all(len(a.hosts) > 1 for a in wins))
check("quick wins do not reorder the plan", qw[0].severity == "critical")
check("limit respected", len(quick_wins(qw, limit=1)) == 1)

print("\n--- robustness ---")
check("empty input", plan([]) == [])
check("non-dict entries ignored", plan([None, "x", 42, F(remediation="a.")]))
junk = [{}, {"remediation": None}, {"severity": None, "remediation": "x."},
        {"ip": None, "remediation": "y."}]
try:
    plan(junk)
    check("malformed findings do not crash", True)
except Exception as e:
    check("malformed findings do not crash", False, str(e))
big = [F(ip=f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}",
         remediation=f"Fix type {i % 20}.") for i in range(3000)]
import time
t0 = time.time(); pbig = plan(big); dt = time.time() - t0
check(f"3000 findings plan quickly ({dt:.2f}s)", dt < 5, f"{dt:.2f}s")
check("grouped down to the distinct actions", len(pbig) == 20, str(len(pbig)))

s = summary(plan(mixed))
check("summary counts actions", s["actions"] == 3)
check("summary counts findings covered", s["findings_covered"] == 7)
check("summary counts hosts", s["hosts"] == 7)

print("\n--- report integration ---")
h = build_report([F(ip="10.0.0.1", severity="critical", title="Redis exposed",
                    remediation="Set requirepass on Redis."),
                  F(ip="10.0.0.2", severity="high", title="Telnet",
                    remediation="Disable Telnet."),
                  F(ip="10.0.0.3", severity="high", title="Telnet",
                    remediation="Disable Telnet.")], [])
check("plan section present", "Remediation plan" in h)
check("actions counted", "Remediation plan &middot; 2" in h)
check("plan appears before the findings detail",
      h.index("Remediation plan") < h.index(">Findings<"))
check("quick wins shown when relevant", "One change, several hosts" in h)
check("action text escaped",
      "<script>" not in build_report(
          [F(remediation="<script>alert(1)</script>")], [])[
              build_report([F(remediation="x")], []).index("<body>"):])
check("no plan section when nothing to plan",
      "Remediation plan" not in build_report([], []))

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
