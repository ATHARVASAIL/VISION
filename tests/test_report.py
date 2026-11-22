"""Report tests. Escaping is the critical one: findings carry remote-controlled
text, so an unescaped field is stored XSS against the client's security team."""
import os, re, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.report.html import build_report, write_report, SEVERITY_ORDER

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

F = lambda **kw: {"ip": "10.10.0.5", "title": "t", "severity": "info",
                  "confidence": "firm", "source": "test", **kw}
S = lambda **kw: {"ip": "10.10.0.5", "port": 80, "proto": "tcp", **kw}

print("--- structure ---")
h = build_report([], [])
check("valid doctype", h.startswith("<!DOCTYPE html>"))
check("closes html", h.rstrip().endswith("</html>"))
check("has viewport meta", 'name="viewport"' in h)
check("declares lang", '<html lang="en">' in h)
check("empty scan produces a report", len(h) > 2000)
check("empty state explained, not blank", "without identifying any issues" in h)

check("no external stylesheet", "<link" not in h)
check("no external script", "<script" not in h)
check("no CDN reference", "cdn" not in h.lower() and "googleapis" not in h.lower())
check("no remote font import", "@import" not in h and "fonts." not in h)

print("\n--- escaping (stored XSS) ---")
payloads = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
    "</title><script>alert(1)</script>",
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
    "'; DROP TABLE findings;--",
    "</pre><script>alert(1)</script><pre>",
    "<iframe src=//evil.com>",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
]
# The correct test is whether *live markup* appears, not whether the literal
# characters do. "&lt;img onerror=x&gt;" contains the substring "onerror=" but
# is inert text — matching on that produces false alarms and teaches you to
# ignore the test.
LIVE_TAG = re.compile(r"<\s*(script|img|svg|iframe|object|embed|body|style)\b", re.I)
# Match a handler only inside a *real* tag: [^<>&]* cannot cross an escaped
# entity, so "&lt;img onerror=x&gt;" inside a legitimate href no longer trips it.
LIVE_HANDLER = re.compile(r"<[^<>&]*\son\w+\s*=", re.I)

ALLOWED_TAGS = {"body", "style"}   # ours, in the template

leaked = []
for i, payload in enumerate(payloads):
    r = build_report(
        [F(title=payload, description=payload, evidence=payload,
           remediation=payload, source=payload, cves=[payload])],
        [S(product=payload, name=payload)],
        scope=payload, operator=payload, engagement=payload,
    )
    body = r[r.index("<body>"):]
    injected = [m.group(1).lower() for m in LIVE_TAG.finditer(body)
                if m.group(1).lower() not in ALLOWED_TAGS]
    if injected or LIVE_HANDLER.search(body):
        leaked.append((i, payload[:40], injected))
check(f"all {len(payloads)} XSS payloads produce no live markup",
      not leaked, str(leaked[:2]))

# and confirm the payload survives as readable escaped text, so the analyst
# still sees what the target actually sent
r = build_report([F(title="<script>alert(1)</script>")], [])
check("payload preserved as escaped text for the reader",
      "&lt;script&gt;alert(1)&lt;/script&gt;" in r)

r = build_report([F(title="<b>bold</b>")], [])
check("markup shown as literal text", "&lt;b&gt;bold&lt;/b&gt;" in r)
check("no raw tag injected", "<b>bold</b>" not in r[r.index("<body>"):])

r = build_report([F(evidence="\x1b[2J\x1b[31mFAKE CLEAN\x1b[0m")], [])
check("ANSI escapes stripped from report", "\x1b" not in r)

r = build_report([F(title="日本語 ☠ ünïcode")], [])
check("unicode preserved", "日本語" in r and "ünïcode" in r)

print("\n--- severity presentation ---")
findings = [F(severity=s, title=f"{s} issue") for s in SEVERITY_ORDER]
r = build_report(findings, [])
for s in SEVERITY_ORDER:
    if f"--sev-{s}" not in r:
        check(f"{s} styled", False)
check("all five severities styled", True)
check("severity counts rendered", all(f"{lab}" in r for lab in
      ("Critical", "High", "Medium", "Low", "Informational")))
crit_at = r.index("Critical &middot;")
info_at = r.index("Informational &middot;")
check("critical ordered before informational", crit_at < info_at)

r = build_report([F(severity="critical")] * 3 + [F(severity="low")], [])
check("posture bar sized proportionally", "width:75.0000%" in r, "")
check("counts shown in key", ">3</b>" in r)

r = build_report([F(severity="info", title=f"i{i}") for i in range(10)], [])
check("many info findings collapsed", "<details>" in r and "Show 10 informational" in r)
r = build_report([F(severity="info", title=f"i{i}") for i in range(3)], [])
check("few info findings not collapsed", "<details>" not in r)

print("\n--- content completeness ---")
r = build_report(
    [F(title="SMB signing disabled", severity="high", port=445,
       cves=["CVE-2017-0144", "CVE-2017-0143"], cvss=9.8,
       evidence="signing:False", remediation="Enforce SMB signing",
       description="Relay attacks are possible.", confidence="confirmed",
       source="netexec")],
    [S(port=445, name="microsoft-ds", product="Samba", version="3.0.20")],
    scope="10.10.0.0/24", operator="analyst", live_hosts=["10.10.0.5"],
    stages=[{"name": "smb-enumeration", "ok": True, "skipped": False,
             "duration": 3.2, "findings": 1},
            {"name": "nuclei", "ok": True, "skipped": True,
             "reason": "nuclei not installed", "duration": 0}],
)
for label, needle in [
    ("scope in masthead", "10.10.0.0/24"),
    ("operator in masthead", "analyst"),
    ("finding title", "SMB signing disabled"),
    ("target host:port", "10.10.0.5:445"),
    ("description", "Relay attacks are possible."),
    ("evidence block", "signing:False"),
    ("remediation", "Enforce SMB signing"),
    ("source tool named", "netexec"),
    ("confidence stated", "confirmed"),
    ("confidence explained", "Verified against the target"),
    ("CVSS shown", "9.8"),
    ("both CVEs linked", "CVE-2017-0143"),
    ("NVD link built", "nvd.nist.gov/vuln/detail/CVE-2017-0144"),
    ("service inventory", "microsoft-ds"),
    ("product and version", "Samba 3.0.20"),
    ("stage that ran", "smb-enumeration"),
    ("stage that was skipped", "Not run"),
    ("skip reason given", "nuclei not installed"),
]:
    check(label, needle in r, needle[:30])

check("CVE links are safe", 'rel="noopener noreferrer"' in r)

print("\n--- CVE identifiers are validated before linking ---")
r = build_report([F(cves=["CVE-2017-0144"])], [])
check("valid CVE is linked", "nvd.nist.gov/vuln/detail/CVE-2017-0144" in r)
for junk in ["javascript:alert(1)", "<img onerror=x>", "../../../etc/passwd",
             "CVE-BAD", "https://evil.com", ""]:
    rr = build_report([F(cves=[junk])], [])
    if "nvd.nist.gov" in rr:
        check(f"junk CVE {junk[:20]!r} not linked", False, "linked!")
check("no junk CVE produces a link", True)
r = build_report([F(cves=["not-a-cve"])], [])
check("junk CVE still shown to the analyst", "not-a-cve" in r)

print("\n--- host risk table ---")
r = build_report([F(ip="10.0.0.1", severity="low"),
                  F(ip="10.0.0.2", severity="critical"),
                  F(ip="10.0.0.3", severity="medium")], [])
order = [r.index(f">10.0.0.{i}<") for i in (2, 3, 1)]
check("hosts ordered by worst severity first", order == sorted(order),
      str(order))

print("\n--- robustness against incomplete findings ---")
cases = {
    "no severity": {"ip": "10.0.0.1", "title": "t"},
    "no title": {"ip": "10.0.0.1", "severity": "high"},
    "no ip": {"title": "t", "severity": "high"},
    "unknown severity": {"ip": "10.0.0.1", "title": "t", "severity": "apocalyptic"},
    "None values": {"ip": None, "title": None, "severity": None, "evidence": None},
    "numeric fields as strings": {"ip": "10.0.0.1", "title": "t", "port": "445",
                                  "cvss": "9.8"},
    "empty cves list": {"ip": "10.0.0.1", "title": "t", "cves": []},
    "cves with empties": {"ip": "10.0.0.1", "title": "t", "cves": ["", None, "CVE-1"]},
}
survived = 0
for label, f in cases.items():
    try:
        out = build_report([f], [])
        assert out.rstrip().endswith("</html>")
        survived += 1
    except Exception as ex:
        check(f"survives {label}", False, f"{type(ex).__name__}: {ex}")
check(f"survives all {len(cases)} malformed findings", survived == len(cases))

check("services missing fields OK",
      build_report([], [{"ip": "10.0.0.1"}]).rstrip().endswith("</html>"))
check("stages missing fields OK",
      build_report([], [], stages=[{"name": "x"}]).rstrip().endswith("</html>"))

print("\n--- print and accessibility floor ---")
check("print stylesheet present", "@media print" in h)
check("page breaks avoided inside findings", "break-inside:avoid" in h)
check("link URLs expanded for print", 'a[href^="http"]::after' in h)
check("reduced motion respected", "prefers-reduced-motion" in h)
check("focus visible", "focus-visible" in h)
check("responsive breakpoint", "@media (max-width" in h)
check("table headers marked up", "<th>" in build_report([], [S()]))
check("tables captioned", "<caption>" in build_report([], [S()]))

print("\n--- file output ---")
d = Path(tempfile.mkdtemp())
p = write_report(d / "report.html", findings=[F()], services=[S()],
                 scope="10.0.0.0/24", operator="x")
check("file written", p.exists())
if sys.platform == "win32":
    check("file is 0600", True, "skipped on Windows — no POSIX modes")
else:
    check("file is 0600", oct(os.stat(p).st_mode & 0o777) == "0o600")
check("file is complete html", p.read_text().rstrip().endswith("</html>"))
check("report is a reasonable size", 8000 < p.stat().st_size < 300_000,
      str(p.stat().st_size))

print("\n--- scale ---")
import time
big_f = [F(ip=f"10.10.{i//254}.{i%254+1}", title=f"Finding {i}",
           severity=SEVERITY_ORDER[i % 5], evidence="x" * 400,
           cves=[f"CVE-2020-{1000+i}"]) for i in range(1500)]
big_s = [S(ip=f"10.10.{i//254}.{i%254+1}", port=80 + i % 100) for i in range(1500)]
t0 = time.time()
big = build_report(big_f, big_s)
dt = time.time() - t0
check(f"1500 findings render fast ({dt:.2f}s)", dt < 8, f"{dt:.2f}s")
check("large report complete", big.rstrip().endswith("</html>"))
check("all findings present", big.count('class="finding"') == 1500,
      str(big.count('class="finding"')))


print("\n--- console flavour must not reach the client ---")
# The interactive console reads like a cockpit. The report is the client's
# document and does not: a deliverable saying "HOSTILE CONTACT" instead of
# "unauthenticated Redis instance" is worse at its job. This asserts the
# boundary rather than trusting it.
from vision.core import ui as _ui

_flavour = (list(_ui.PHASE_CALLSIGN.values())
            + [sys_ for sys_, _st in _ui.BOOT_LINES]
            + [st for _sys, st in _ui.BOOT_LINES]
            + ["systems check"])
_doc = build_report(
    [{"ip": "10.0.0.5", "port": 6379,
      "title": "Redis exposed without authentication", "severity": "critical",
      "confidence": "confirmed", "cves": [], "source": "banner-analysis",
      "remediation": "Set requirepass and bind to a trusted interface."}],
    [{"ip": "10.0.0.5", "port": 6379, "proto": "tcp", "name": "redis"}],
    stages=[{"name": "port-scan", "skipped": False}])
_leaked = [t for t in _flavour if t and t in _doc]
check("no console callsign or boot text appears in the report",
      not _leaked, str(_leaked))
check("the report uses the real phase vocabulary",
      "Methodology" in _doc)
check("findings keep plain professional wording",
      "Redis exposed without authentication" in _doc)

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
