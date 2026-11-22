#!/usr/bin/env python3
"""CVSS v3.1 base-vector parsing and scoring."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vision.analysis.cvss import parse, try_parse, severity_for, Cvss, CvssError
from vision.core.schema import Finding, Severity, Proto

fails = []


def check(label, cond, detail=""):
    if cond:
        print(f"PASS  {label}")
    else:
        msg = f"FAIL  {label}"
        if detail:
            msg += f"  [{detail}]"
        print(msg)
        fails.append(label)


print("--- official FIRST v3.1 reference vectors score exactly ---")
# Each of these vectors has a published base score. If our arithmetic drifts by
# even 0.1 the number in a client report is wrong, so these are exact matches.
REFERENCE = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "high"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "high"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, "low"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium"),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 3.5, "low"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8, "high"),
    ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 5.4, "medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "medium"),
]
for vec, score, sev in REFERENCE:
    c = parse(vec)
    check(f"{vec} scores {score}", abs(c.base_score - score) < 0.001,
          f"got {c.base_score}")
    check(f"{vec} is {sev}", c.severity == sev, f"got {c.severity}")

print("\n--- scope change materially raises the score ---")
# Same impact/exploitability, scope Unchanged vs Changed — Changed must score
# higher, which is the whole point of the scope metric.
_u = parse("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N").base_score
_c = parse("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N").base_score
check("scope-changed outscores scope-unchanged", _c > _u, f"{_c} vs {_u}")

print("\n--- canonical vector round-trips ---")
for vec, _, _ in REFERENCE:
    c = parse(vec)
    check(f"round-trip {vec}", parse(c.vector).base_score == c.base_score)
    check(f"canonical form is prefixed {vec}", c.vector.startswith("CVSS:3.1/"))

print("\n--- non-canonical input is accepted and canonicalised ---")
_bare = parse("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
check("bare metric body parses", _bare.base_score == 9.8)
check("bare body gains the CVSS:3.1 prefix", _bare.vector.startswith("CVSS:3.1/"))
_v30 = parse("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
check("v3.0 vector parses (identical base equations)", _v30.base_score == 9.8)
check("v3.0 version is preserved", _v30.version == "3.0")

print("\n--- malformed vectors are REJECTED, never guessed ---")
# A wrong CVSS number is worse than none. Everything invalid must raise.
BAD = {
    "empty": "",
    "garbage": "not a vector at all",
    "incomplete": "CVSS:3.1/AV:N/AC:L",
    "bad value": "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "duplicate metric": "CVSS:3.1/AV:N/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H",
    "temporal metric (not base)":
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F",
    "environmental metric (not base)":
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H",
    "missing value": "CVSS:3.1/AV:/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
}
for why, vec in BAD.items():
    raised = False
    try:
        parse(vec)
    except CvssError:
        raised = True
    check(f"rejects {why}", raised, f"did not reject {vec!r}")

print("\n--- try_parse never raises, returns None on bad input ---")
check("try_parse(None) is None", try_parse(None) is None)
check("try_parse('') is None", try_parse("") is None)
check("try_parse(garbage) is None", try_parse("nonsense") is None)
check("try_parse(valid) returns a Cvss",
      isinstance(try_parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), Cvss))

print("\n--- severity bands match the v3.1 qualitative scale ---")
for score, band in [(0.0, "none"), (0.1, "low"), (3.9, "low"), (4.0, "medium"),
                    (6.9, "medium"), (7.0, "high"), (8.9, "high"),
                    (9.0, "critical"), (10.0, "critical")]:
    check(f"score {score} is {band}", severity_for(score) == band,
          f"got {severity_for(score)}")

print("\n--- a Finding derives score and severity from its vector ---")
_f = Finding(ip="10.0.0.5", title="RCE", port=445, proto=Proto.TCP,
             cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
check("vector sets the numeric score", _f.cvss == 9.8)
check("vector sets the severity", _f.severity is Severity.CRITICAL)
check("vector is canonicalised on the finding",
      _f.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

_bad_f = Finding(ip="10.0.0.5", title="x", cvss_vector="CVSS:3.1/AV:GARBAGE")
check("a malformed vector is dropped, not carried", _bad_f.cvss_vector is None)
check("and it sets no score", _bad_f.cvss is None)

_both = Finding(ip="10.0.0.5", title="x", cvss=5.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
check("an explicit score is not overwritten by the vector", _both.cvss == 5.0)
check("but the vector is still recorded", _both.cvss_vector is not None)

print("\n--- the report renders the vector beside the score ---")
from vision.report.html import build_report
_h = build_report([{
    "ip": "10.0.0.5", "port": 445, "title": "RCE", "severity": "critical",
    "confidence": "confirmed", "cvss": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "source": "test"}], [])
check("the vector string appears in the report",
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in _h)
check("the report still renders", _h.rstrip().endswith("</html>"))

print("\n" + "=" * 50)
print(f"{'ALL PASS' if not fails else 'FAILURES: ' + ', '.join(fails)}")
sys.exit(1 if fails else 0)
