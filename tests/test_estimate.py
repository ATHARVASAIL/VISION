"""Runtime estimation and finding-volume control.

Two problems from a real 50-minute Metasploitable run:

  * 456 findings on ONE host, 414 of them from nmap's vulners script — 163 for
    a single PostgreSQL service. Every one had the same remediation. That is a
    report nobody reads.
  * No way to know beforehand that the run would take 50 minutes, or that
    nuclei would be two thirds of it.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

FIXTURES = Path(__file__).resolve().parent / "fixtures"

from vision.core.estimate import (
    estimate, describe, human, STAGE_COST, STAGE_PARALLELISM, INTENSITY_FACTOR,
)
from vision.core.pipeline import Pipeline
from vision.tools.nmap2findings import parse

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

ALL = [n for n, _ in Pipeline.STAGES]

print("--- estimates are grounded in a measured run ---")
# Reference: 32 stages, 1 host, 22 services, normal intensity, 49.7 min actual.
e = estimate(ALL, hosts=1, services=22, intensity="normal")
check("the measured run falls inside the predicted band",
      e.low <= 49.7 * 60 <= e.high,
      f"predicted {e.range_text()}, actual 49.7 min")
check("a range is given, not a single number", "–" in e.range_text())
check("the estimate is non-zero", e.seconds > 0)

print("\n--- host parallelism is modelled, not linear ---")
# Scaling linearly gave 197 hours for a /24. nmap parallelises internally and
# the enrichment stages run through a bounded pool.
one = estimate(ALL, hosts=1, intensity="normal").seconds
many = estimate(ALL, hosts=254, intensity="normal").seconds
check("254 hosts is not 254x one host", many < one * 60, f"{many / one:.0f}x")
check("but it is meaningfully longer", many > one * 2, f"{many / one:.1f}x")
check("a /24 stays within a working week",
      many < 40 * 3600, human(many))
check("every parallel stage has a worker count",
      all(STAGE_PARALLELISM.get(s, 0) >= 1
          for s in ("port-scan", "smb-shares", "nuclei", "tls-deep")))

print("\n--- intensity changes the estimate sensibly ---")
st = estimate(ALL, hosts=10, intensity="stealth").seconds
no = estimate(ALL, hosts=10, intensity="normal").seconds
ag = estimate(ALL, hosts=10, intensity="aggressive").seconds
check("stealth is the slowest", st > no)
check("aggressive is slower than normal", ag > no)
check("stealth is slower than aggressive — quiet costs time", st > ag)
check("factors are all positive", all(v > 0 for v in INTENSITY_FACTOR.values()))

print("\n--- the expensive stages are named ---")
lines = describe(estimate(ALL, hosts=254, intensity="normal"))
check("a headline figure is given", "estimated" in lines[0])
check("dominant stages are called out", len(lines) > 1)
check("each names how to skip it",
      all("--skip" in l for l in lines[1:]), str(lines[1:]))
check("shares are percentages", any("%" in l for l in lines[1:]))

print("\n--- fewer stages means less time ---")
quick = estimate(sorted(Pipeline.QUICK), hosts=1).seconds
full = estimate(ALL, hosts=1).seconds
check("a quick scan is much faster", quick < full / 3, f"{quick:.0f}s vs {full:.0f}s")
check("skipping the biggest stage helps",
      estimate([s for s in ALL if s != "nuclei"], hosts=1).seconds < full)

print("\n--- formatting ---")
check("seconds under 90 stay seconds", human(45) == "45s")
check("minutes are rounded", human(300) == "5 min")
check("hours appear for long runs", "hr" in human(20000))
check("zero is safe", human(0) == "0s")
check("negative is safe", human(-10) == "0s")

print("\n--- every stage has a cost entry or a sane default ---")
missing = [s for s in ALL if s not in STAGE_COST]
check("all registered stages are costed", not missing, str(missing))
check("no stage costs nothing at all",
      all(sum(STAGE_COST[s]) > 0 for s in ALL if s in STAGE_COST))

print("\n--- vulners findings collapse to one per service ---")
xml = FIXTURES / "nmap-vulners-full.xml"
if not xml.exists():
    check("vulners fixture present (skipped)", True)
else:
    data = parse(str(xml))
    v = [f for f in data["findings"] if "vulners" in f.get("source", "")]
    check("vulners produced findings", v)
    check("one finding per service, not per CVE",
          len(v) <= 12, f"{len(v)} findings — was 414 before aggregation")
    biggest = max(v, key=lambda f: len(f.get("cves") or []))
    check("the full CVE list is preserved for the advisor",
          len(biggest["cves"]) > 50, str(len(biggest["cves"])))
    check("the title states how many CVEs",
          "known CVEs" in biggest["title"], biggest["title"][:60])
    check("the worst CVE is named", "worst" in biggest["title"])
    check("severity comes from the worst score",
          biggest["severity"] in ("critical", "high"))
    check("a single-CVE service still reads naturally",
          any(f["title"].startswith("CVE-") for f in v if len(f["cves"]) == 1))
    check("every aggregate carries remediation",
          all(f.get("remediation") for f in v))
    check("remediation warns about distro backports",
          any("backport" in f.get("remediation", "") for f in v))
    check("no duplicate service entries",
          len({(f["ip"], f["port"]) for f in v}) == len(v))

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
