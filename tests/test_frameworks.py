"""Framework mapping and user rule tests.

The risk with framework mapping is over-claiming: an over-broad mapping makes
every finding look like it breaches everything, which is worse than no mapping.
Most of these tests check that mappings stay tight and that a rule file cannot
do anything other than describe patterns.
"""
import json, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.analysis.frameworks import (
    map_finding, coverage, summary, MAPPINGS, ATTACK, CIS, PCI, OWASP,
    FRAMEWORK_VERSIONS,
)
from vision.analysis.rules import (
    load_file, load_dir, all_chains, EXAMPLE_RULE,
    MAX_PATTERN, MAX_RULES_PER_FILE,
)
from vision.analysis.correlate import correlate, CHAINS

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

def F(**kw):
    base = {"ip": "10.0.0.5", "port": 445, "title": "t", "severity": "medium",
            "confidence": "confirmed", "cves": [], "source": "test"}
    base.update(kw); return base

ids = lambda f: {c.id for c in map_finding(f)}

print("--- mappings land on the right controls ---")
cases = [
    ("SMB signing not required", {"T1557.001", "4.1", "2.2"}),
    ("MS17-010 SMB remote code execution", {"T1210", "7.3", "6.3.3"}),
    ("SMB shares accessible without authentication", {"T1021.002", "3.3"}),
    ("Telnet exposed without transport encryption", {"T1040", "3.10", "4.2.1"}),
    ("SNMP readable with default community 'public'", {"T1082", "4.6"}),
    ("Environment file exposed", {"T1552.001", "A05:2021"}),
    ("Redis exposed without authentication", {"T1213", "4.8"}),
    ("HTTP security headers missing", {"A05:2021", "6.4.1"}),
    ("Directory listing enabled", {"A05:2021"}),
    ("TLS certificate expired 30 days ago", {"4.2.1", "A02:2021"}),
    ("Deprecated protocol TLSv1.0 enabled", {"4.2.1", "A02:2021"}),
    ("Public exploits available for vsftpd 2.3", {"T1210", "A06:2021"}),
    ("Tomcat manager reachable", {"T1190"}),
    ("IKE aggressive mode", {"T1133"}),
    ("NFS exports world-readable", {"T1213"}),
    ("SSH permits password authentication", {"T1110.003", "A07:2021"}),
    ("VNC service exposed", {"T1133", "13.4"}),
]
for title, expected in cases:
    got = ids(F(title=title))
    check(f"{title[:44]}", expected <= got, f"missing {expected - got}")

print("\n--- mappings stay tight (no over-claiming) ---")
check("unrelated finding is unmapped", map_finding(F(title="Something benign")) == [])
check("empty finding is unmapped", map_finding({}) == [])
check("no finding maps to everything",
      all(len(map_finding(F(title=t))) <= 6 for t, _ in cases),
      str(max((len(map_finding(F(title=t))), t) for t, _ in cases)))
check("TLS finding does not claim SMB controls",
      "T1557.001" not in ids(F(title="Deprecated protocol TLSv1.0 enabled")))
check("web finding does not claim patch controls",
      "6.3.3" not in ids(F(title="Directory listing enabled")))
check("SMB signing does not claim OWASP",
      not any(c.framework == "owasp" for c in map_finding(F(title="SMB signing not required"))))

print("\n--- deduplication ---")
f = F(title="Telnet exposed without transport encryption",
      description="Telnet exposed without transport encryption",
      evidence="Telnet exposed without transport encryption")
controls = map_finding(f)
check("repeated text does not duplicate controls",
      len(controls) == len({(c.framework, c.id) for c in controls}))

print("\n--- searching across all fields ---")
check("matches on description",
      ids(F(title="x", description="SMB signing not required")) >= {"T1557.001"})
check("matches on evidence",
      ids(F(title="x", evidence="Redis exposed without authentication")) >= {"T1213"})
check("handles None fields",
      map_finding({"title": None, "description": None, "evidence": None}) == [])

print("\n--- coverage ---")
data = [F(title=t) for t, _ in cases]

cov = coverage(data)
check("coverage groups by framework", set(cov) <= {"attack", "cis", "pci", "owasp"})
check("coverage counts findings per control",
      all(isinstance(n, int) and n >= 1 for v in cov.values() for _, n in v))
check("coverage sorts by frequency",
      all(v[i][1] >= v[i+1][1] for v in cov.values() for i in range(len(v)-1)))
check("coverage of nothing is empty", coverage([]) == {})

s = summary(data)
check("summary counts findings", s["findings"] == len(data))
check("summary counts mapped", s["mapped"] == len(data))
check("summary reports unmapped",
      summary(data + [F(title="benign")])["unmapped"] == 1)

print("\n--- control definitions are well formed ---")
all_controls = list(ATTACK.values()) + list(CIS.values()) + list(PCI.values()) + list(OWASP.values())
check("every control has an id", all(c.id for c in all_controls))
check("every control has a title", all(len(c.title) > 5 for c in all_controls))
check("no duplicate ids within a framework",
      all(len({c.id for c in d.values()}) == len(d)
          for d in (ATTACK, CIS, PCI, OWASP)))
check("urls are https where present",
      all(c.url.startswith("https://") for c in all_controls if c.url))
check("ATT&CK ids are well formed",
      all(c.id.startswith("T") and c.id[1:].replace(".", "").isdigit()
          for c in ATTACK.values()))
check("framework versions documented", set(FRAMEWORK_VERSIONS) == {"attack", "cis", "pci", "owasp"})
check("every mapping has controls", all(m.controls for m in MAPPINGS))
check("every mapping has a note", all(len(m.note) > 20 for m in MAPPINGS))
check("every mapping pattern compiles",
      all(map_finding(F(title="probe")) is not None for _ in [1]))

print("\n--- user rules load ---")
d = Path(tempfile.mkdtemp())
(d / "ok.json").write_text(json.dumps(EXAMPLE_RULE))
r = load_file(d / "ok.json")
check("example rule loads", len(r.chains) == 1 and not r.errors, str(r.errors))
rule = r.chains[0]
check("id preserved", rule.id == "example.legacy-appliance")
check("severity preserved", rule.severity == "high")
check("steps built", len(rule.steps) == 2)
check("load_bearing honoured",
      rule.steps[0].load_bearing and not rule.steps[1].load_bearing)
check("references kept", rule.references and rule.references[0].startswith("https://"))

f = [F(ip="10.0.0.5", port=443, title="Outdated ApplianceOS 3.1", severity="high")]
paths = correlate(f, rules=r.chains)
check("custom rule fires end to end", len(paths) == 1)
check("custom chain reports its severity", paths and paths[0].severity == "high")
check("contextual step may reuse the same finding",
      paths and len(paths[0].matched_steps) == 2)

print("\n--- a chain still needs distinct evidence per load-bearing step ---")
strict = {"chains": [{"id": "strict.two", "severity": "high",
                      "steps": [{"title": "Outdated"}, {"title": "Outdated"}]}]}
(d / "strict.json").write_text(json.dumps(strict))
sr = load_file(d / "strict.json")
check("two load-bearing steps need two findings",
      len(correlate(f, rules=sr.chains)) == 0)
check("two findings satisfy it",
      len(correlate(f + [F(ip="10.0.0.5", title="Outdated other thing")],
                    rules=sr.chains)) == 1)

print("\n--- malformed rules are reported, never fatal ---")
bad = {"chains": [
    {"id": "good.one", "steps": [{"title": "x"}], "severity": "high"},
    {"id": "BAD ID", "steps": [{"title": "x"}]},
    {"id": "no.steps"},
    {"id": "bad.sev", "steps": [{"title": "x"}], "severity": "apocalyptic"},
    {"id": "bad.scope", "steps": [{"title": "x"}], "scope": "galaxy"},
    {"id": "bad.regex", "steps": [{"title": "[unclosed"}]},
    {"id": "empty.step", "steps": [{"label": "x"}]},
    {"id": "steps.not.list", "steps": "nope"},
    {"id": "bad.port", "steps": [{"port": "not-a-number"}]},
    "not even a mapping",
]}
(d / "bad.json").write_text(json.dumps(bad))
br = load_file(d / "bad.json")
check("valid rule survives a bad file", [c.id for c in br.chains] == ["good.one"])
check("every bad rule reported", len(br.errors) == 9, str(len(br.errors)))
check("errors name the file", all("bad.json" in e for e in br.errors))
check("errors explain the problem", all(len(e) > 25 for e in br.errors))

(d / "notjson.json").write_text("{ this is not json")
check("unparseable file reports an error", load_file(d / "notjson.json").errors)
check("unparseable file yields no chains", not load_file(d / "notjson.json").chains)
check("missing file reports an error", load_file(d / "nope.json").errors)
(d / "notalist.json").write_text('{"chains": {"id": "x"}}')
check("wrong top-level shape reported", load_file(d / "notalist.json").errors)

print("\n--- rule files are data, never code ---")
evil = {"chains": [{"id": "evil.one", "severity": "high",
                    "steps": [{"title": "x"}],
                    "match": "__import__('os').system('id')",
                    "narrative": "<script>alert(1)</script>",
                    "remediation": "\x1b[2Jfake",
                    "references": ["javascript:alert(1)", "https://ok.example"]}]}
(d / "evil.json").write_text(json.dumps(evil))
er = load_file(d / "evil.json")
check("unknown fields ignored", len(er.chains) == 1)
check("no code field is honoured", not hasattr(er.chains[0], "match"))
check("narrative is sanitised of escapes", "\x1b" not in er.chains[0].narrative)
check("remediation sanitised", "\x1b" not in er.chains[0].remediation)
check("non-https references dropped",
      list(er.chains[0].references) == ["https://ok.example"])

huge = {"chains": [{"id": "big.one", "severity": "high",
                    "steps": [{"title": "a" * (MAX_PATTERN + 10)}]}]}
(d / "huge.json").write_text(json.dumps(huge))
check("oversized pattern rejected", load_file(d / "huge.json").errors)

many = {"chains": [{"id": f"r.{i}", "severity": "low", "steps": [{"title": "x"}]}
                   for i in range(MAX_RULES_PER_FILE + 1)]}
(d / "many.json").write_text(json.dumps(many))
check("too many rules rejected", load_file(d / "many.json").errors)

print("\n--- directory loading ---")
dd = Path(tempfile.mkdtemp())
(dd / "a.json").write_text(json.dumps({"chains": [
    {"id": "a.one", "severity": "low", "steps": [{"title": "x"}]}]}))
(dd / "b.json").write_text(json.dumps({"chains": [
    {"id": "b.one", "severity": "low", "steps": [{"title": "y"}]}]}))
(dd / "ignored.txt").write_text("not a rule file")
res = load_dir(dd)
check("all rule files loaded", {c.id for c in res.chains} == {"a.one", "b.one"})
check("non-rule files ignored", not res.errors)
check("missing directory is not an error", not load_dir(Path("/nonexistent")).errors)

print("\n--- built-in plus custom ---")
chains, errors = all_chains([str(d / "ok.json")])
builtin_ids = {c.id for c in CHAINS}
check("built-ins retained", builtin_ids <= {c.id for c in chains})
check("custom rule added", "example.legacy-appliance" in {c.id for c in chains})
check("no duplicate ids", len({c.id for c in chains}) == len(chains))

override = {"chains": [{"id": "redis-rce", "name": "Our own wording",
                        "severity": "high", "steps": [{"title": "Redis"}]}]}
(d / "override.json").write_text(json.dumps(override))
chains2, _ = all_chains([str(d / "override.json")])
redis = [c for c in chains2 if c.id == "redis-rce"]
check("custom rule overrides a built-in of the same id", len(redis) == 1)
check("override takes effect", redis[0].name == "Our own wording")

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
