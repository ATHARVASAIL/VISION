"""Attack path correlation and retest diff tests.

The risk with a correlation engine is over-claiming: a chain that fires on
insufficient evidence produces a confident-sounding narrative about an
exploitation route that does not exist. Most of these tests are about that.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.analysis.correlate import (
    correlate, summary, CHAINS, ChainRule, Step,
    title_matches, has_cve, on_port, any_of, all_of,
)
from vision.analysis.diff import compare, fingerprint

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

def F(**kw):
    base = {"ip": "10.0.0.5", "port": 445, "title": "t", "severity": "medium",
            "confidence": "confirmed", "cves": [], "source": "test"}
    base.update(kw)
    return base

print("--- predicate builders ---")
check("title_matches hits", title_matches(r"SMB signing")(F(title="SMB signing not required")))
check("title_matches is case-insensitive", title_matches(r"smb SIGNING")(F(title="SMB signing")))
check("title_matches misses", not title_matches(r"nope")(F(title="SMB signing")))
check("title_matches handles missing title", not title_matches(r"x")({"ip": "1.1.1.1"}))
check("has_cve hits", has_cve("CVE-2017-0144")(F(cves=["CVE-2017-0144"])))
check("has_cve is case-insensitive", has_cve("cve-2017-0144")(F(cves=["CVE-2017-0144"])))
check("has_cve misses", not has_cve("CVE-2017-0144")(F(cves=["CVE-2020-1"])))
check("has_cve handles no cves", not has_cve("CVE-1")(F(cves=[])))
check("on_port hits", on_port(445, 139)(F(port=445)))
check("on_port misses", not on_port(445)(F(port=80)))
check("on_port handles missing port", not on_port(445)({"ip": "1.1.1.1"}))
check("any_of", any_of(title_matches("no"), title_matches("t"))(F(title="t")))
check("all_of", all_of(title_matches("t"), on_port(445))(F(title="t", port=445)))
check("all_of rejects partial", not all_of(title_matches("t"), on_port(80))(F(title="t", port=445)))

print("\n--- chains fire on real evidence ---")
cases = {
    "eternalblue-system": [F(cves=["CVE-2017-0144"], title="MS17-010", severity="critical")],
    "redis-rce": [F(title="Redis exposed without authentication", port=6379, severity="critical")],
    "snmp-to-config": [F(title="SNMP readable with default community 'public'", port=161)],
    "nfs-key-drop": [F(title="NFS exports world-readable", port=2049)],
    "tomcat-war-deploy": [F(title="Tomcat manager reachable", port=8080)],
    "anon-share-write": [F(title="SMB shares accessible without authentication",
                           evidence="backups (READ, WRITE)")],
    "smb-relay": [F(title="SMB signing not required"),
                  F(title="SMB shares accessible without authentication")],
    "secrets-to-data": [F(title="Environment file exposed", port=8080),
                        F(title="MySQL detected", port=3306, confidence="tentative")],
    "userenum-to-spray": [F(title="LDAP allows anonymous bind", port=389),
                          F(title="SSH open", port=22)],
    "cleartext-credential-capture": [
        F(title="Telnet exposed without transport encryption", port=23),
        F(ip="10.0.0.6", title="SSH", port=22)],
}
for rule_id, findings in cases.items():
    ids = {p.rule.id for p in correlate(findings)}
    check(f"{rule_id} fires", rule_id in ids, str(ids))

print("\n--- chains do NOT fire without their preconditions ---")
check("smb-relay needs both steps",
      "smb-relay" not in {p.rule.id for p in correlate([F(title="SMB signing not required")])})
check("secrets chain needs a database",
      "secrets-to-data" not in {p.rule.id for p in
                                correlate([F(title="Environment file exposed", port=8080)])})
check("read-only share is not a write chain",
      "anon-share-write" not in {p.rule.id for p in correlate(
          [F(title="SMB shares accessible without authentication",
             evidence="public (READ ONLY)")])})
check("no chains on an empty list", correlate([]) == [])
check("no chains on unrelated findings",
      correlate([F(title="SSH permits password authentication", severity="low")]) == [])

print("\n--- host scoping ---")
split = [F(ip="10.0.0.1", title="SMB signing not required"),
         F(ip="10.0.0.2", title="SMB shares accessible without authentication")]
ids = {p.rule.id for p in correlate(split)}
check("host-scoped chain does not span hosts", "smb-relay" not in ids or
      all(p.rule.scope == "network" for p in correlate(split) if p.rule.id == "smb-relay"))

same = [F(ip="10.0.0.1", title="SMB signing not required"),
        F(ip="10.0.0.1", title="SMB shares accessible without authentication")]
paths = [p for p in correlate(same) if p.rule.id == "smb-relay"]
check("chain fires within one host", len(paths) == 1)
check("path records the host", paths and paths[0].host == "10.0.0.1")

cross = [F(ip="10.0.0.1", title="Telnet exposed without transport encryption", port=23),
         F(ip="10.0.0.2", title="SSH", port=22)]
ids = {p.rule.id for p in correlate(cross)}
check("network-scoped chain may span hosts", "cleartext-credential-capture" in ids)

multi = [F(ip=f"10.0.0.{i}", title="Redis exposed without authentication", port=6379)
         for i in (1, 2, 3)]
check("one path per affected host",
      len([p for p in correlate(multi) if p.rule.id == "redis-rce"]) == 3)

print("\n--- confidence is capped by the weakest LOAD-BEARING link ---")
p = correlate([F(title="Environment file exposed", port=8080, confidence="confirmed"),
               F(title="MySQL 5.5", port=3306, confidence="tentative")])[0]
check("incidental context does not drag confidence down", p.confidence == "confirmed",
      p.confidence)
check("chain keeps its severity", p.severity == "critical", p.severity)

p = correlate([F(title="Environment file exposed", port=8080, confidence="tentative"),
               F(title="MySQL 5.5", port=3306, confidence="tentative")])[0]
check("tentative load-bearing step caps confidence", p.confidence == "tentative")
check("tentative chain capped to medium", p.severity == "medium", p.severity)

p = correlate([F(title="SMB signing not required", confidence="firm"),
               F(title="SMB shares accessible without authentication",
                 confidence="confirmed")])
relay = [x for x in p if x.rule.id == "smb-relay"][0]
check("firm weakest link -> firm chain", relay.confidence == "firm")
check("firm chain capped to high", relay.severity == "high", relay.severity)

p = correlate([F(cves=["CVE-2017-0144"], confidence="confirmed")])[0]
check("confirmed chain keeps critical", p.severity == "critical")

print("\n--- ordering and output shape ---")
mixed = [F(cves=["CVE-2017-0144"], confidence="confirmed"),
         F(ip="10.0.0.9", title="LDAP allows anonymous bind", port=389),
         F(ip="10.0.0.9", title="SSH", port=22)]
paths = correlate(mixed)
check("highest impact first", paths[0].rule.id == "eternalblue-system", paths[0].rule.id)
check("scores strictly ordered",
      all(paths[i].score >= paths[i+1].score for i in range(len(paths)-1)))

p = paths[0]
f = p.as_finding()
for key in ("ip", "title", "severity", "confidence", "description", "evidence",
            "remediation", "source"):
    check(f"as_finding has {key}", f.get(key) not in (None, ""), key)
check("as_finding source is namespaced", f["source"].startswith("correlation:"))
check("as_finding carries the chain in evidence", "Chain:" in f["evidence"])
check("as_finding states the outcome", "Outcome:" in f["description"])
check("as_finding severity matches the path", f["severity"] == p.severity)

s = summary(paths)
check("summary counts paths", s["paths"] == len(paths))
check("summary counts hosts", s["hosts"] >= 1)
check("summary breaks down by severity", isinstance(s["by_severity"], dict))

print("\n--- rule hygiene ---")
ids = [c.id for c in CHAINS]
check("no duplicate rule ids", len(set(ids)) == len(ids))
check("every rule has steps", all(c.steps for c in CHAINS))
check("every rule states an outcome", all(c.outcome for c in CHAINS))
check("every rule has remediation", all(len(c.remediation) > 30 for c in CHAINS))
check("every rule has a narrative", all(len(c.narrative) > 60 for c in CHAINS))
check("severities are valid",
      all(c.severity in ("low", "medium", "high", "critical") for c in CHAINS))
check("scopes are valid", all(c.scope in ("host", "network") for c in CHAINS))
check("references are https",
      all(str(r).startswith("https://") for c in CHAINS for r in c.references))

print("\n--- robustness ---")
junk = [{}, {"ip": None}, {"title": None, "cves": None},
        {"ip": "10.0.0.1", "cves": "not-a-list"}, {"port": "not-an-int"}]
try:
    correlate(junk)
    check("malformed findings do not crash correlation", True)
except Exception as ex:
    check("malformed findings do not crash correlation", False, str(ex))
check("non-dict entries ignored", correlate([None, "x", 42, F(cves=["CVE-2017-0144"])]))

exploding = ChainRule(id="boom", name="n", outcome="o", severity="high",
                      steps=(Step("s", lambda f: 1 / 0),), narrative="n" * 61,
                      remediation="r" * 31)
try:
    correlate([F()], rules=[exploding])
    check("a raising predicate is contained", True)
except ZeroDivisionError:
    check("a raising predicate is contained", False)

big = [F(ip=f"10.{i//65536}.{(i//256)%256}.{i%256}", title="Redis exposed without authentication",
         port=6379) for i in range(2000)]
import time
t0 = time.time(); correlate(big); dt = time.time() - t0
check(f"2000 findings correlate quickly ({dt:.2f}s)", dt < 10, f"{dt:.2f}s")

print("\n--- retest diff ---")
base = [F(ip="10.0.0.1", title="A", severity="high"),
        F(ip="10.0.0.2", title="B", severity="medium"),
        F(ip="10.0.0.3", title="C", severity="low")]
curr = [F(ip="10.0.0.2", title="B", severity="critical"),
        F(ip="10.0.0.3", title="C", severity="low"),
        F(ip="10.0.0.4", title="D", severity="high")]
d = compare(base, curr)
check("resolved detected", len(d.resolved) == 1 and d.resolved[0]["title"] == "A")
check("new detected", len(d.new) == 1 and d.new[0]["title"] == "D")
check("unchanged detected", len(d.unchanged) == 1 and d.unchanged[0]["title"] == "C")
check("worsened detected", len(d.worsened) == 1 and d.worsened[0][1]["title"] == "B")
check("remediation rate correct", abs(d.remediation_rate() - 33.33) < 0.1,
      f"{d.remediation_rate():.2f}")
check("regressions flag new high/critical", len(d.regressions) == 1)

d2 = compare([F(title="X", severity="critical")], [F(title="X", severity="low")])
check("improved detected", len(d2.improved) == 1)
check("improved is not counted as resolved", len(d2.resolved) == 0)

check("identical scans show no change",
      compare(base, base).counts == {"resolved": 0, "new": 0, "unchanged": 3,
                                     "worsened": 0, "improved": 0})
check("empty baseline means all new", len(compare([], curr).new) == 3)
check("empty current means all resolved", len(compare(base, []).resolved) == 3)
check("both empty is safe", compare([], []).counts["new"] == 0)
check("rate on empty baseline is 0", compare([], curr).remediation_rate() == 0.0)
check("full remediation is 100%", compare(base, []).remediation_rate() == 100.0)

print("\n--- diff fingerprint stability ---")
a = F(ip="10.0.0.1", port=445, cves=["CVE-2017-0144"], severity="high",
      confidence="firm", evidence="x", title="One wording")
b = F(ip="10.0.0.1", port=445, cves=["CVE-2017-0144"], severity="low",
      confidence="confirmed", evidence="totally different", title="Other wording")
check("identity survives re-rating and rewording", fingerprint(a) == fingerprint(b))
check("different host is a different finding",
      fingerprint(a) != fingerprint(F(ip="10.0.0.2", port=445, cves=["CVE-2017-0144"])))
check("different port is a different finding",
      fingerprint(a) != fingerprint(F(ip="10.0.0.1", port=139, cves=["CVE-2017-0144"])))
check("cve order does not matter",
      fingerprint(F(cves=["CVE-1", "CVE-2"])) == fingerprint(F(cves=["CVE-2", "CVE-1"])))
check("cve case does not matter",
      fingerprint(F(cves=["cve-2017-0144"])) == fingerprint(F(cves=["CVE-2017-0144"])))
check("no-cve findings fall back to title",
      fingerprint(F(cves=[], title="T")) == fingerprint(F(cves=[], title="t")))
check("malformed finding still fingerprints", isinstance(fingerprint({}), str))

d3 = compare([], [], baseline_hosts=["10.0.0.1"], current_hosts=["10.0.0.2"])
check("host added detected", d3.hosts_added == ["10.0.0.2"])
check("host removed detected", d3.hosts_removed == ["10.0.0.1"])

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
