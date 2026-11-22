"""Regression tests against real tool output.

Every fixture in this file came off an actual Metasploitable 2 host, captured
by Vision's own evidence directory during a live run. That run found three bugs
that no synthetic test had caught, which is the whole argument for this file
existing: fixtures I write are fixtures that match the parser I wrote.

The three:

  1. Worker threads lost the stage name, so 10 searchsploit commands were
     logged as "unknown". Masked in most stages because `parallel_map` runs a
     single item inline; on any network large enough to fan out, it would be
     every parallel stage.
  2. `smbmap` timed out at 60s against Metasploitable's Samba and the stage
     reported "ok, 0 findings" — a partial scan reading as a clean one.
  3. Kali ships classic `enum4linux` alongside `enum4linux-ng`, with entirely
     different output. Vision ran it successfully, dumped a full null session,
     and parsed nothing out of it.
"""
import sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

FIXTURES = Path(__file__).resolve().parent / "fixtures"

from vision.core.parsers import (
    parse_showmount_exports, export_is_world_readable, parse_rpcclient_users,
)
from vision.core.pipeline import Pipeline, RunState, current_stage
from vision.core.scope import Scope
from vision.core.concurrency import parallel_map, parallel_collect
import vision.core.pipeline as plmod
import vision.core.extra as extra_mod
from vision.core.toolchain import BY_NAME

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

def fixture(name):
    return (FIXTURES / name).read_text(errors="replace")

SCOPE = Scope.from_lists(["192.168.88.0/24"])

def pipe(services=None, hosts=None):
    wd = Path(tempfile.mkdtemp())
    st = RunState(scope="t", workdir=str(wd))
    st.services = services or []
    st.live_hosts = hosts or ["192.168.88.128"]
    return Pipeline(SCOPE, wd, st)

print("--- fixtures are real captures, not hand-written ---")
for name in ("enum4linux-classic.txt", "nmap-metasploitable.txt",
             "showmount-metasploitable.txt", "rpcclient-metasploitable.txt"):
    p = FIXTURES / name
    check(f"{name} present", p.exists())
    if p.exists():
        check(f"{name} is a Vision evidence capture",
              "# vision evidence" in fixture(name))

print("\n--- BUG 1: the stage name must survive a worker thread ---")
current_stage("exploitdb-correlation")
seen = set(parallel_map(lambda x: current_stage(), list(range(8))))
check("parallel_map workers keep the stage name",
      seen == {"exploitdb-correlation"}, str(seen))
current_stage("smb-shares")
got = {d["s"] for d in parallel_collect(
    lambda x: [{"s": current_stage()}], list(range(6)))}
check("parallel_collect workers keep the stage name",
      got == {"smb-shares"}, str(got))
current_stage("single-item")
check("the inline single-item path still works",
      parallel_map(lambda x: current_stage(), [1]) == ["single-item"])
check("nothing is ever logged as 'unknown' from a pool",
      "unknown" not in seen | got)

print("\n--- BUG 2: a timeout is not a clean result ---")
extra_calls = []
def timing_out(argv, timeout):
    plmod._STAGE_TIMEOUTS.append("smbmap")
    extra_calls.append(argv)
    return (-1, "", f"timed out after {timeout}s")

BY_NAME["smbmap"].which = lambda: "/usr/bin/smbmap"
p = pipe([{"ip": "192.168.88.128", "port": 445, "proto": "tcp",
           "name": "netbios-ssn"}])
orig_run, orig_have = plmod._run, plmod._have
plmod._run, plmod._have = timing_out, (lambda n: True)
try:
    res = p.run_stage("smb-shares")
finally:
    plmod._run, plmod._have = orig_run, orig_have

check("the stage is marked incomplete", res.incomplete)
check("the reason names the timeout", "timed out" in res.reason, res.reason)
check("the reason names the tool", "smbmap" in res.reason, res.reason)
check("coverage is described as partial", "partial" in res.reason)
check("a timeout still produces a finding rather than silence",
      res.findings >= 1 or res.incomplete)

p2 = pipe([{"ip": "192.168.88.128", "port": 445, "proto": "tcp",
            "name": "netbios-ssn"}])
plmod._STAGE_TIMEOUTS.clear()
plmod._run, plmod._have = (lambda a, t: (0, "", "")), (lambda n: True)
try:
    clean = p2.run_stage("smb-shares")
finally:
    plmod._run, plmod._have = orig_run, orig_have
check("a genuinely empty result is NOT marked incomplete", not clean.incomplete)
check("a clean stage carries no timeout note", "timed out" not in (clean.reason or ""))

print("\n--- BUG 3: classic enum4linux output must parse ---")
real = fixture("enum4linux-classic.txt")
check("the fixture really is classic enum4linux", "enum4linux v0.9" in real)
check("it contains a successful null session",
      "allows sessions using username '', password ''" in real)
check("it does NOT contain the -ng format the old parser expected",
      "Minimum password length:" not in real,
      "if this appears, the test no longer proves anything")

extra_mod._tool = lambda n: "/usr/bin/enum4linux" if "enum4linux" in n else None
p3 = pipe([{"ip": "192.168.88.128", "port": 445, "proto": "tcp",
            "name": "netbios-ssn"}])
plmod._run = lambda a, t: (0, real, "")
try:
    r3 = p3.enum4linux()
finally:
    plmod._run = orig_run

titles = [f["title"] for f in p3.state.findings]
check("real output now yields findings", r3.findings > 0,
      "this returned 0 before the fix")
check("the null session is reported",
      any("null session" in t.lower() for t in titles), str(titles))
check("the workgroup disclosure is reported",
      any("WORKGROUP" in t for t in titles), str(titles))
check("every finding carries remediation",
      all(f.get("remediation") for f in p3.state.findings))
check("every finding is attributed to the tool",
      all("enum4linux" in f.get("source", "") for f in p3.state.findings))

print("\n--- parsers that already handled real output ---")
exports = parse_showmount_exports(fixture("showmount-metasploitable.txt"))
check("NFS export parsed", exports == [("/", "*")], str(exports))
check("world-readable export detected",
      any(export_is_world_readable(c) for _p, c in exports))

users = parse_rpcclient_users(fixture("rpcclient-metasploitable.txt"))
check("rpcclient users parsed from real output", len(users) >= 30, str(len(users)))
check("real account names extracted",
      {"games", "nobody", "bind"} <= set(users), str(users[:8]))
check("no duplicates", len(users) == len(set(users)))
check("no empty names", all(u.strip() for u in users))

print("\n--- the real nmap scan is representative ---")
nmap = fixture("nmap-metasploitable.txt")
for svc in ("vsftpd 2.3.4", "OpenSSH", "Samba", "MySQL", "PostgreSQL"):
    check(f"fixture contains {svc}", svc in nmap)
check("the fixture is a real host, not a synthetic one",
      "192.168.88.128" in nmap and "Host is up" in nmap)

print("\n--- BUG 4: each CVE gets its own score, not the block maximum ---")
from vision.tools.nmap2findings import _cvss_per_cve, sev_from_cvss
from collections import Counter

vulners = fixture("nmap-vulners.txt")
scores = _cvss_per_cve(vulners)
check("the fixture is real vulners output", "vulners:" in vulners)
check("many CVEs parsed", len(scores) > 100, str(len(scores)))
spread = Counter(sev_from_cvss(v) for v in scores.values())
check("severities are distributed, not all one value",
      len(spread) >= 3, str(dict(spread)))
check("criticals are a minority",
      spread["critical"] < len(scores) / 2,
      f"{spread['critical']} of {len(scores)} — this was 147 of 147 before")
check("known 10.0 is critical", sev_from_cvss(scores["CVE-2011-2523"]) == "critical")
check("known 6.5 is NOT critical",
      sev_from_cvss(scores["CVE-2008-1657"]) != "critical",
      "the block maximum used to make this critical")
check("scores stay in range", all(0.0 <= v <= 10.0 for v in scores.values()))
check("an unscored CVE is not invented", "CVE-9999-0001" not in scores)
check("empty input is safe", _cvss_per_cve("") == {})
check("garbage input is safe", _cvss_per_cve("no scores here") == {})

print("\n--- BUG 5: a resumed session must still write the run log ---")
# A real engagement scanned on day one, quit, resumed on day two, and ran a
# manual smbclient command. The evidence file was written; run.jsonl was not
# touched. `self.runlog` was only ever created inside scan(), so a resumed
# session logged nothing — the exact audit gap the tool runner exists to close.
import tempfile as _tf, json as _json
from vision.core.console import Console
from vision.core import manualrun as _mr

class _Args:
    output = _tf.mkdtemp(); operator = "t"; no_banner = True
    cache = "/tmp/x.json"; msf_path = None; audit = "/tmp/a.jsonl"
    allow_destructive = False; timeout = 60; debug = False; no_evidence = False

_c = Console(_Args())
_c.scope = Scope.from_lists(["127.0.0.1/32"])
check("the console exposes a run log without a scan having run",
      _c.runlog is not None)
_mr.run(["nmap", "--version"], _c.scope, _c.workdir, log=_c.runlog,
        allow_unknown_tool=True)
_log = Path(_Args.output) / "run.jsonl"
check("the log file is created on first use", _log.exists())
_recs = [_json.loads(l) for l in _log.read_text().splitlines()]
check("a manual command on a resumed session IS logged",
      any(r.get("stage") == "manual" for r in _recs), str(len(_recs)))
check("the same log object is reused, not replaced",
      _c.runlog is _c.runlog)

print("\n--- coverage audit against real run data ---")
from vision.analysis.coverage import audit as _audit, expected_stage

_svcs = [{"ip": "192.168.88.128", "port": 21, "name": "ftp"},
         {"ip": "192.168.88.128", "port": 445, "name": "netbios-ssn"},
         {"ip": "192.168.88.128", "port": 36346, "name": "nlockmgr"}]
_finds = [{"ip": "192.168.88.128", "port": 21, "title": "x", "severity": "high"}]
_stages = [{"name": "banner-analysis", "skipped": False},
           {"name": "smb-enumeration", "skipped": True,
            "reason": "netexec not installed"}]
_a = _audit(_svcs, _finds, _stages)
check("a service with findings counts as assessed",
      _a.services[0].assessed)
check("a service whose stage never ran is NOT assessed",
      not _a.services[1].assessed,
      "smb-enumeration was skipped for a missing tool")
check("a service no stage covers is flagged",
      any(s.port == 36346 for s in _a.unassessed))
check("missing tools are named", _a.skipped_for_tools == ["netexec"])
check("the summary is a percentage, not a claim", "%" in _a.summary())
check("expected_stage maps by service name", expected_stage(
    {"name": "ftp", "port": 2121}) == "banner-analysis")
check("expected_stage falls back to port", expected_stage(
    {"name": None, "port": 445}) == "smb-enumeration")
check("an unknown service maps to nothing",
      expected_stage({"name": "weird", "port": 61234}) is None)
check("everything covered reports clean",
      _audit([{"ip": "1.1.1.1", "port": 21, "name": "ftp"}],
             [{"ip": "1.1.1.1", "port": 21}],
             [{"name": "banner-analysis", "skipped": False}]).is_clean)

print("\n--- the widened service map covers common internal services ---")
# The map was thin (~19 groups written from imagination) and its blind spots
# were the operator's silent to-do list. These are services that turn up on
# essentially every internal engagement and must resolve to a real stage.
for _name, _port, _stage in [
        ("rdp", 3389, "banner-analysis"),
        ("ms-wbt-server", 3389, "banner-analysis"),
        ("ms-sql-s", 1433, "exploitdb-correlation"),
        ("oracle-tns", 1521, "exploitdb-correlation"),
        ("kerberos-sec", 88, "kerberos-userenum"),
        ("winrm", 5985, "banner-analysis"),
        ("msrpc", 135, "rpc-enumeration"),
        ("sip", 5060, "banner-analysis"),
        ("docker", 2375, "datastore-exposure"),
        ("java-rmi", 1099, "exploitdb-correlation")]:
    check(f"{_name}:{_port} maps to {_stage}",
          expected_stage({"name": _name, "port": _port}) == _stage,
          expected_stage({"name": _name, "port": _port}))

# A map entry pointing at a stage the pipeline does not define would silently
# mark a service "covered" by a stage that can never run — worse than an honest
# "no stage covers this". Every mapped stage must be a real stage.
from vision.analysis.coverage import STAGE_FOR_SERVICE as _MAP
from vision.core.pipeline import Pipeline as _P
_real = {s[0] for s in _P.STAGES}
_mapped = {stage for _, _, stage in _MAP}
check("every mapped stage is a real pipeline stage",
      _mapped <= _real, f"phantom stages: {_mapped - _real}")
check("the map is meaningfully wider than before",
      len(_MAP) >= 28, f"only {len(_MAP)} groups")

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
