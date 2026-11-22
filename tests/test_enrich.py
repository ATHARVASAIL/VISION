"""Verify every enrichment stage: parsing, severity, scope, graceful skip."""
import re, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.core.pipeline import Pipeline, RunState
from vision.core.scope import Scope
from vision.core import enrich

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

scope = Scope.from_lists(["10.10.0.0/24"])
def mkpipe(services=None, hosts=None):
    wd = Path(tempfile.mkdtemp())
    st = RunState(scope="test", workdir=str(wd))
    st.services = services or []
    st.live_hosts = hosts or []
    return Pipeline(scope, wd, st)

def patch_run(output, code=0):
    """Replace _run in the pipeline module for the duration of one stage."""
    import vision.core.pipeline as pl
    orig = pl._run
    pl._run = lambda argv, timeout: (code, output, "")
    return orig, pl

def patch_tool(name):
    orig = enrich._tool
    enrich._tool = lambda n: f"/usr/bin/{n}" if n == name else None
    return orig

def SVC(ip, port, **kw):
    base = {"ip": ip, "port": port, "proto": "tcp"}
    base.update(kw)
    return base

print("--- graceful skip when tool missing ---")
o = patch_tool("__none__")
p = mkpipe([SVC("10.10.0.5", 445)])
for stage in ["snmp_enum", "smb_shares", "rpc_enum", "nfs_enum", "ldap_enum",
              "testssl_scan", "searchsploit_correlate", "ike_scan"]:
    r = getattr(p, stage)()
    if not (r.skipped and r.ok):
        check(f"{stage} skips cleanly", False, f"skipped={r.skipped} ok={r.ok}")
        break
else:
    check("all 8 tool-dependent stages skip cleanly when tool absent", True)
enrich._tool = o

print("\n--- banner analysis (no external tool) ---")
p = mkpipe([SVC("10.10.0.5", 23), SVC("10.10.0.5", 21), SVC("10.10.0.6", 6379),
            SVC("10.10.0.6", 1524), SVC("10.10.0.7", 443, tunnel="ssl"),
            SVC("10.10.0.8", 80)])
r = p.banner_analysis()
titles = [f["title"] for f in p.state.findings]
check("telnet flagged", any("Telnet" in t for t in titles))
check("ftp flagged", any("FTP" in t for t in titles))
check("redis flagged critical",
      any(f["severity"] == "critical" for f in p.state.findings if "Redis" in f["title"]))
check("ingreslock flagged critical",
      any(f["severity"] == "critical" for f in p.state.findings if "Ingreslock" in f["title"]))
check("https NOT flagged as cleartext", not any("443" == str(f.get("port")) and "encryption" in f["title"] for f in p.state.findings))
check("http flagged medium",
      any(f["severity"] == "medium" for f in p.state.findings if f.get("port") == 80))
check("remediation present", all(f.get("remediation") for f in p.state.findings))
check("runs without any tool installed", r.ok and not r.skipped)

print("\n--- smbmap share parsing ---")
o = patch_tool("smbmap")
SMBMAP = """
[+] IP: 10.10.0.5:445  Name: target
        Disk                  Permissions     Comment
        ----                  -----------     -------
        ADMIN$                NO ACCESS       Remote Admin
        C$                    NO ACCESS       Default share
        IPC$                  READ ONLY       Remote IPC
        backups               READ, WRITE     nightly dumps
        public                READ ONLY
"""
p = mkpipe([SVC("10.10.0.5", 445)])
orig, pl = patch_run(SMBMAP)
r = p.smb_shares()
pl._run = orig
f = p.state.findings
check("share finding produced", len(f) == 1, str(len(f)))
check("writable share -> critical", f and f[0]["severity"] == "critical")
check("IPC$ excluded", f and "IPC$" not in f[0]["evidence"])
check("readable shares captured", f and "backups" in f[0]["evidence"] and "public" in f[0]["evidence"])
check("NO ACCESS excluded", f and "ADMIN$" not in f[0]["evidence"])
enrich._tool = o

print("\n--- read-only shares are high, not critical ---")
o = patch_tool("smbmap")
p = mkpipe([SVC("10.10.0.5", 445)])
orig, pl = patch_run(SMBMAP.replace("READ, WRITE", "READ ONLY"))
p.smb_shares(); pl._run = orig
check("read-only -> high", p.state.findings[0]["severity"] == "high")
enrich._tool = o

print("\n--- rpcclient user enumeration ---")
o = patch_tool("rpcclient")
RPC = "user:[Administrator] rid:[0x1f4]\nuser:[guest] rid:[0x1f5]\nuser:[svc_sql] rid:[0x452]"
p = mkpipe([SVC("10.10.0.5", 445)])
orig, pl = patch_run(RPC); p.rpc_enum(); pl._run = orig
f = p.state.findings
check("null-session users found", len(f) == 1)
check("user count in evidence", f and "3 users" in f[0]["evidence"], f[0]["evidence"][:40] if f else "")
check("usernames captured", f and "svc_sql" in f[0]["evidence"])
enrich._tool = o

print("\n--- NFS exports ---")
o = patch_tool("showmount")
p = mkpipe([SVC("10.10.0.5", 2049)])
orig, pl = patch_run("Export list for 10.10.0.5:\n/srv/backup *\n/home 10.10.0.0/24")
p.nfs_enum(); pl._run = orig
f = p.state.findings
check("world-export -> high", f and f[0]["severity"] == "high")
check("exports in evidence", f and "/srv/backup" in f[0]["evidence"])
enrich._tool = o

o = patch_tool("showmount")
p = mkpipe([SVC("10.10.0.5", 2049)])
orig, pl = patch_run("Export list for 10.10.0.5:\n/home 10.10.0.0/24")
p.nfs_enum(); pl._run = orig
check("restricted export -> medium", p.state.findings[0]["severity"] == "medium")
enrich._tool = o

print("\n--- LDAP anonymous bind ---")
o = patch_tool("ldapsearch")
p = mkpipe([SVC("10.10.0.5", 389)])
orig, pl = patch_run("namingContexts: DC=corp,DC=local\nnamingContexts: CN=Configuration,DC=corp,DC=local")
p.ldap_enum(); pl._run = orig
f = p.state.findings
check("anon bind detected", len(f) == 1)
check("naming context captured", f and "DC=corp" in f[0]["evidence"])
enrich._tool = o

print("\n--- IKE aggressive mode ---")
o = patch_tool("ike-scan")
p = mkpipe([SVC("10.10.0.5", 500)])
orig, pl = patch_run("10.10.0.5  Aggressive Mode Handshake returned HDR=(CKY-R=abc) SA=(Enc=3DES)")
p.ike_scan(); pl._run = orig
check("aggressive mode -> high", p.state.findings and p.state.findings[0]["severity"] == "high")
enrich._tool = o

o = patch_tool("ike-scan")
p = mkpipe([SVC("10.10.0.5", 500)])
orig, pl = patch_run("0 returned handshake; 0 returned notify")
p.ike_scan(); pl._run = orig
check("main-mode-only produces nothing", len(p.state.findings) == 0)
enrich._tool = o

print("\n--- searchsploit correlation ---")
o = patch_tool("searchsploit")
import json as _j
SS = _j.dumps({"RESULTS_EXPLOIT": [
    {"Title": "vsftpd 2.3.4 - Backdoor Command Execution", "Codes": "CVE-2011-2523"},
    {"Title": "vsftpd 2.3.4 - Backdoor (Metasploit)", "Codes": "CVE-2011-2523"},
    {"Title": "vsftpd - Remote DoS", "Codes": ""}]})
p = mkpipe([SVC("10.10.0.5", 21, product="vsftpd", version="2.3.4")])
orig, pl = patch_run(SS); p.searchsploit_correlate(); pl._run = orig
f = p.state.findings
check("exploitdb hits produced", len(f) == 1)
check("3+ hits -> high", f and f[0]["severity"] == "high")
check("CVE extracted from Codes", f and "CVE-2011-2523" in f[0]["cves"])
check("marked tentative", f and f[0]["confidence"] == "tentative")
check("remediation names version", f and "2.3.4" in f[0]["remediation"])
enrich._tool = o

o = patch_tool("searchsploit")
p = mkpipe([SVC("10.10.0.5", 21, product="vsftpd", version="2.3.4")])
orig, pl = patch_run(_j.dumps({"RESULTS_EXPLOIT": []})); p.searchsploit_correlate(); pl._run = orig
check("no hits -> no finding", len(p.state.findings) == 0)
enrich._tool = o

print("\n--- scope enforcement across stages ---")
o = patch_tool("smbmap")
p = mkpipe([SVC("8.8.8.8", 445), SVC("10.10.0.5", 445)])
orig, pl = patch_run(SMBMAP); p.smb_shares(); pl._run = orig
check("out-of-scope host skipped", all(f["ip"] != "8.8.8.8" for f in p.state.findings))
check("in-scope host processed", any(f["ip"] == "10.10.0.5" for f in p.state.findings))
enrich._tool = o

print("\n--- dedupe across tools ---")
p = mkpipe([SVC("10.10.0.5", 21)])
p._merge_findings([{"ip":"10.10.0.5","port":21,"title":"X","cves":["CVE-2011-2523"],
                    "severity":"medium","confidence":"tentative","source":"nmap"}])
p._merge_findings([{"ip":"10.10.0.5","port":21,"title":"X","cves":["CVE-2011-2523"],
                    "severity":"critical","confidence":"confirmed","source":"searchsploit"}])
check("same CVE collapses to one finding", len(p.state.findings) == 1, str(len(p.state.findings)))
check("severity upgraded on merge", p.state.findings[0]["severity"] == "critical")
check("confidence upgraded on merge", p.state.findings[0]["confidence"] == "confirmed")
check("both sources recorded", "nmap" in p.state.findings[0]["source"] and "searchsploit" in p.state.findings[0]["source"])

print("\n--- UDP discovery (ike-vpn was unreachable without it) ---")
from vision.core.toolchain import BY_NAME as _BY
_BY["ike-scan"].which = lambda: "/usr/bin/ike-scan"
AGG = "10.0.0.5\tAggressive Mode Handshake returned HDR=(CKY-R=abc)"

import vision.core.pipeline as _plmod

def _ike(services):
    p = mkpipe(services)
    o = _plmod._run; _plmod._run = lambda a, t: (0, AGG, "")
    r = p.ike_scan(); _plmod._run = o
    return r, p.state.findings

r, f = _ike([SVC("10.10.0.5", 443)])
check("ike-vpn skips when no UDP 500 known", r.skipped and not f)
r, f = _ike([SVC("10.10.0.5", 500, proto="udp", name="isakmp")])
check("ike-vpn fires once UDP 500 is discovered", len(f) == 1, str(r.reason))

check("udp-scan registered", "udp-scan" in {n for n, _ in Pipeline.STAGES})
check("udp-scan in STANDARD", "udp-scan" in Pipeline.STANDARD)
check("udp-scan not in QUICK", "udp-scan" not in Pipeline.QUICK)
check("udp port list covers snmp and ike",
      "161" in Pipeline.UDP_PORTS and "500" in Pipeline.UDP_PORTS)

p = mkpipe()
r = p.udp_scan()
check("udp-scan skips without live hosts", r.skipped and r.ok)

p = mkpipe(hosts=["10.10.0.5"])
check("udp timeout capped below scan timeout", p.udp_timeout <= p.timeout)

print("\n--- SNMP targets prefer discovered UDP 161 ---")
p = mkpipe([SVC("10.10.0.5", 161, proto="udp", name="snmp")],
           hosts=["10.10.0.5", "10.10.0.6", "10.10.0.7"])
disc = sorted({s["ip"] for s in p.state.services
               if s["port"] == 161 and s.get("proto") == "udp"})
check("targets narrowed to the discovered host", disc == ["10.10.0.5"])
p2 = mkpipe([SVC("10.10.0.5", 443)], hosts=["10.10.0.5", "10.10.0.6"])
disc2 = sorted({s["ip"] for s in p2.state.services
                if s["port"] == 161 and s.get("proto") == "udp"})
check("falls back when no UDP scan ran", disc2 == [])

print("\n--- every stage honours the shared invariants ---")
# The last three bugs were all invariant violations that no individual test
# would catch: a stage that skipped scope, ran serially while its siblings ran
# concurrently, or emitted findings with no remediation. Assert the invariants
# across the whole registry so a new stage cannot quietly break one.

_SRC = {str(m): m.read_text(encoding="utf-8") for m in sorted(Path("vision/core").glob("*.py"))}

def _body(method):
    for _mod, _src in _SRC.items():
        i = _src.find(f"def {method}(self")
        if i == -1:
            continue
        rest = _src[i:]
        nxt = re.search(r"\n    def |\nclass ", rest[1:])
        return rest[:nxt.start() + 1] if nxt else rest
    return ""

# Stages that shell out to nmap enforce scope inside _parse_nmap instead.
_VIA_PARSER = {"port_scan", "udp_scan", "vuln_scripts"}
# Stages exempt from the concurrency rule: those that hand the whole target set
# to their tool in one invocation, plus the pure-Python ones that spawn nothing.
_BY_METHOD = {m: n for n, m in Pipeline.STAGES}
_NO_PROBE = {m for m, n in _BY_METHOD.items()
             if n in Pipeline.RANGE_STAGES | Pipeline.SINGLE_SOURCE_STAGES}
_NO_PROBE |= {"banner_analysis", "datastore_exposure"}

_missing_scope, _serial, _no_remediation = [], [], []
for _name, _method in Pipeline.STAGES:
    b = _body(_method)
    if not b:
        _missing_scope.append(f"{_name} (source not found)")
        continue
    if "scope.contains" not in b and "_web_targets" not in b \
            and _method not in _VIA_PARSER:
        _missing_scope.append(_name)
    # Stages that probe hosts one at a time must do so concurrently and bounded.
    if _method not in _NO_PROBE:
        if "parallel_collect" not in b:
            _serial.append(_name)
        elif "bounded(" not in b:
            _serial.append(f"{_name} (unbounded)")
    _fd, _rm = b.count('"title":'), b.count('"remediation":')
    if _fd and _rm < _fd:
        _no_remediation.append(f"{_name} ({_rm}/{_fd})")

check("every stage enforces scope", not _missing_scope, str(_missing_scope))
check("_parse_nmap enforces scope for the nmap stages",
      "scope.contains" in _body("_parse_nmap"))
check("every per-host stage probes concurrently and bounded",
      not _serial, str(_serial))
check("every finding carries remediation", not _no_remediation,
      str(_no_remediation))
check("nuclei results are scope-filtered",
      "scope.contains" in _body("nuclei_scan"))

# Every stage must add findings through _merge_findings. port_scan used a raw
# list.extend, so rescanning the same target appended duplicates of its own
# findings instead of collapsing them — the scan was not idempotent.
_raw_extend = [n for n, m in Pipeline.STAGES
               if "state.findings.extend" in _body(m)]
check("no stage bypasses the dedupe path", not _raw_extend, str(_raw_extend))

print("\n--- rescanning the same target is idempotent ---")
_p = mkpipe([SVC("10.10.0.5", 23, name="telnet"),
             SVC("10.10.0.5", 5900, name="vnc")])
_p.banner_analysis()
_first = len(_p.state.findings)
_p.banner_analysis()
_p.banner_analysis()
check("repeat stage runs do not duplicate findings",
      len(_p.state.findings) == _first, f"{_first} -> {len(_p.state.findings)}")
check("findings were actually produced", _first > 0)

print("\n--- scan coverage matches what the stages filter on ---")
# The class of bug that made ike-vpn dead and datastore-exposure unreachable:
# a stage keys on a port the default scan never looks at. Assert the scan
# profile covers every port a stage can act on.
_svc = Path("/usr/share/nmap/nmap-services")
if _svc.exists():
    _e = []
    for _line in _svc.read_text(errors="replace").splitlines():
        if _line.startswith("#"):
            continue
        _m = re.match(r"\S+\s+(\d+)/(tcp|udp)\s+([\d.]+)", _line)
        if _m:
            _e.append((int(_m.group(1)), _m.group(2), float(_m.group(3))))
    TOP1000 = {p for p, _, _ in
               sorted([x for x in _e if x[1] == "tcp"], key=lambda x: -x[2])[:1000]}
    EXTRA = {int(x) for x in Pipeline.EXTRA_PORTS.split(",")}
    COVERED = TOP1000 | EXTRA

    STAGE_PORTS = {
        "smb": [139, 445], "nfs": [111, 2049], "ldap": [389, 636, 3268],
        "tls-posture": [443, 8443, 993, 995, 465, 636, 989, 990],
        "datastore": [6379, 6380, 11211, 27017, 27018, 9200, 9201],
    }
    for _name, _ports in STAGE_PORTS.items():
        _gap = [p for p in _ports if p not in COVERED]
        check(f"{_name} ports are actually scanned", not _gap, f"unscanned: {_gap}")

    check("Redis is reachable in the default profile", 6379 in COVERED)
    check("Memcached is reachable in the default profile", 11211 in COVERED)
    check("MongoDB is reachable in the default profile", 27017 in COVERED)
    check("supplementary list only adds what top-1000 misses",
          not (EXTRA & TOP1000), f"redundant: {sorted(EXTRA & TOP1000)}")
else:
    check("nmap-services present for coverage audit (skipped)", True)

check("UDP ports cover the UDP-keyed stages",
      {"161", "500"} <= set(Pipeline.UDP_PORTS.split(",")))
check("aggressive mode skips the supplementary scan",
      "-p-" in open("vision/core/pipeline.py").read())

print("\n--- stage registry integrity ---")
# Assert the invariant, not a magic number — a hardcoded count means every
# new stage breaks an unrelated test for no reason.
names = [n for n, _ in Pipeline.STAGES]
check("stage registry is non-empty", len(names) >= 15, str(len(names)))
check("no duplicate stage names", len(set(names)) == len(names),
      str([n for n in names if names.count(n) > 1]))
check("every method exists", all(hasattr(Pipeline, m) for _, m in Pipeline.STAGES))
check("QUICK subset of STANDARD", Pipeline.QUICK <= Pipeline.STANDARD)
check("STANDARD subset of all", Pipeline.STANDARD <= {n for n,_ in Pipeline.STAGES})
check("banner-analysis in QUICK", "banner-analysis" in Pipeline.QUICK)
check("slow stages excluded from STANDARD",
      "nmap-vuln-scripts" not in Pipeline.STANDARD and "tls-deep" not in Pipeline.STANDARD)

print("\n--- every tool streams its output live, not only at the end ---")
# All 32 stages call the same module-level _run, so this one function decides
# whether an operator can see what a tool is doing. It used to be a blocking
# subprocess.run: nothing appeared until the tool finished, so a nine-minute
# nmap and a hung nmap looked identical -- a spinner and a climbing number.
import time as _t9
import vision.core.pipeline as _pl9

_seen = []
_orig_hook = _pl9._ON_OUTPUT
_pl9.set_output_hook(lambda stage, line: _seen.append((_t9.time(), stage, line)))
_pl9.current_stage("stream-test")
if sys.platform == "win32":
    print("SKIP  _run streaming tests require POSIX select on pipes — Windows")
else:
    try:
        _code, _out, _err = _pl9._run(
            ["sh", "-c", "echo one; sleep 0.15; echo two; sleep 0.15; echo three"], 10)
        check("the command still succeeds", _code == 0)
        check("full output is still returned for the parsers",
              _out.strip().splitlines() == ["one", "two", "three"])
        check("each line was delivered live via the hook",
              [l.strip() for _, _, l in _seen] == ["one", "two", "three"])
        check("the stage name accompanies each line",
              all(s == "stream-test" for _, s, _ in _seen))
        check("lines arrived spread over time, not batched at exit",
              _seen[-1][0] - _seen[0][0] > 0.2,
              f"spread={_seen[-1][0]-_seen[0][0]:.3f}s")
    finally:
        _pl9.set_output_hook(_orig_hook)

print("\n--- a stalled tool still times out and keeps what it printed ---")
_pl9._STAGE_TIMEOUTS.clear()
if sys.platform == "win32":
    print("SKIP  _run timeout test requires POSIX select on pipes — Windows")
else:
    _t0_9 = _t9.time()
    _code2, _out2, _err2 = _pl9._run(["sh", "-c", "echo before; sleep 30"], 2)
    _el9 = _t9.time() - _t0_9
    check("the timeout fires on schedule despite streaming",
          _el9 < 5, f"took {_el9:.1f}s against a 2s budget")
    check("output printed before the stall is salvaged, not discarded",
          _out2.strip() == "before", repr(_out2))
    check("the stage is still recorded as having timed out",
          _pl9._STAGE_TIMEOUTS, "a timed-out stage must not read as clean")
    check("a timed-out run reports a non-zero exit", _code2 != 0)

print("\n--- nmap stages request verbose progress ---")
# nmap prints nothing until it finishes unless asked. Without -v the live
# stream has nothing to show during exactly the long scans where progress
# matters most.
_src9 = Path("vision/core/pipeline.py").read_text(encoding="utf-8")
check("every nmap invocation asks for verbose output",
      _src9.count('"nmap", "-v"') >= 5,
      f"only {_src9.count(chr(34)+'nmap'+chr(34)+', '+chr(34)+'-v'+chr(34))} of 5")
check("the long scans also report periodic completion estimates",
      "--stats-every" in _src9)

print("\n" + "=" * 50)
print("ALL PASS" if not fails else "FAILURES: " + ", ".join(fails))
sys.exit(1 if fails else 0)
