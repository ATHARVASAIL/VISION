"""End-to-end integration: a realistic Metasploitable-like target, scanned
start to finish, through the same code paths an operator uses.

This is the test that catches wiring bugs the unit suites miss — a stage that
writes to the wrong key, an export that drops a field, a phase that never runs.
"""
import json, os, socket, sys, tempfile, threading, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.core.pipeline import Pipeline, RunState
from vision.core.scope import Scope
from vision.core.console import Console
from vision.analysis.msf_index import MsfIndex
from vision.analysis.exploit_advisor import ExploitAdvisor, ExploitLauncher
from vision.cli import load_findings
from vision.core.toolchain import BY_NAME

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

# This suite spawns real TCP servers and expects the real `nmap` binary to
# connect and produce real XML output -- deliberately, since it exists to
# catch wiring bugs unit tests can't (a stage writing to the wrong key, an
# export dropping a field). That means it needs nmap on PATH to mean anything.
#
# Without this guard, a box missing nmap silently ran every stage through its
# normal early-exit ("nmap not installed" -> skip), producing a wall of nine
# failures that all read as "the scan found nothing" -- indistinguishable
# from an actual regression without reading each skip reason by hand. Skip
# loudly and immediately instead.
if not BY_NAME["nmap"].installed:
    print("SKIP  test_integration requires nmap on PATH — not installed here")
    print("      this is an environment gap, not a code defect; install nmap "
          "to exercise this suite")
    sys.exit(0)

if sys.platform == "win32":
    print("SKIP  integration tests require Linux (nmap + raw sockets)")
    sys.exit(0)

# ---------------------------------------------------------------- fake target

BANNERS = {
    2121: b"220 (vsFTPd 2.3.4)\r\n",
    2323: b"\xff\xfb\x01Ubuntu 8.04\r\nlogin: ",
    16379: b"-DENIED Redis\r\n",
    15900: b"RFB 003.003\n",
}
_servers = []

def serve(port, banner):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
    except OSError:
        return
    s.listen(8)
    _servers.append(s)
    while True:
        try:
            c, _ = s.accept()
            c.sendall(banner)
            time.sleep(0.05)
            c.close()
        except OSError:
            break

for port, banner in BANNERS.items():
    threading.Thread(target=serve, args=(port, banner), daemon=True).start()
time.sleep(1.0)

listening = []
for port in BANNERS:
    try:
        c = socket.create_connection(("127.0.0.1", port), timeout=2)
        c.close(); listening.append(port)
    except OSError:
        pass
check(f"test target listening on {len(listening)}/{len(BANNERS)} ports",
      len(listening) == len(BANNERS), str(listening))

# ---------------------------------------------------------------- pipeline

print("\n--- phase 1-2: recon and service enumeration ---")
wd = Path(tempfile.mkdtemp())
scope = Scope.from_lists(["127.0.0.1/32"], allow_private_only=True)
state = RunState(scope=scope.summary(), workdir=str(wd))
pipe = Pipeline(scope, wd, state, timeout=180)

r = pipe.discover_hosts()
check("host discovery finds the target", r.ok and "127.0.0.1" in state.live_hosts,
      f"ok={r.ok} hosts={state.live_hosts}")

# Constrain to our ports so the scan is fast and deterministic.
import vision.core.pipeline as plmod
_orig_run = plmod._run
def scoped_run(argv, timeout):
    if argv and argv[0] == "nmap" and "--top-ports=1000" in argv:
        argv = [a if a != "--top-ports=1000" else "-p" for a in argv]
        i = argv.index("-p")
        argv.insert(i + 1, ",".join(str(p) for p in BANNERS))
    return _orig_run(argv, timeout)
plmod._run = scoped_run

r = pipe.port_scan()
plmod._run = _orig_run
check("port scan succeeds", r.ok, r.reason)
found_ports = {s["port"] for s in state.services}
check(f"all {len(BANNERS)} services detected",
      set(BANNERS) <= found_ports, f"found {sorted(found_ports)}")
check("service names identified",
      sum(1 for s in state.services if s.get("name")) >= 3,
      str([(s["port"], s.get("name")) for s in state.services]))
check("version detection captured a product",
      any(s.get("product") for s in state.services),
      str([(s["port"], s.get("product"), s.get("version")) for s in state.services]))

print("\n--- phase 2b: banner analysis ---")
r = pipe.banner_analysis()
check("banner analysis produced findings", r.findings > 0, str(r.findings))
titles = [f["title"] for f in state.findings]
check("FTP cleartext flagged", any("FTP" in t for t in titles), str(titles))
check("Telnet cleartext flagged", any("Telnet" in t for t in titles), str(titles))
vsftpd = [s for s in state.services if (s.get("product") or "").lower().startswith("vsftpd")]
if vsftpd and vsftpd[0].get("version", "").startswith("2.3"):
    check("vsftpd 2.3.4 flagged as outdated",
          any("Outdated" in t for t in titles), str(titles))
else:
    check("vsftpd version detection (informational)", True)

print("\n--- phase 3-4: stages degrade cleanly without their tools ---")
skipped, ran, crashed = 0, 0, []
for name, method in Pipeline.STAGES:
    if name in ("host-discovery", "port-scan", "banner-analysis"):
        continue
    try:
        res = getattr(pipe, method)()
        if res.skipped: skipped += 1
        else: ran += 1
    except Exception as e:
        crashed.append(f"{name}: {type(e).__name__}: {e}")
check("no stage crashes", not crashed, "; ".join(crashed[:2]))
check(f"remaining stages resolved ({ran} ran, {skipped} skipped cleanly)",
      ran + skipped == len(Pipeline.STAGES) - 3)

print("\n--- findings integrity ---")
check("every finding has an in-scope IP",
      all(scope.contains(f["ip"]) for f in state.findings))
check("every finding has a title", all(f.get("title") for f in state.findings))
check("every finding has a valid severity",
      all(f.get("severity") in ("info", "low", "medium", "high", "critical")
          for f in state.findings))
check("every finding has a confidence",
      all(f.get("confidence") in ("tentative", "firm", "confirmed")
          for f in state.findings))
check("every finding names its source", all(f.get("source") for f in state.findings))
check("no ANSI escapes leaked into findings",
      not any("\x1b" in str(f.get("evidence", "")) for f in state.findings))

print("\n--- export round trip ---")
out = pipe.export()
check("findings.json written", out.exists())
check("findings.json is 0600", oct(os.stat(out).st_mode & 0o777) == "0o600")
data = json.loads(out.read_text())
check("export contains services", len(data["services"]) == len(state.services))
check("export contains findings", len(data["findings"]) == len(state.findings))

reloaded_f, reloaded_s = load_findings(str(out))
check("exported findings reload through the CLI loader",
      len(reloaded_f) == len(state.findings), f"{len(reloaded_f)} vs {len(state.findings)}")
check("exported services reload", len(reloaded_s) == len(state.services))

print("\n--- report generation ---")
class Args:
    output = str(wd); operator = "integration-test"; no_banner = True
    cache = str(wd / "idx.json"); msf_path = None
    audit = str(wd / "audit.jsonl"); allow_destructive = False; timeout = 60
con = Console(Args())
con.scope, con.state, con.findings_file = scope, state, out
md = con._write_markdown()
csv = con._write_csv()
check("markdown report written", md.exists() and md.stat().st_size > 200)
check("csv report written", csv.exists())
check("markdown is 0600", oct(os.stat(md).st_mode & 0o777) == "0o600")
check("csv is 0600", oct(os.stat(csv).st_mode & 0o777) == "0o600")
body = md.read_text()
check("report names the scope", "127.0.0.1" in body)
check("report names the operator", "integration-test" in body)
check("report lists every service",
      all(str(s["port"]) in body for s in state.services))
check("report lists every finding",
      all(f["title"][:25] in body for f in state.findings))
check("report has remediation guidance", "Remediation" in body or "remediation" in body)
rows = csv.read_text().strip().splitlines()
check("csv has header plus one row per finding",
      len(rows) == len(state.findings) + 1, f"{len(rows)} rows")

print("\n--- resume after interruption ---")
state.save(wd / "state.json")
resumed = RunState.load(wd / "state.json")
p2 = Pipeline(scope, wd, resumed, resume=True)
done = resumed.completed()
check("completed stages recorded", "host-discovery" in done and "port-scan" in done)
before = len(resumed.findings)
results = p2.execute(skip={n for n, _ in Pipeline.STAGES} - {"host-discovery"})
check("resumed run skips completed work",
      all(r.skipped for r in results), str([r.name for r in results if not r.skipped]))
check("resume preserves findings", len(resumed.findings) == before)

print("\n--- exploit advisory on real findings ---")
mods = wd / "modules" / "exploits" / "unix" / "ftp"
mods.mkdir(parents=True, exist_ok=True)
(mods / "vsftpd_234_backdoor.rb").write_text('''
class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  def initialize(info = {})
    super(update_info(info, 'Name' => 'VSFTPD v2.3.4 Backdoor Command Execution',
      'Description' => %q{ Backdoor in vsftpd 2.3.4. },
      'References' => [ [ 'CVE', '2011-2523' ] ]))
  end
  def check
    Exploit::CheckCode::Vulnerable
  end
end
''')
idx = MsfIndex.build([str(wd / "modules")])
check("module index built", len(idx) == 1)
check("namespace is singular", idx.modules[0].fullname.startswith("exploit/"),
      idx.modules[0].fullname)

state.findings.append({
    "ip": "127.0.0.1", "port": 2121, "proto": "tcp",
    "title": "CVE-2011-2523 — vsftpd 2.3.4", "severity": "critical",
    "confidence": "firm", "cves": ["CVE-2011-2523"], "source": "test",
})
out2 = pipe.export()
f2, s2 = load_findings(str(out2))
adv = ExploitAdvisor(idx, scope)
cands = adv.advise(f2, s2)
check("advisory matches the CVE to the module", len(cands) >= 1, str(len(cands)))
if cands:
    c = cands[0]
    check("candidate targets the right host", c.rhost == "127.0.0.1")
    check("candidate targets the right port", c.rport == 2121)
    check("check() capability surfaced", c.module.has_check)
    check("tier is verify-only", c.tier.value == "verify-only", c.tier.value)
    L = ExploitLauncher(scope, audit_log=str(wd / "audit.jsonl"),
                        msfconsole="/bin/echo")
    res = L.run(c, action="check", dry_run=True, require_confirm=False)
    check("dry-run emits a valid resource script",
          "use exploit/" in res.stdout and "set RHOSTS 127.0.0.1" in res.stdout)
    check("resource script sets the right port", "set RPORT 2121" in res.stdout)
    check("dry run is audited", (wd / "audit.jsonl").exists())

print("\n--- full CLI surface smoke test ---")
from vision.cli import build_parser
parser = build_parser()
ok = 0
for argv in (["doctor"], ["setup", "--dry-run"], ["index"], ["menu"],
             ["run", "--scope", "10.0.0.0/24"],
             ["advise", "--findings", str(out), "--scope", "10.0.0.0/24"],
             ["exploit", "--findings", str(out), "--scope", "10.0.0.0/24"]):
    try:
        a = parser.parse_args(argv)
        assert callable(a.func)
        ok += 1
    except SystemExit:
        check(f"CLI accepts {' '.join(argv[:2])}", False)
check(f"all {ok} subcommands parse and bind a handler", ok == 7)

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
