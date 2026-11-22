"""Validate indexer parsing, advisor ranking, and every safety gate."""
import sys as _sys_sr
import sys, tempfile, textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.core.schema import Finding, Service, Severity, Confidence, Proto
from vision.core.scope import Scope
from vision.analysis.msf_index import MsfIndex, MsfModule
from vision.analysis.exploit_advisor import (
    ExploitAdvisor, ExploitCandidate, ExploitLauncher, ExploitBlocked,
    SafetyTier, _run_group,
)

FAKE = {
"exploits/multi/mysql/mysql_authbypass_hashdump.rb": '''
class MetasploitModule < Msf::Auxiliary
  Rank = ExcellentRanking
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'MySQL Authentication Bypass Password Dump',
      'Description' => %q{ This module exploits a password bypass vulnerability in MySQL. },
      'References' => [ [ 'CVE', '2012-2122' ], [ 'URL', 'http://x' ] ],
      'DisclosureDate' => '2012-06-09',
      'Privileged' => false ))
  end
  def check
    Exploit::CheckCode::Vulnerable
  end
end
''',
"exploits/windows/smb/ms17_010_eternalblue.rb": '''
class MetasploitModule < Msf::Exploit::Remote
  Rank = AverageRanking
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption',
      'Description' => %q{ This module is a port of the EternalBlue exploit. Note that
        this module may cause the target to crash and bluescreen. },
      'References' => [ [ 'CVE', '2017-0143' ], [ 'CVE', '2017-0144' ] ],
      'Privileged' => true ))
  end
  def check
    CheckCode::Vulnerable
  end
end
''',
"auxiliary/dos/http/apache_range_dos.rb": '''
class MetasploitModule < Msf::Auxiliary
  Rank = NormalRanking
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Apache Range Header DoS',
      'Description' => %q{ Denial of service against Apache httpd. },
      'References' => [ [ 'CVE', '2011-3192' ] ]))
  end
end
''',
"exploits/linux/misc/sketchy_overflow.rb": '''
class MetasploitModule < Msf::Exploit::Remote
  Rank = LowRanking
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Sketchy Stack Overflow',
      'Description' => %q{ Unreliable overflow. },
      'References' => [ [ 'CVE', '2019-9999' ] ]))
  end
end
''',
}

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        fails.append(label)

root = Path(tempfile.mkdtemp()) / "modules"
for rel, src in FAKE.items():
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(src))

print("--- indexer ---")
idx = MsfIndex.build([str(root)])
check("indexed all modules", len(idx) == 4, f"got {len(idx)}")

mysql = idx.by_cve("CVE-2012-2122")
check("CVE join finds mysql module", len(mysql) == 1 and "mysql_authbypass" in mysql[0].fullname)
check("rank parsed", mysql[0].rank == "Excellent", mysql[0].rank)
check("check() detected", mysql[0].has_check is True)
check("name parsed", "Authentication Bypass" in mysql[0].name, mysql[0].name)
check("mysql not destructive", mysql[0].destructive is False)
check("namespace singular (exploit not exploits)",
      not mysql[0].fullname.startswith("exploits/"), mysql[0].fullname)
check("eternalblue namespace", idx.by_cve("CVE-2017-0144")[0].fullname
      == "exploit/windows/smb/ms17_010_eternalblue",
      idx.by_cve("CVE-2017-0144")[0].fullname)
check("aux namespace preserved", idx.by_cve("CVE-2011-3192")[0].fullname
      == "auxiliary/dos/http/apache_range_dos")

eb = idx.by_cve("CVE-2017-0144")[0]
check("multi-CVE module indexed under both", len(eb.cves) == 2, str(eb.cves))
check("bluescreen -> destructive", eb.destructive is True)
check("privileged parsed", eb.privileged is True)

dos = idx.by_cve("CVE-2011-3192")[0]
check("dos path -> destructive", dos.destructive is True)
check("is_dos flag", dos.is_dos is True)

# Auxiliary scanners must not be flagged destructive just because their
# description talks about what the *target* is vulnerable to (e.g. "enables
# password spraying" or "allows remote code execution"). The module itself
# is a read-only enumerator.
_enum_src = '''
class MetasploitModule < Msf::Auxiliary
  Rank = NormalRanking
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'SSH User Enumeration',
      'Description' => %q{ This module allows username enumeration
        against SSH. An attacker can use the leaked usernames for
        password spraying, which enables remote code execution. },
      'References' => [ [ 'CVE', '2016-6210' ] ]))
  end
  def run
    # enumerates usernames — does not crash or overwrite anything
  end
end
'''
import tempfile as _tmp2, textwrap as _tw2
_p2 = _tmp2.mkdtemp() + "/auxiliary/scanner/ssh/ssh_enumusers.rb"
Path(_p2).parent.mkdir(parents=True, exist_ok=True)
Path(_p2).write_text(_tw2.dedent(_enum_src))
_enum_mod = MsfModule(
    fullname="auxiliary/scanner/ssh/ssh_enumusers",
    path=_p2, name="SSH User Enumeration", rank="Normal",
    cves=["CVE-2016-6210"], has_check=False)
check("an auxiliary scanner is NOT destructive even if its description "
      "mentions the target's RCE capability",
      not _enum_mod.destructive,
      f"destructive={_enum_mod.destructive}")

check("lowercase search works", len(idx.search("mysql")) >= 1)
check("kind filter", all(m.kind == "exploit" for m in idx.search("overflow", kind="exploit")))

print("\n--- cache roundtrip ---")
cache = str(Path(tempfile.mkdtemp()) / "idx.json")
idx.save(cache)
idx2 = MsfIndex.load(cache)
check("roundtrip preserves count", len(idx2) == len(idx))
check("roundtrip preserves cve map", len(idx2.by_cve("CVE-2012-2122")) == 1)
# platforms is a frozenset, which JSON cannot serialise directly; the cache
# must convert it both ways or the whole index fails to save. Guard it here.
_pmod = next((m for m in idx2.modules if m.platforms), None)
check("roundtrip preserves module platforms as a frozenset",
      _pmod is None or isinstance(_pmod.platforms, frozenset))

print("\n--- scope ---")
scope = Scope.from_lists(["10.10.0.0/24", "192.168.1.10-20"], deny=["10.10.0.1"])
check("in scope", scope.contains("10.10.0.55"))
check("deny beats allow", not scope.contains("10.10.0.1"))
check("range shorthand", scope.contains("192.168.1.15"))
check("range excludes outside", not scope.contains("192.168.1.30"))
check("out of scope", not scope.contains("8.8.8.8"))
check("hostname rejected", not scope.contains("evil.com"))

print("\n--- advisor ---")
svc = Service(ip="10.10.0.55", port=3306, proto=Proto.TCP, name="mysql",
              product="MySQL", version="5.5.28")
f_mysql = Finding(ip="10.10.0.55", port=3306, proto=Proto.TCP,
                  title="MySQL auth bypass", severity=Severity.CRITICAL,
                  confidence=Confidence.FIRM, cves=["CVE-2012-2122"], source="nmap")
f_smb = Finding(ip="10.10.0.60", port=445, proto=Proto.TCP, title="MS17-010",
                severity=Severity.CRITICAL, confidence=Confidence.FIRM,
                cves=["CVE-2017-0144"], source="nuclei")
f_dos = Finding(ip="10.10.0.61", port=80, proto=Proto.TCP, title="Apache range DoS",
                severity=Severity.MEDIUM, cves=["CVE-2011-3192"], source="nuclei")
f_oos = Finding(ip="8.8.8.8", port=3306, proto=Proto.TCP, title="out of scope",
                cves=["CVE-2012-2122"], source="import")

adv = ExploitAdvisor(idx, scope)
cands = adv.advise([f_mysql, f_smb, f_dos, f_oos], services=[svc])
names = [c.module.fullname for c in cands]
check("mysql candidate present", any("mysql_authbypass" in n for n in names))
check("out-of-scope finding dropped", not any(c.rhost == "8.8.8.8" for c in cands))
check("destructive VISIBLE by default", any(c.module.destructive for c in cands), str(names))
check("destructive marked locked", all(c.locked for c in cands if c.module.destructive))
check("non-destructive not locked", not any(c.locked for c in cands if not c.module.destructive))

cands_h = adv.advise([f_dos], hide_destructive=True)
check("hide_destructive suppresses", len(cands_h) == 0)
cands_d = adv.advise([f_dos])
check("destructive listed when not hidden", len(cands_d) == 1)
check("destructive tier", cands_d[0].tier is SafetyTier.DESTRUCTIVE)

# --- auxiliary severity capping ---
# An auxiliary matched via CVE inherits the finding's severity. But a
# username-enumeration auxiliary cannot demonstrate critical impact — it
# can only confirm the target is reachable and list accounts. The displayed
# severity must reflect what the module can actually achieve.
_enum_f = Finding(ip="10.10.0.62", port=22, proto=Proto.TCP,
                  title="OpenSSH 4.7p1 — 55 known CVEs",
                  severity=Severity.CRITICAL, confidence=Confidence.FIRM,
                  cves=["CVE-2016-6210"], source="nmap:vulners")
_enum_cand = ExploitCandidate(
    module=_enum_mod, finding=_enum_f, match_reason="cve:CVE-2016-6210",
    confidence=Confidence.FIRM)
check("an auxiliary's effective severity is capped at HIGH when the finding "
      "is CRITICAL",
      _enum_cand.effective_severity is Severity.HIGH,
      f"got {_enum_cand.effective_severity}")
check("an auxiliary on a non-critical finding is unchanged",
      ExploitCandidate(
          module=_enum_mod,
          finding=Finding(ip="10.10.0.62", port=22, proto=Proto.TCP,
                          title="SSH user enum", severity=Severity.MEDIUM),
          match_reason="product:ssh").effective_severity is Severity.MEDIUM)
# The describe() output reflects the cap.
_desc = _enum_cand.describe()
check("describe() shows the capped severity",
      "[high]" in _desc and "[critical]" not in _desc,
      _desc)

# The score must also use the capped severity — an auxiliary on a CRITICAL
# finding must not rank higher than the same module on a HIGH finding.
_exploit_mod = MsfModule(
    fullname="exploit/ssh/something",
    path="/x", name="x", rank="Good", cves=["CVE-2016-6210"],
    has_check=True)
_exploit_cand = ExploitCandidate(
    module=_exploit_mod,
    finding=Finding(ip="10.10.0.62", port=22, proto=Proto.TCP,
                    title="SSH vuln", severity=Severity.HIGH,
                    confidence=Confidence.FIRM),
    match_reason="cve:CVE-2016-6210", confidence=Confidence.FIRM)
check("an auxiliary on CRITICAL does not outrank an exploit on HIGH "
      "(score uses effective_severity)",
      _enum_cand.score < _exploit_cand.score,
      f"auxiliary={_enum_cand.score:.1f} vs exploit={_exploit_cand.score:.1f}")

top = cands[0]
check("highest-ranked first", "mysql_authbypass" in top.module.fullname, top.module.fullname)
check("verify-only tier for check-capable", top.tier is SafetyTier.VERIFY_ONLY)
check("RHOSTS set", top.options()["RHOSTS"] == "10.10.0.55")
check("RPORT set", top.options()["RPORT"] == "3306")
check("cve match reason", top.match_reason.startswith("cve:"))

s = adv.summary(cands)
check("summary counts hosts", s["hosts"] == 3, str(s))
check("summary counts locked", s["locked"] >= 1, str(s))

print("\n--- fuzzy fallback (no CVE) ---")
f_nocve = Finding(ip="10.10.0.55", port=3306, proto=Proto.TCP,
                  title="MySQL 5.5.28 detected", severity=Severity.INFO, source="nmap")
fz = adv.advise([f_nocve], services=[svc])
check("product fallback fires", len(fz) >= 1)
check("fallback marked as product match", fz[0].match_reason.startswith("product:"))
check("fallback downgraded to tentative", fz[0].confidence is Confidence.TENTATIVE)

print("\n--- launcher gates ---")
audit = str(Path(tempfile.mkdtemp()) / "audit.jsonl")
L = ExploitLauncher(scope, audit_log=audit, msfconsole="/bin/echo")

rc = L.run(top, action="check", dry_run=True, require_confirm=False)
check("dry-run emits resource script", "use auxiliary/" in rc.stdout or "use exploit/" in rc.stdout, rc.stdout[:80])
check("script sets RHOSTS", "set RHOSTS 10.10.0.55" in rc.stdout)
check("check script calls check", rc.stdout.strip().splitlines()[-2] == "check")

ex = L.run(top, action="exploit", dry_run=True, require_confirm=False)
check("exploit script uses exploit -z", "exploit -z" in ex.stdout)
# ExitOnSession is deliberately false: the script must stay alive after the
# session opens so it can capture identity, then close the session itself.
# With it true, msfconsole exited immediately and Vision recorded nothing about
# what the exploit achieved.
check("exploit keeps the console alive to capture proof",
      "ExitOnSession false" in ex.stdout)
check("and closes the session when done", "sessions -K" in ex.stdout)

# Gate: destructive blocked
dcand = cands_d[0]
try:
    L.run(dcand, action="exploit", dry_run=True, require_confirm=False)
    check("destructive blocked without override", False, "no exception raised")
except ExploitBlocked as e:
    check("destructive blocked without override", "DESTRUCTIVE" in str(e))

L2 = ExploitLauncher(scope, audit_log=audit, allow_destructive=True, msfconsole="/bin/echo")
try:
    L2.run(dcand, action="exploit", dry_run=True, require_confirm=False)
    check("destructive allowed with override", True)
except ExploitBlocked as e:
    check("destructive allowed with override", False, str(e))

# Gate: scope re-check at fire time (finding smuggled in post-advisory)
smuggled = ExploitAdvisor(Scope.from_lists(["0.0.0.0/0"]), ).__class__ if False else None
from vision.analysis.exploit_advisor import ExploitCandidate
evil = ExploitCandidate(module=mysql[0], finding=f_oos, match_reason="cve:x")
try:
    L.run(evil, action="check", dry_run=True, require_confirm=False)
    check("scope re-checked at fire time", False, "out-of-scope target ran")
except ExploitBlocked as e:
    check("scope re-checked at fire time", "outside engagement scope" in str(e))

# Gate: no check method
nocheck = ExploitCandidate(module=idx.by_cve("CVE-2019-9999")[0], finding=f_mysql)
try:
    L.run(nocheck, action="check", dry_run=True, require_confirm=False)
    check("check blocked when unsupported", False)
except ExploitBlocked as e:
    check("check blocked when unsupported", "no check method" in str(e))

# Gate: missing msfconsole
L3 = ExploitLauncher(scope, audit_log=audit, msfconsole=None)
L3.msfconsole = None
try:
    L3.run(top, action="check", dry_run=True, require_confirm=False)
    check("dry-run works WITHOUT msfconsole installed", True)
except ExploitBlocked as e:
    check("dry-run works WITHOUT msfconsole installed", False, str(e))
try:
    L3.run(top, action="check", dry_run=False, require_confirm=False)
    check("real run blocked without msfconsole", False)
except ExploitBlocked as e:
    check("real run blocked without msfconsole", "msfconsole not found" in str(e))
# gates must still bite on dry runs
try:
    L3.run(evil, action="check", dry_run=True, require_confirm=False)
    check("scope gate still applies on dry-run", False)
except ExploitBlocked as e:
    check("scope gate still applies on dry-run", "outside engagement scope" in str(e))

print("\n--- audit log ---")
import json as _j
lines = [_j.loads(l) for l in Path(audit).read_text().splitlines()]
check("audit wrote records", len(lines) >= 1, str(len(lines)))
check("audit has operator+module+target",
      all({"operator", "module", "target"} <= set(l) for l in lines))

print("\n--- manual command ---")
mc = L.manual_command(top, "check")
check("manual cmd is copy-pasteable", "msfconsole -q -x" in mc and "RHOSTS" in mc)
print("   " + mc)

print("\n--- real-run regressions: timeout hang, duplicate work, false match ---")
# A batched verification run against a real Metasploitable host hung for
# 5.7 hours on a 30-minute timeout, queued 48 checks where 20 were distinct
# work, and matched WordPress/Pandora FMS exploits to a bare MySQL service.

if _sys_sr.platform == "win32":
    print("SKIP  real-run group-kill tests require POSIX process groups -- Windows")
else:
    import time as _time

    _t0 = _time.time()
    _out, _code = _run_group(["sh", "-c", "echo start; sleep 30"], 2)
    _elapsed = _time.time() - _t0
    check("timeout kills the whole process group, not just the parent",
          _elapsed < 5, f"took {_elapsed:.1f}s against a 2s timeout")
    check("a hung command still returns a result rather than raising",
          _code == -1)
    check("partial output is salvaged from a killed process", "start" in _out)
    _t1 = _time.time()
    _out2, _code2 = _run_group(["echo", "fine"], 10)
    check("a normal command is unaffected", _code2 == 0 and "fine" in _out2)
    check("a normal command does not pay the group-kill overhead",
          _time.time() - _t1 < 2)

_mod = MsfModule(fullname="exploit/linux/ftp/proftp_telnet_iac", path="/x",
                 name="P", rank="Great", cves=["CVE-2010-4221"], has_check=True)
_idx = MsfIndex(modules=[_mod])
_fs = [Finding(ip="192.168.88.128", port=2121, proto=Proto.TCP,
              title=f"CVE-2010-4221 #{i}", cves=["CVE-2010-4221"])
      for i in range(8)]
_adv = ExploitAdvisor(_idx, Scope.from_lists(["192.168.88.0/24"]))
_cands = _adv.advise(_fs, [])
check("8 CVE findings on one module+port collapse to 1 candidate",
      len(_cands) == 1, f"got {len(_cands)} — this was 8 before the fix")

_wp = MsfModule(fullname="exploit/multi/http/wp_db_backup_rce", path="/x",
                name="WP", rank="Great",
                description="Exploits WordPress DB backup, which stores "
                            "credentials referencing a MySQL connection "
                            "string")
_real_mysql = MsfModule(fullname="exploit/linux/mysql/mysql_yassl_hello",
                        path="/x", name="M", rank="Good",
                        description="Buffer overflow in MySQL")
_idx2 = MsfIndex(modules=[_wp, _real_mysql])
_hits = [m.fullname for m in _idx2.search("mysql")]
check("fuzzy search matches module name, not description prose",
      _wp.fullname not in _hits,
      "an HTTP exploit matched a MySQL service because its description "
      "mentions MySQL — this is what put WordPress and Pandora FMS "
      "exploits against port 3306 in a real run")
check("a module that genuinely targets the product still matches",
      _real_mysql.fullname in _hits)




print("\n--- proof of impact: what an exploit actually achieved ---")
# Vision used to stop at "session opened" and record nothing. A report needs
# "root shell obtained, uid=0(root) captured", not "the check said vulnerable".
from vision.analysis.proof import (
    parse as parse_proof, to_finding as proof_finding, UNIX_PROOF,
    METERPRETER_PROOF,
)

_SHELL = """[*] 192.168.88.128:21 - Backdoor service has been spawned
[*] Command shell session 1 opened (192.168.88.129:44215 -> 192.168.88.128:6200)
uid=0(root) gid=0(root)
root
metasploitable
Linux metasploitable 2.6.24-16-server #1 SMP i686 GNU/Linux"""
_pr = parse_proof(_SHELL)
check("a session is detected", _pr.obtained)
check("session id captured", _pr.session_id == "1")
check("session type identified", _pr.session_type == "command shell")
check("root is recognised", _pr.is_root)
check("user extracted", _pr.user == "root")
check("host extracted from uname", _pr.host == "metasploitable", _pr.host)
check("privilege reported", _pr.privilege == "privileged")
check("summary reads as evidence", "root" in _pr.summary())

_METER = """[*] Meterpreter session 2 opened (10.0.0.1:4444 -> 10.0.0.5:1039)
Server username: NT AUTHORITY\\SYSTEM
Computer        : WIN-DC01
OS              : Windows 2008"""
_mp = parse_proof(_METER)
check("meterpreter detected", _mp.session_type == "meterpreter")
check("SYSTEM is privileged", _mp.is_root)
check("the full Windows identity is kept, not split on the backslash",
      "SYSTEM" in _mp.user and _mp.user != "NT", _mp.user)
check("computer name captured", _mp.host == "WIN-DC01")

_LOW = """[*] Command shell session 3 opened (a -> b)
uid=33(www-data) gid=33(www-data)
www-data
webhost
Linux webhost 5.4.0 #1 SMP x86_64 GNU/Linux"""
_lp = parse_proof(_LOW)
check("an unprivileged session is not reported as root", not _lp.is_root)
check("unprivileged user extracted", _lp.user == "www-data")
check("privilege reported honestly", _lp.privilege == "user")

_FAIL = "[-] Exploit completed, but no session was created."
_fp = parse_proof(_FAIL)
check("a failed exploit yields no proof", not _fp.obtained)
check("a failed exploit produces no finding", proof_finding(_fp, None) is None)
check("empty output is safe", not parse_proof("").obtained)
check("None output is safe", not parse_proof(None).obtained)

# --- REAL transcript from the field: vsftpd 2.3.4 backdoor, genuine root shell.
# This is the exact output from Omkar's Metasploitable run (bind_netcat payload).
# It is NOT synthetic: root is proven by the "sh-3.2#" prompt, not by uid=0 —
# the backdoor's raw shell returned a mangled `id`. The first time this real
# transcript was parsed it scored is_root=False, because every hand-written
# fixture had always included a clean uid=0(root) and the prompt-only case had
# never been exercised. Guards that this real case stays detected.
_REAL_VSFTPD_ROOT = (
    "[+] 192.168.88.128:21 - Backdoor has been spawned!\n"
    "[*] Started bind TCP handler against 192.168.88.128:4444\n"
    "[*] Command shell session 1 opened "
    "(192.168.88.129:44267 -> 192.168.88.128:4444) at 2026-09-05 02:21:59 -0400\n"
    "\n\nShell Banner:\nsh: no job control in this shell\nsh-3.2#\n"
)
_rr = parse_proof(_REAL_VSFTPD_ROOT)
check("real vsftpd transcript: session detected", _rr.obtained)
check("real vsftpd transcript: session id is 1", _rr.session_id == "1")
check("real vsftpd transcript: ROOT detected via the # prompt", _rr.is_root)
check("real vsftpd transcript: privilege reported as privileged",
      _rr.privilege == "privileged")

# The prompt heuristic must not over-claim: a $ prompt is never root, and a
# session with neither a # prompt nor uid=0 must stay unprivileged.
_DOLLAR = ("[*] Command shell session 1 opened (a -> b)\n"
           "www-data@web:/var/www$ id\n"
           "uid=33(www-data) gid=33(www-data)\nwww-data@web:/var/www$\n")
check("a $ prompt shell is not root", not parse_proof(_DOLLAR).is_root)
_NOEV = ("[*] Command shell session 1 opened (a -> b)\n"
         "sh: no job control in this shell\n")
check("a session with no # prompt and no uid is not root",
      not parse_proof(_NOEV).is_root)

# --- Same real transcript, but the full messy tail: a separator line, an
# echoed `exit`, and command echoes. The first parse of this real output put
# user='-----' and host='exit' into the result — a client report would have
# read "shell as user ----- on host exit". Shell noise must never be mistaken
# for an identity. Built directly from Omkar's field transcript.
_REAL_MESSY = (
    "[*] Command shell session 1 opened "
    "(192.168.88.129:44267 -> 192.168.88.128:4444) at 2026-09-05 02:21:59 -0400\n"
    "\n\nShell Banner:\nsh: no job control in this shell\nsh-3.2#\n"
    "-----\n          \nsh-3.2# exit\nexit\n"
    "[*] 192.168.88.128 - Command shell session 1 closed.\n")
_rm = parse_proof(_REAL_MESSY)
check("real messy transcript: still root", _rm.is_root)
check("a separator line is not read as the user", _rm.user != "-----")
check("an echoed command is not read as the host", _rm.host != "exit")
check("root with no real username falls back to 'root'", _rm.user == "root")
check("no junk host is emitted when none is present", _rm.host == "")
# The identity filter accepts genuine accounts and rejects transcript noise.
check("a real account is still accepted",
      parse_proof("[*] Command shell session 1 opened (a -> b)\n"
                  "uid=33(www-data) gid=33\nweb01\n").host == "web01")

_mod = MsfModule(fullname="exploit/unix/ftp/vsftpd_234_backdoor", path="/x",
                 name="V", rank="Excellent", cves=["CVE-2011-2523"])
_cand = ExploitCandidate(
    module=_mod, finding=Finding(ip="192.168.88.128", port=21,
                                 proto=Proto.TCP, title="t",
                                 cves=["CVE-2011-2523"]))
_f = proof_finding(_pr, _cand)
check("a privileged session is critical", _f["severity"] == "critical")
check("confidence is confirmed — earned by demonstration",
      _f["confidence"] == "confirmed")
check("the module is attributed", "vsftpd_234_backdoor" in _f["source"])
check("CVEs carry through", _f["cves"] == ["CVE-2011-2523"])
check("the transcript is the evidence", "uid=0(root)" in _f["evidence"])
check("remediation states it was demonstrated",
      "demonstrated" in _f["remediation"])
check("marked as exploited", _f.get("exploited") is True)
_lf = proof_finding(_lp, _cand)
check("an unprivileged session is high, not critical",
      _lf["severity"] == "high")

print("\n--- a session must be REPORTED by msfconsole, not merely mentioned ---")
# Text containing the phrase without msfconsole's [*] prefix used to parse as a
# real session and produce a "remote code execution confirmed" finding for a
# shell that never existed. Claiming compromise that did not happen is the
# worst false positive this tool can produce.
for _text, _why in [
        ("the docs say: Command shell session 1 opened", "prose"),
        ("Command shell session 3 opened (a -> b)", "log line with no prefix"),
        ("> Meterpreter session 2 opened", "quoted text"),
        ("[-] Exploit failed: Command shell session would open", "failure text")]:
    check(f"no session claimed from {_why}", not parse_proof(_text).obtained,
          _text[:40])
check("a real msfconsole line is still recognised",
      parse_proof("[*] Command shell session 1 opened (a -> b)").obtained)
check("the [+] prefix also counts",
      parse_proof("[+] Meterpreter session 4 opened (a -> b)").obtained)

print("\n--- a username must be plausible ---")
_pad = parse_proof("[*] Command shell session 1 opened (a -> b)\n" + "A" * 5000)
check("padding is not extracted as an account name", _pad.user == "", _pad.user)
check("a session is still detected around it", _pad.obtained)
check("a real short username survives",
      parse_proof("[*] Command shell session 1 opened (a -> b)\n"
                  "uid=33(www-data) gid=33").user == "www-data")

print("\n--- proof findings flow through everything downstream ---")
from vision.analysis.remediation import plan as _plan
from vision.core.triage import Triage as _Triage, FALSE_POSITIVE as _FP
from vision.report.html import build_report as _report

_pf = proof_finding(_pr, _cand)
_other = {"ip": "192.168.88.128", "port": 23, "title": "Telnet exposed",
          "severity": "high", "confidence": "firm", "cves": [],
          "source": "banner-analysis", "remediation": "Disable Telnet."}
_all = [_pf, _other]
check("an exploited finding reaches the remediation plan",
      any(a.severity == "critical" for a in _plan(_all)))
_t = _Triage()
_t.set(_pf, _FP, "lab target, agreed with client")
check("an exploited finding can be triaged out", _t.status(_pf) == _FP)
check("and then leaves the main report body",
      len(_t.reportable(_all)) == 1)
_h = _report(_t.annotate(_all), [{"ip": "192.168.88.128", "port": 21,
                                  "name": "ftp"}])
check("the report still renders", _h.rstrip().endswith("</html>"))
check("it appears in the excluded appendix instead",
      "Excluded findings" in _h)
_inj = proof_finding(parse_proof(
    "[*] Command shell session 1 opened (a -> b)\nuid=0(root)\n"
    "<script>alert(1)</script>"), _cand)
_hi = _report([_inj], [])
check("a transcript cannot inject script into the report",
      "<script>alert(1)</script>" not in _hi[_hi.index("<body>"):])

print("\n--- proof commands are read-only ---")
# These prove what was obtained. Anything that reads user data, dumps
# credentials, moves laterally or persists is an operator decision made with
# the engagement terms in hand — the playbook holds those.
for _cmd in UNIX_PROOF + METERPRETER_PROOF:
    _bad = ("cat ", "rm ", "wget", "curl", "nc ", "chmod", "useradd",
            "hashdump", "mimikatz", "download", "upload", "persistence",
            "migrate", "portfwd", ">", "|")
    check(f"'{_cmd}' only reads identity",
          not any(b in _cmd for b in _bad))
check("the command set stays minimal", len(UNIX_PROOF + METERPRETER_PROOF) <= 8)

_script = ExploitLauncher(
    Scope.from_lists(["192.168.88.0/24"]), audit_log=tempfile.mktemp(),
    msfconsole="/bin/echo")._resource_script(_cand, "exploit", None)
check("the exploit script captures proof", "sessions -c" in _script)
check("the session is closed afterwards", "sessions -K" in _script,
      "leaving shells open on a client estate is how a test becomes an incident")
check("no credential dumping in the script",
      not any(w in _script for w in ("hashdump", "mimikatz", "creds")))
check("check scripts remain payload-free",
      "exploit" not in ExploitLauncher(
          Scope.from_lists(["192.168.88.0/24"]), audit_log=tempfile.mktemp(),
          msfconsole="/bin/echo")._resource_script(_cand, "check", None)
      .replace("use exploit", ""))

print("\n--- live phase streaming: what the operator actually sees ---")
# Before this, the spinner showed a static label plus an elapsed-seconds
# counter and nothing else — a genuinely slow module and a hung one looked
# identical. This is what caused a real operator to wait 17 minutes on a run
# that had actually finished and was sitting at an unanswered prompt.
from vision.analysis.exploit_advisor import classify_phase, _stream_run

REAL_LINES = [
    ("[*] Started reverse TCP handler on 10.0.0.1:4444",
     "listener ready, waiting for callback"),
    ("[*] 10.0.0.5:21 - Connecting to FTP server 10.0.0.5:21...",
     "connecting to target"),
    ("[*] 10.0.0.5:21 - Trying to exploit vsftpd 2.3.4 backdoor",
     "sending exploit"),
    ("[*] Sending stage (1017704 bytes) to 10.0.0.5",
     "sending payload stage"),
    ("[*] Command shell session 1 opened (10.0.0.1:44215 -> 10.0.0.5:6200)",
     "session opened"),
    ("uid=0(root) gid=0(root)", "reading session identity"),
    ("[*] Killing all sessions...", "closing the session"),
]
for line, expected in REAL_LINES:
    got = classify_phase(line)
    check(f"classifies real msfconsole line: {expected}", got == expected,
          f"got {got!r} from {line!r}")

check("a blank line has no phase", classify_phase("") is None)
check("whitespace-only has no phase", classify_phase("   \n") is None)
check("an unrecognised [*] line still shows something readable",
      classify_phase("[*] some future msfconsole message we never coded "
                     "for specifically") is not None)
check("a [-] failure line is classified as a rejection",
      classify_phase("[-] Exploit failed: connection refused")
      == "target rejected the attempt")
check("phase text is bounded so it cannot blow out the terminal line",
      len(classify_phase("[*] " + "x" * 500) or "") <= 70)

import time as _time4
if _sys_sr.platform == "win32":
    print("SKIP  _stream_run tests require POSIX select on pipes -- Windows")
else:
    print("\n--- _stream_run delivers output as it happens, not after exit ---")
    _seen = []
    _out, _err, _code = _stream_run(
        ["sh", "-c", "echo one; sleep 0.15; echo two; sleep 0.15; echo three"],
        timeout=5, on_line=lambda l: _seen.append((_time4.time(), l.strip())))
    check("all lines captured in the return value",
          _out.strip().splitlines() == ["one", "two", "three"])
    check("all lines delivered via the callback, in order",
          [l for _, l in _seen] == ["one", "two", "three"])
    check("callback timestamps are spread out — genuinely streamed, not "
          "delivered all at once when the process exits",
          _seen[-1][0] - _seen[0][0] > 0.2, f"spread={_seen[-1][0]-_seen[0][0]:.3f}s")
    check("exit code captured correctly", _code == 0)
    
    _out2, _err2, _code2 = _stream_run(["echo", "quick"], timeout=5)
    check("a command with no on_line callback still works", _out2.strip() == "quick")
    
    print("\n--- the streaming timeout is real, not merely checked between lines ---")
    # The first version of _stream_run called a plain blocking readline() and
    # only checked the deadline between lines. A process that prints one line and
    # then goes quiet for a while -- completely normal for a real exploit module
    # mid-handshake -- blocked inside that single readline() call for its whole
    # runtime, ignoring the deadline. A 2-second timeout took 30 seconds to fire.
    import subprocess as _subprocess4
    _t0 = _time4.time()
    try:
        _stream_run(["sh", "-c", "echo start; sleep 30"], timeout=2)
        check("timeout fires even when the process goes quiet after one line",
              False, "did not raise")
    except _subprocess4.TimeoutExpired:
        _elapsed = _time4.time() - _t0
        check("timeout fires even when the process goes quiet after one line",
              _elapsed < 5, f"took {_elapsed:.1f}s against a 2s budget")

print("\n--- the spinner can show a live phase, not just elapsed time ---")
from vision.core import ui as _ui4
_sp = _ui4.Spinner("msf exploit -> 10.0.0.5", stream=_time4)  # not a real stream
check("Spinner exposes update()", hasattr(_sp, "update"))
_sp.text = "msf exploit -> 10.0.0.5"
_sp.update("msf exploit -> 10.0.0.5: sending exploit")
check("update() actually changes the label the spinner will draw",
      _sp.text == "msf exploit -> 10.0.0.5: sending exploit")

print("\n--- a critical unmatched finding is flagged, not silently dropped ---")
# A brand-new CVE with no Metasploit module yet used to produce the exact
# same message as "nothing here is exploitable" -- indistinguishable for the
# one case that most needs flagging.
from vision.core.schema import Finding as _F4, Severity as _Sev4

_new_cve = _F4(ip="10.10.0.5", port=8443, proto=Proto.TCP,
              title="Brand new appliance RCE", cves=["CVE-2026-99999"],
              severity=_Sev4.CRITICAL)
_low = _F4(ip="10.10.0.5", port=22, proto=Proto.TCP,
          title="Weak MAC algorithms", severity=_Sev4.LOW)
_empty_idx = MsfIndex(modules=[])
_adv4 = ExploitAdvisor(_empty_idx, Scope.from_lists(["10.10.0.0/24"]))
_cands4 = _adv4.advise([_new_cve, _low], [])
check("no modules exist for either finding in an empty index",
      len(_cands4) == 0)
_matched_ids = {id(c.finding) for c in _cands4}
_urgent = [f for f in [_new_cve, _low]
          if id(f) not in _matched_ids and f.severity.value in ("critical", "high")]
check("the critical unmatched finding is correctly identified",
      len(_urgent) == 1 and _urgent[0] is _new_cve)
check("the low-severity unmatched finding is correctly excluded from the "
      "urgent list", _low not in _urgent)

if _sys_sr.platform == "win32":
    print("SKIP  buffered output tests require POSIX select on pipes -- Windows")
else:
    print("\n--- buffered output is fully drained, not stranded ---")
    # select() reports the OS pipe readable, but a buffered readline() pulls a
    # whole chunk into Python's own buffer and returns only its first line. The
    # rest are then invisible to select() — they are in Python's buffer, not the
    # pipe — so a process that printed several lines and then went quiet had all
    # but its first line stranded until it exited. That is exactly the case
    # streaming exists to handle, so it silently defeated the whole feature.
    import subprocess as _sp5
    import os as _os5
    import stat as _st5
    
    _multi = "/tmp/_vision_test_multiline.sh"
    with open(_multi, "w") as _fh:
        _fh.write("#!/bin/sh\nprintf 'a\\nb\\nc\\nd\\n'\nsleep 30\n")
    _os5.chmod(_multi, _os5.stat(_multi).st_mode | _st5.S_IEXEC)
    
    try:
        _stream_run([_multi], 2)
        check("a process that goes quiet after several lines still times out",
              False, "did not raise")
    except _sp5.TimeoutExpired as _e5:
        _got = len((_e5.output or "").strip().splitlines())
        check("every buffered line is captured, not just the first",
              _got == 4, f"captured {_got} of 4")
    
    print("\n--- partial output survives a timeout ---")
    # A batched verification that times out on the fifteenth module must not throw
    # away the fourteen verdicts it already has. Before this, the timeout handler
    # set out="" and every completed result was discarded — forcing a re-run of a
    # multi-minute session to recover work that was already done.
    try:
        _stream_run([_multi], 2)
    except _sp5.TimeoutExpired as _e6:
        check("TimeoutExpired carries the partial transcript",
              bool(_e6.output), "output was empty")
        check("the partial transcript is usable, not truncated mid-stream",
              (_e6.output or "").strip().splitlines() == ["a", "b", "c", "d"])
    
    _L6 = ExploitLauncher(Scope.from_lists(["10.0.0.0/24"]),
                          audit_log=tempfile.mktemp(), msfconsole=_multi)
    _mods6 = [MsfModule(fullname=f"exploit/unix/ftp/m{i}", path="/x", name=f"M{i}",
                       rank="Great", cves=[f"CVE-2020-{i}"], has_check=True)
             for i in range(2)]
    _cands6 = [ExploitCandidate(
        module=_mods6[i],
        finding=Finding(ip=f"10.0.0.{5+i}", port=21, proto=Proto.TCP, title="t",
                        cves=[f"CVE-2020-{i}"])) for i in range(2)]
    _res6 = _L6.verify_many(_cands6, timeout=2, require_confirm=False)
    check("a timed-out batch still returns results rather than losing them all",
          len(_res6) == 2, f"got {len(_res6)}")

print("\n--- batch verification streams too, not just single exploits ---")
# verify_many is the longest single msfconsole session Vision runs, so it is
# where a static spinner is most misleading — it was left on the old blocking
# path when run() was converted.
import inspect as _insp6
check("verify_many accepts an on_line callback",
      "on_line" in _insp6.signature(ExploitLauncher.verify_many).parameters)
check("verify_many uses the streaming runner, not the blocking one",
      "_stream_run" in _insp6.getsource(ExploitLauncher.verify_many))

print("\n--- the operator is told WHY each module was suggested ---")
# A module name alone asks the operator to take the match on faith. A CVE
# match and a fuzzy product-name guess deserve very different levels of trust
# before anything is fired, and match_reason existed but was never displayed.
from vision.cli import candidate_table as _ct

_mods_w = [
    MsfModule(fullname="exploit/windows/smb/ms17_010_eternalblue", path="/x",
              name="EB", rank="Great", cves=["CVE-2017-0144"], has_check=True),
    MsfModule(fullname="auxiliary/scanner/smb/smb_login", path="/x",
              name="L", rank="Normal", cves=[], has_check=False),
]
_idx_w = MsfIndex(modules=_mods_w)
_adv_w = ExploitAdvisor(_idx_w, Scope.from_lists(["10.0.0.0/24"]))
_f_cve = Finding(ip="10.0.0.5", port=445, proto=Proto.TCP, title="MS17-010",
                 cves=["CVE-2017-0144"], severity=Severity.CRITICAL)
_f_prod = Finding(ip="10.0.0.6", port=445, proto=Proto.TCP, title="SMB",
                  severity=Severity.MEDIUM)
_svcs_w = [Service(ip="10.0.0.6", port=445, proto=Proto.TCP, name="smb",
                   product="smb")]
_c_w = _adv_w.advise([_f_cve, _f_prod], _svcs_w)

check("a CVE match records the CVE as its reason",
      any(c.match_reason.startswith("cve:CVE-2017-0144") for c in _c_w))
check("a fuzzy product match records the product as its reason",
      any(c.match_reason.startswith("product:") for c in _c_w))
_table = _ct(_c_w)
check("the rendered table has a WHY column", "WHY" in _table)
check("a confirmed CVE is shown by name in the table",
      "CVE-2017-0144" in _table)
check("a fuzzy guess is visually marked as approximate",
      "~smb" in _table, "an operator must be able to tell a guess from a match")

print("\n--- auxiliary modules reach the operator, not just exploits ---")
# Auxiliary modules -- scanners, login checkers, gatherers -- are the safer
# half of Metasploit and are usually what an assessment wants for a service
# with no known CVE. They were indexed and permitted by the safety gate, but
# the fallback search asked only for kind="exploit", so they never appeared.
check("an auxiliary module is suggested for a service with no CVE",
      any(c.module.kind == "auxiliary" for c in _c_w),
      str([c.module.fullname for c in _c_w]))
check("exploits still rank ahead of auxiliary modules",
      [c.module.kind for c in _c_w].index("exploit")
      < [c.module.kind for c in _c_w].index("auxiliary"))
check("the safety gate already permitted auxiliary — this was purely a "
      "discovery gap",
      "auxiliary" in _insp6.getsource(ExploitLauncher.preflight))

print("\n--- root is detected across every real id/getuid shape ---")
# The root patterns originally recognised only uid=0(root), the two SYSTEM
# forms, and a bare `root` on its own line. Three real privileged transcripts
# slipped through and were reported as unprivileged user sessions — silently
# downgrading a demonstrated root compromise from critical to high in a
# client's report. The direction of the bug is under-claiming, not over-
# claiming, but a proven root shell described as "user" is still wrong.
_ROOT_SHAPES = [
    ("linux meterpreter getuid prints 'Server username: root'",
     "[*] Meterpreter session 1 opened (a -> b)\n"
     "Server username: root\nComputer     : mtsp\nOS           : Ubuntu 8.04"),
    ("comma-form id from a busybox/embedded shell",
     "[*] Command shell session 3 opened (a -> b)\n"
     "uid=0, gid=0, euid=0, egid=0\nLinux embedded 3.2.0 armv7l"),
    ("bare uid=0 with no (root) suffix",
     "[*] Meterpreter session 3 opened (a -> b)\nuid=0"),
]
for _why, _tx in _ROOT_SHAPES:
    _rp = parse_proof(_tx)
    check(f"root recognised: {_why}", _rp.is_root and _rp.privilege == "privileged",
          f"is_root={_rp.is_root} user={_rp.user!r}")
    _rf = proof_finding(_rp, _cand)
    check(f"and the finding is critical: {_why}", _rf["severity"] == "critical")

# The widening must not turn a normal account into a false root claim. uid=0
# is anchored to a token boundary, so a non-zero uid can never match it.
_NOT_ROOT = [
    ("uid=33(www-data) gid=33(www-data)", "www-data"),
    ("uid=1000(alice) gid=1000(alice)", "alice"),
    ("Server username: CORP\\jdoe", "jdoe"),
    ("uid=0333(oddaccount) gid=0333", "0-then-digit is not uid 0"),
]
for _tx, _who in _NOT_ROOT:
    _nr = parse_proof("[*] Command shell session 5 opened (a -> b)\n" + _tx)
    check(f"not falsely root: {_who}", not _nr.is_root,
          f"is_root leaked True for {_tx!r}")

print("\n--- the cross-host worklist orders work without firing anything ---")
# The worklist is the answer to "handle every finding efficiently" that does
# NOT become mass-exploitation: it ranks and orders, each entry still one
# module against one host behind one typed confirmation. It must put the
# strongest lead first, keep destructive modules last-but-visible, and never
# batch an exploit.
def _wl_mod(name, rank, check_=False, destructive=False, cves=None):
    return MsfModule(fullname=name, path="/x", name=name.split("/")[-1],
                     rank=rank, cves=cves or [], has_check=check_,
                     destructive=destructive)

def _wl_cand(module, ip, port, sev, cve_match=False, conf=Confidence.TENTATIVE):
    _f = Finding(ip=ip, port=port, proto=Proto.TCP, title="t", severity=sev,
                 cves=module.cves if cve_match else [])
    return ExploitCandidate(
        module=module, finding=_f,
        match_reason=("cve:" + module.cves[0]) if cve_match else "product:svc",
        confidence=conf)

_wadv = ExploitAdvisor(MsfIndex([]), Scope.from_lists(["192.168.88.0/24"]))
_wcands = [
    _wl_cand(_wl_mod("exploit/unix/ftp/vsftpd_234_backdoor", "Excellent", True,
                     cves=["CVE-2011-2523"]),
             "192.168.88.128", 21, Severity.CRITICAL, True, Confidence.CONFIRMED),
    _wl_cand(_wl_mod("exploit/multi/samba/usermap_script", "Excellent", True,
                     cves=["CVE-2007-2447"]),
             "192.168.88.128", 139, Severity.CRITICAL, True),
    _wl_cand(_wl_mod("auxiliary/scanner/ssh/ssh_login", "Normal", True),
             "192.168.88.130", 22, Severity.MEDIUM),
    _wl_cand(_wl_mod("exploit/windows/smb/ms08_067_netapi", "Great", True, True,
                     cves=["CVE-2008-4250"]),
             "192.168.88.130", 445, Severity.CRITICAL, True),
]
_plan = _wadv.worklist(_wcands)
check("every candidate appears as a step", len(_plan) == len(_wcands))
check("steps are numbered from 1 with no gaps",
      [p["step"] for p in _plan] == list(range(1, len(_plan) + 1)))
_host_order = list(dict.fromkeys(p["host"] for p in _plan))
check("the host with the strongest lead comes first",
      _host_order[0] == "192.168.88.128",
      f"host order was {_host_order}")
check("hosts are not interleaved — each appears as one contiguous block",
      len(_host_order) == len(set(_host_order)))
_locked = [p for p in _plan if p["locked"]]
check("the destructive module is flagged locked", len(_locked) == 1)
check("the destructive module is ranked last within its host",
      _plan[-1]["locked"] is True,
      "a destructive exploit should never be the first thing an operator sees")
check("each step names why it was selected",
      all(p["why"] for p in _plan))
check("each step declares verify-first when a check exists",
      _plan[0]["verify_first"] is True)

# verified_only narrows to what a check has already confirmed.
_vplan = _wadv.worklist(_wcands, verified_only=True)
check("verified-only keeps only confirmed candidates",
      all(p["confidence"] == "confirmed" for p in _vplan) and len(_vplan) == 1)

# The rendering is plain text an operator can read; it must not be empty and
# must mention the locked flag so a destructive step cannot hide in a wall.
_txt = _wadv.render_worklist(_plan)
check("the rendered worklist is non-empty", bool(_txt.strip()))
check("the rendering surfaces the LOCKED flag", "LOCKED" in _txt)
check("an empty worklist renders a readable message",
      "no exploit" in _wadv.render_worklist([]))

# The whole point: there is no batch-exploit path hiding in the worklist.
check("worklist returns plain data, not a launcher — it cannot fire",
      all(isinstance(p, dict) for p in _plan))

print("\n--- has_check excludes modules whose check() only returns Unsupported ---")
# From a real Metasploitable run: the advisory offered usermap_script as
# "verify-only", but msfconsole answered "This module does not support check."
# The index saw `def check` and believed it; the method was an Unsupported stub.
# An advisory promising a check that errors at runtime wastes the operator's
# one confirmation step. has_check must mirror what msfconsole will actually do.
from vision.analysis.msf_index import (
    _module_has_usable_check, _module_platforms)

_WORKING_CHECK = ("def check\n"
                  "  res = send_request_cgi('uri' => '/')\n"
                  "  return Exploit::CheckCode::Vulnerable if res\n"
                  "  Exploit::CheckCode::Safe\nend\n")
_STUB_CHECKS = [
    "def check\n  Exploit::CheckCode::Unsupported\nend\n",
    "def check\n  CheckCode::Unsupported\nend\n",
    "def check\n  return Exploit::CheckCode::Unsupported\nend\n",
    "def check\n  # cannot be safely checked\n  Exploit::CheckCode::Unsupported\nend\n",
]
check("a real check method is recognised as usable",
      _module_has_usable_check(_WORKING_CHECK))
for i, _stub in enumerate(_STUB_CHECKS):
    check(f"an Unsupported check stub is not counted as a check (variant {i})",
          not _module_has_usable_check(_stub))
check("no check method at all is not a check",
      not _module_has_usable_check("def exploit\n  connect\nend\n"))

print("\n--- module platform is parsed so cross-platform matches can be seen ---")
# Also from the real run: a Windows-only Apache DoS (CVE-2010-0425, mod_isapi)
# was CVE-joined to a Linux target and shown as a critical lead. The CVE match
# was precise; the module's platform was never considered. Parsing the module's
# platform is the first half of catching that — an empty set means neutral and
# must never be mistaken for a clash.
check("a windows module reports the windows platform",
      _module_platforms("exploit/windows/smb/ms08_067_netapi") == frozenset({"windows"}))
check("a linux module reports linux",
      _module_platforms("exploit/linux/ftp/x") == frozenset({"linux"}))
check("a unix module reports unix",
      _module_platforms("exploit/unix/ftp/vsftpd_234_backdoor") == frozenset({"unix"}))
check("a multi/scanner module is platform-neutral (empty, never a clash)",
      _module_platforms("exploit/multi/samba/usermap_script") == frozenset()
      and _module_platforms("auxiliary/scanner/ssh/ssh_enumusers") == frozenset())
check("platform is read from the Platform field when the path is neutral",
      _module_platforms("auxiliary/dos/http/apache_mod_isapi",
                        "Platform => 'win',") == frozenset({"windows"}))

print("\n--- exploit runs auto-supply LHOST so a reverse default payload validates ---")
# Field-discovered: modern Metasploit defaults vsftpd (and many modules) to a
# *reverse* payload, which fails with "OptionValidateError: LHOST" when LHOST is
# unset. Vision set only RHOSTS and relied on the default payload, so its own
# exploit path would die before firing — exactly what an operator hit by hand.
# The fix supplies LHOST from the interface toward the target, without pinning a
# payload name (names change across msf versions — cmd/unix/interact was
# removed). check() delivers no payload and must stay LHOST-free.
from vision.analysis.exploit_advisor import local_ip_toward, ExploitLauncher
from unittest.mock import patch

_llmod = MsfModule(fullname="exploit/unix/ftp/vsftpd_234_backdoor", path="/x",
                   name="x", rank="Excellent", has_check=True)
_llf = Finding(ip="192.168.88.128", port=21, proto=Proto.TCP, title="t",
               severity=Severity.CRITICAL)
_llc = ExploitCandidate(module=_llmod, finding=_llf, match_reason="cve:x")
_lll = ExploitLauncher(Scope.from_lists(["192.168.88.0/24"]),
                       audit_log=str(Path(tempfile.mkdtemp()) / "a.jsonl"))

# local_ip_toward probes the live routing table; patch so the test is
# deterministic regardless of the execution environment.
with patch("vision.analysis.exploit_advisor.local_ip_toward",
           return_value="192.168.1.100"):
    _exploit_rc = _lll._resource_script(_llc, "exploit", None)
    _check_rc = _lll._resource_script(_llc, "check", None)
check("the exploit script sets LHOST", "set LHOST" in _exploit_rc)
check("the check script does NOT set LHOST (no payload delivered)",
      "set LHOST" not in _check_rc)
check("an operator-pinned payload suppresses auto-LHOST",
      "set LHOST 10.9.9.9" in _lll._resource_script(
          _llc, "exploit", {"PAYLOAD": "cmd/unix/reverse_netcat",
                            "LHOST": "10.9.9.9"}))
check("local_ip_toward returns an address or None, never raises",
      local_ip_toward("192.168.88.128") is None
      or isinstance(local_ip_toward("192.168.88.128"), str))

print("\n" + "=" * 50)
print(f"{'ALL PASS' if not fails else 'FAILURES: ' + ', '.join(fails)}")
sys.exit(1 if fails else 0)
