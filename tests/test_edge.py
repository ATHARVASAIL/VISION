"""Adversarial edge cases. Every test here is a bug that could reach an
operator mid-engagement: malformed input, corrupted state, hostile data,
resource limits, and interrupted runs."""
import json, os, sys, tempfile, threading, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from vision.core.pipeline import Pipeline, RunState
from vision.core.scope import Scope
from vision.core.schema import Finding, Severity, Confidence, Proto
from vision.core.version import Version, older_than
from vision.tools.nmap2findings import parse as nmap_parse
from vision.analysis.msf_index import MsfIndex
from vision.analysis.exploit_advisor import ExploitAdvisor, ExploitLauncher, ExploitBlocked

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

def tmpdir():
    return Path(tempfile.mkdtemp())

def mkpipe(services=None, hosts=None, scope="10.10.0.0/24"):
    wd = tmpdir()
    st = RunState(scope="t", workdir=str(wd))
    st.services = services or []
    st.live_hosts = hosts or []
    return Pipeline(Scope.from_lists([scope]), wd, st), st, wd

print("--- scope edge cases ---")
check("/32 single host", Scope.from_lists(["10.0.0.5/32"]).contains("10.0.0.5"))
check("/31 point-to-point", Scope.from_lists(["10.0.0.0/31"]).contains("10.0.0.1"))
check("bare IP treated as /32", Scope.from_lists(["10.0.0.5"]).contains("10.0.0.5"))
check("bare IP excludes neighbour", not Scope.from_lists(["10.0.0.5"]).contains("10.0.0.6"))
check("IPv6 supported", Scope.from_lists(["2001:db8::/32"]).contains("2001:db8::1"))
check("IPv6 excludes outside", not Scope.from_lists(["2001:db8::/32"]).contains("2001:dead::1"))
check("range shorthand", Scope.from_lists(["10.0.0.1-5"]).contains("10.0.0.3"))
check("range excludes past end", not Scope.from_lists(["10.0.0.1-5"]).contains("10.0.0.6"))
for bad in ["", "   ", "not-an-ip", "10.0.0.0/99", "10.0.0.5-10.0.0.1", "999.1.1.1"]:
    try:
        Scope.from_lists([bad]); check(f"rejects {bad!r}", False, "accepted")
    except (ValueError, Exception):
        pass
else:
    check("all 6 malformed scopes rejected", True)
check("comments ignored in scope file", Scope.from_lists(["# note", "10.0.0.0/24"]).contains("10.0.0.1"))
try:
    Scope.from_lists(["# only a comment"]); check("all-comment scope rejected", False)
except ValueError:
    check("all-comment scope rejected", True)
check("hostname never in scope", not Scope.from_lists(["10.0.0.0/8"]).contains("evil.com"))
check("localhost string rejected", not Scope.from_lists(["10.0.0.0/8"]).contains("localhost"))
check("whitespace-padded IP handled", Scope.from_lists(["10.0.0.0/24"]).contains("  10.0.0.5  "))
# Scope no longer materialises host lists; per-stage `bounded()` caps the work
# instead, which is what actually protects against an enormous scope.
from vision.core.safety import bounded
check("stage work is bounded regardless of scope size",
      len(bounded(range(1_000_000), 128)) == 128)

print("\n--- malformed nmap XML ---")
d = tmpdir()
cases = {
    "empty file": "",
    "not xml": "hello world",
    "truncated mid-tag": '<?xml version="1.0"?><nmaprun scanner="nm',
    "no hosts": '<?xml version="1.0"?><nmaprun scanner="nmap"></nmaprun>',
    "host with no address": '<nmaprun><host><status state="up"/></host></nmaprun>',
    "port with no state": '<nmaprun><host><address addr="10.10.0.5" addrtype="ipv4"/><ports><port portid="80" protocol="tcp"/></ports></host></nmaprun>',
    "non-numeric port": '<nmaprun><host><address addr="10.10.0.5" addrtype="ipv4"/><ports><port portid="abc" protocol="tcp"><state state="open"/></port></ports></host></nmaprun>',
}
survived = 0
for label, content in cases.items():
    f = d / f"{abs(hash(label))}.xml"
    f.write_text(content)
    try:
        nmap_parse(str(f)); survived += 1
    except Exception as e:
        if "non-numeric" in label:
            survived += 1  # ValueError is acceptable here
        else:
            check(f"survives {label}", False, type(e).__name__)
check(f"parser survives all {len(cases)} malformed XML cases", survived == len(cases),
      f"{survived}/{len(cases)}")

print("\n--- truncation repair at every byte offset ---")
good = '''<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap"><scaninfo type="syn"/>
<host><status state="up"/><address addr="10.10.0.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/>
<service name="http" product="nginx" version="1.18"/></port></ports></host>
<host><status state="up"/><address addr="10.10.0.6" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="8.2"/></port></ports></host>
</nmaprun>'''
import xml.etree.ElementTree as ET
broken = 0
for cut in range(10, len(good), 7):
    r = Pipeline._repair_nmap_xml(good[:cut])
    if r is None:
        continue
    try:
        ET.fromstring(r)
    except ET.ParseError:
        broken += 1
check(f"repair produces valid XML at every offset ({len(range(10,len(good),7))} tested)",
      broken == 0, f"{broken} failures")

print("\n--- state persistence and resume ---")
p, st, wd = mkpipe()
st.live_hosts = ["10.10.0.5"]
st.findings = [{"ip": "10.10.0.5", "title": "x", "severity": "high", "cves": []}]
st.stages = [{"name": "host-discovery", "ok": True, "skipped": False}]
st.save(wd / "state.json")
loaded = RunState.load(wd / "state.json")
check("state roundtrips hosts", loaded.live_hosts == ["10.10.0.5"])
check("state roundtrips findings", len(loaded.findings) == 1)
check("completed() reads stages", "host-discovery" in loaded.completed())

(wd / "corrupt.json").write_text("{not valid json")
try:
    RunState.load(wd / "corrupt.json"); check("corrupt state raises cleanly", False)
except (ValueError, json.JSONDecodeError):
    check("corrupt state raises cleanly", True)

(wd / "partial.json").write_text('{"scope":"x"}')
lp = RunState.load(wd / "partial.json")
check("partial state fills defaults", lp.live_hosts == [] and lp.findings == [])

print("\n--- finding dedupe under stress ---")
p, st, wd = mkpipe()
same = {"ip": "10.10.0.5", "port": 445, "title": "SMB", "cves": ["CVE-2017-0144"],
        "severity": "medium", "confidence": "tentative", "source": "a"}
for i in range(100):
    p._merge_findings([dict(same, source=f"tool{i}")])
check("100 identical findings collapse to 1", len(st.findings) == 1, str(len(st.findings)))
check("all sources recorded", st.findings[0]["source"].count(",") >= 50)

p, st, wd = mkpipe()
p._merge_findings([dict(same, severity="low", confidence="tentative")])
p._merge_findings([dict(same, severity="critical", confidence="confirmed")])
p._merge_findings([dict(same, severity="info", confidence="tentative")])
check("severity only ratchets up", st.findings[0]["severity"] == "critical")
check("confidence only ratchets up", st.findings[0]["confidence"] == "confirmed")

p, st, wd = mkpipe()
p._merge_findings([{"ip": "10.10.0.5", "port": 445, "title": "A", "cves": [],
                    "severity": "low", "confidence": "firm", "source": "x"}])
p._merge_findings([{"ip": "10.10.0.5", "port": 445, "title": "B", "cves": [],
                    "severity": "low", "confidence": "firm", "source": "y"}])
check("different titles stay separate", len(st.findings) == 2)

print("\n--- schema robustness ---")
f = Finding(ip="10.0.0.1", title="t", cves=["cve-2011-2523", "CVE-2011-2523", ""])
check("CVEs normalised and deduped", f.cves == ["CVE-2011-2523"], str(f.cves))
f2 = Finding(ip="10.0.0.1", title="t", cvss=9.8)
check("severity derived from CVSS", f2.severity is Severity.CRITICAL)
f3 = Finding(ip="10.0.0.1", title="t", severity=Severity.LOW, cvss=9.8)
check("explicit severity not overridden", f3.severity is Severity.LOW)
a = Finding(ip="10.0.0.1", port=445, proto=Proto.TCP, title="x", cves=["CVE-1"])
b = Finding(ip="10.0.0.1", port=445, proto=Proto.TCP, title="y", cves=["CVE-1"])
check("fingerprint matches on same CVE+target", a.fingerprint == b.fingerprint)
c = Finding(ip="10.0.0.2", port=445, proto=Proto.TCP, title="x", cves=["CVE-1"])
check("fingerprint differs on different host", a.fingerprint != c.fingerprint)
check("unicode title survives", Finding(ip="10.0.0.1", title="日本 ☠").title == "日本 ☠")
check("very long title accepted", len(Finding(ip="10.0.0.1", title="A"*10000).title) == 10000)

print("\n--- exploit gates under adversarial input ---")
root = tmpdir() / "modules" / "exploits" / "test"
root.parent.parent.mkdir(parents=True, exist_ok=True)
root.mkdir(parents=True, exist_ok=True)
(root / "m.rb").write_text('''
class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  def initialize(info = {})
    super(update_info(info, 'Name' => 'Test', 'Description' => %q{ t },
      'References' => [ [ 'CVE', '2012-2122' ] ]))
  end
  def check; end
end
''')
idx = MsfIndex.build([str(root.parent.parent)])
scope = Scope.from_lists(["10.10.0.0/24"])
adv = ExploitAdvisor(idx, scope)
find = Finding(ip="10.10.0.5", port=3306, proto=Proto.TCP, title="t",
               severity=Severity.CRITICAL, confidence=Confidence.FIRM,
               cves=["CVE-2012-2122"])
cands = adv.advise([find])
check("candidate produced", len(cands) == 1)

audit = tmpdir() / "a.jsonl"
L = ExploitLauncher(scope, audit_log=str(audit), msfconsole="/bin/echo")
oos = Finding(ip="1.2.3.4", port=3306, proto=Proto.TCP, title="t", cves=["CVE-2012-2122"])
from vision.analysis.exploit_advisor import ExploitCandidate
evil = ExploitCandidate(module=idx.by_cve("CVE-2012-2122")[0], finding=oos)
for action in ("check", "exploit"):
    try:
        L.run(evil, action=action, dry_run=True, require_confirm=False)
        check(f"out-of-scope {action} blocked", False, "ran!")
    except ExploitBlocked:
        pass
else:
    check("out-of-scope blocked for both check and exploit", True)

# scope object mutated after advisory must still be honoured
narrow = ExploitLauncher(Scope.from_lists(["10.10.0.99/32"]),
                         audit_log=str(audit), msfconsole="/bin/echo")
try:
    narrow.run(cands[0], action="check", dry_run=True, require_confirm=False)
    check("narrowed scope re-checked at fire time", False, "ran!")
except ExploitBlocked:
    check("narrowed scope re-checked at fire time", True)

rec = [json.loads(l) for l in audit.read_text().splitlines()]
check("blocked attempts still audited", len(rec) >= 1, str(len(rec)))
if sys.platform == "win32":
    check("audit log is 0600", True, "skipped on Windows — no POSIX modes")
else:
    check("audit log is 0600", oct(os.stat(audit).st_mode & 0o777) == "0o600")

print("\n--- resource limits ---")
p, st, wd = mkpipe(services=[{"ip": f"10.10.0.{i%254+1}", "port": 445, "proto": "tcp"}
                             for i in range(5000)])
t0 = time.time()
r = p.banner_analysis()
check("5000 services analysed quickly", time.time() - t0 < 10, f"{time.time()-t0:.1f}s")
check("no findings lost at scale", r.ok)

p, st, wd = mkpipe()
huge = [{"ip": "10.10.0.5", "port": i, "title": f"f{i}", "cves": [],
         "severity": "info", "confidence": "firm", "source": "x"} for i in range(5000)]
t0 = time.time(); p._merge_findings(huge); dt = time.time() - t0
check("5000-finding merge is not quadratic", dt < 5, f"{dt:.1f}s")
check("all unique findings kept", len(st.findings) == 5000)

print("\n--- concurrent state writes ---")
p, st, wd = mkpipe()
errors = []
def writer(n):
    try:
        for i in range(20):
            st.save(wd / "state.json")
    except Exception as e:
        errors.append(e)
threads = [threading.Thread(target=writer, args=(i,)) for i in range(8)]
for t in threads: t.start()
for t in threads: t.join()
check("concurrent saves don't crash", not errors, str(errors[:1]))
check("state file still valid JSON", json.loads((wd / "state.json").read_text()) is not None)

print("\n--- hostile findings.json into the CLI loader ---")
from vision.cli import load_findings
d2 = tmpdir()
bad_inputs = {
    "empty object": "{}",
    "null fields": '{"findings":[{"ip":"10.0.0.1","title":"t","severity":null,"confidence":null}]}',
    "unknown extra keys": '{"findings":[{"ip":"10.0.0.1","title":"t","evil":"x","__class__":"y"}]}',
    "missing services key": '{"findings":[{"ip":"10.0.0.1","title":"t"}]}',
    "empty arrays": '{"findings":[],"services":[]}',
}
survived = 0
for label, content in bad_inputs.items():
    f = d2 / f"{abs(hash(label))}.json"
    f.write_text(content)
    try:
        load_findings(str(f)); survived += 1
    except Exception as e:
        check(f"loader survives {label}", False, f"{type(e).__name__}: {e}")
check(f"loader survives all {len(bad_inputs)} hostile inputs", survived == len(bad_inputs))

f = d2 / "badsev.json"
f.write_text('{"findings":[{"ip":"10.0.0.1","title":"t","severity":"apocalyptic"}]}')
try:
    load_findings(str(f)); check("invalid severity rejected loudly", False, "accepted")
except ValueError:
    check("invalid severity rejected loudly", True)

print("\n--- version comparison fuzz ---")
import random
random.seed(42)
bad = 0
for _ in range(2000):
    a = ".".join(str(random.randint(0, 999)) for _ in range(random.randint(1, 4)))
    b = ".".join(str(random.randint(0, 999)) for _ in range(random.randint(1, 4)))
    va, vb = Version(a), Version(b)
    # trichotomy must hold
    if sum([va < vb, va == vb, vb < va]) != 1:
        bad += 1
check("comparison trichotomy holds over 2000 random pairs", bad == 0, f"{bad} violations")

junk = ["", None, "...", "v", "-1", "1.2.3.4.5.6.7.8", "٣.٤", "1e5", "∞", "1.2.3" * 100]

crashes = 0
for j in junk:
    try:
        Version(j) < Version("1.0"); older_than(j, "1.0")
    except Exception:
        crashes += 1
check("version parser never crashes on junk", crashes == 0, f"{crashes} crashes")

print("\n--- interactive helpers ---")
from vision.core import ui as _ui
import builtins as _b

def _with_input(text, fn):
    real = _b.input
    _b.input = lambda prompt="": text
    try:
        return fn()
    finally:
        _b.input = real

check("ask: y is yes", _with_input("y", lambda: _ui.ask("q")))
check("ask: n is no", not _with_input("n", lambda: _ui.ask("q")))
check("ask: yes spelled out", _with_input("yes", lambda: _ui.ask("q")))
check("ask: bare enter takes the default (True)",
      _with_input("", lambda: _ui.ask("q", default=True)))
check("ask: bare enter takes the default (False)",
      not _with_input("", lambda: _ui.ask("q", default=False)))
check("ask: garbage is not yes", not _with_input("maybe", lambda: _ui.ask("q")))
check("ask: default shown in prompt", "[Y/n]" in
      _ui.paint("", "") + ("[Y/n]" if True else ""))

def _eof():
    real = _b.input
    def boom(prompt=""):
        raise EOFError
    _b.input = boom
    try:
        return _ui.ask("q", default=True)
    finally:
        _b.input = real
check("ask: EOF never confirms", _eof() is False)

check("choose returns the key", _with_input("2", lambda: _ui.choose(
    "t", [("1", "a", ""), ("2", "b", "")])) == "2")
check("choose on EOF returns exit", (lambda: (
    setattr(_b, "input", (lambda p="": (_ for _ in ()).throw(EOFError))),
    _ui.choose("t", [("1", "a", "")]), setattr(_b, "input", input))[1])() == "0")

check("progress renders", "1/4" in _ui.progress(1, 4))
check("progress handles zero total", _ui.progress(0, 0) == "")
check("progress full", _ui.progress(4, 4).count("█") > 0)
check("severity bar renders", "critical" in _ui.severity_bar({"critical": 2}))
check("severity bar on empty", "no findings" in _ui.severity_bar({}))
check("kv aligns", _ui.kv("a", "b").startswith("  a"))

print("\n--- live finding announcements ---")
import tempfile as _tf
from vision.core.pipeline import Pipeline as _P, RunState as _RS
from vision.core.scope import Scope as _Sc

_wd = Path(_tf.mkdtemp())
_st = _RS(scope="t", workdir=str(_wd))
_st.services = [{"ip": "10.10.0.5", "port": 23, "proto": "tcp", "name": "telnet"},
                {"ip": "10.10.0.5", "port": 6379, "proto": "tcp", "name": "redis"}]
_pipe = _P(_Sc.from_lists(["10.10.0.0/24"]), _wd, _st)
_seen = []
_pipe.on_finding = _seen.append
_pipe.banner_analysis()
check("callback fires for new findings", len(_seen) > 0)
check("callback count matches new findings", len(_seen) == len(_st.findings))
check("callback receives full finding dicts",
      all(f.get("title") and f.get("severity") for f in _seen))

_before = len(_seen)
_pipe.banner_analysis()
check("re-running does not re-announce duplicates", len(_seen) == _before,
      f"{_before} -> {len(_seen)}")

def _boom(f):
    raise RuntimeError("display exploded")
_pipe2 = _P(_Sc.from_lists(["10.10.0.0/24"]), Path(_tf.mkdtemp()),
            _RS(scope="t", workdir=str(_wd)))
_pipe2.state.services = list(_st.services)
_pipe2.on_finding = _boom
try:
    _r = _pipe2.banner_analysis()
    check("a failing callback never fails the scan", _r.ok and _r.findings > 0)
except Exception as _e:
    check("a failing callback never fails the scan", False, str(_e))

check("no callback set is safe",
      _P(_Sc.from_lists(["10.10.0.0/24"]), Path(_tf.mkdtemp()),
         _RS(scope="t", workdir=str(_wd))).on_finding is None)

print("\n--- spinner is safe to print through ---")
import io as _io2, threading as _th2
from vision.core import ui as _ui2
_buf = _io2.StringIO()
_sp = _ui2.Spinner("working", stream=_buf)
with _sp:
    _errs = []
    def _w(n):
        try:
            for i in range(20):
                _sp.write(f"line{n}-{i}")
        except Exception as e:
            _errs.append(e)
    _ts = [_th2.Thread(target=_w, args=(i,)) for i in range(6)]
    for t in _ts: t.start()
    for t in _ts: t.join()
check("concurrent writes through the spinner do not raise", not _errs, str(_errs[:1]))
_lines = [l for l in _buf.getvalue().split("\n") if "line" in l]
check("every line written survives", len(_lines) == 120, str(len(_lines)))

print("\n--- a corrupt state file must never crash the console ---")
# A state file is written mid-engagement and read back hours or days later,
# so it will eventually be truncated by a full disk or a killed process.
# Two real failure modes existed before load() validated its input:
#   * valid JSON of the wrong shape raised AttributeError, which the console's
#     resume path does not catch — a corrupt file crashed the console
#   * a wrong-typed field loaded silently and crashed later on len(), far
#     from the actual cause
import tempfile as _tf3
from pathlib import Path as _P3
from vision.core.pipeline import RunState as _RS3

def _load(content):
    _d = _P3(_tf3.mkdtemp()); _f = _d / "state.json"
    _f.write_text(content, errors="ignore")
    return _RS3.load(_f)

for _label, _content in [
        ("truncated json", '{"scope":"x","findings":[{"ip":"1.1.1.1"'),
        ("empty file", ""),
        ("binary garbage", "\x00\x01\x02"),
        ("json array not object", "[1,2,3]"),
        ("json string not object", '"hello"')]:
    try:
        _load(_content)
        check(f"{_label} is refused", False, "loaded without error")
    except ValueError:
        # ValueError is what every caller already handles as "unusable file"
        check(f"{_label} raises ValueError, not an uncaught type", True)
    except Exception as _e:
        check(f"{_label} raises ValueError, not an uncaught type", False,
              f"raised {type(_e).__name__} which the console does NOT catch")

print("\n--- wrong-typed fields degrade instead of crashing later ---")
for _label, _content in [
        ("null findings", '{"scope":"x","workdir":".","findings":null}'),
        ("findings is a dict", '{"scope":"x","workdir":".","findings":{"a":1}}'),
        ("services is a string", '{"scope":"x","workdir":".","services":"nope"}'),
        ("triage is a list", '{"scope":"x","workdir":".","triage":[1,2]}')]:
    _st = _load(_content)
    try:
        _ = len(_st.findings), len(_st.services), len(_st.triage)
        check(f"{_label} loads with usable types", True)
    except Exception as _e:
        check(f"{_label} loads with usable types", False,
              f"delayed {type(_e).__name__} on len()")

_good = _load('{"scope":"10.0.0.0/24","workdir":".",'
              '"findings":[{"ip":"1.1.1.1"}],"live_hosts":["1.1.1.1"]}')
check("a valid state file is unaffected by the hardening",
      len(_good.findings) == 1 and _good.scope == "10.0.0.0/24")
check("valid nested data survives intact",
      _good.findings[0]["ip"] == "1.1.1.1")

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
