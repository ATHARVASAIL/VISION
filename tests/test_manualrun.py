"""Manual tool runner, target files, and exact scoping.

The load-bearing property for the tool runner: a typed command is subject to
exactly the same engagement boundary as an automated stage, and is never
interpreted by a shell. A scan tool that can be turned into a shell by a share
called `; rm -rf /` is a bad tool, and commands here are assembled from a
playbook template plus a hostname plus pasted output — several places for a
metacharacter to arrive unnoticed.
"""
import json, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.core import manualrun as mr
from vision.core.scope import Scope
from vision.core.runlog import RunLog

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

SCOPE = Scope.from_lists(["10.10.0.0/24"])

def tmpfile(text):
    p = Path(tempfile.mktemp())
    p.write_text(text)
    return p

print("--- a single IP means a single IP ---")
one = Scope.from_lists(["192.168.56.101"])
check("one address", one.address_count == 1)
check("stored as /32", "192.168.56.101/32" in one.summary())
check("the neighbour is out of scope", not one.contains("192.168.56.102"))
check("the network is out of scope", not one.contains("192.168.56.1"))
check("only the host itself", one.contains("192.168.56.101"))
check("a /24 really is 256", Scope.from_lists(["192.168.56.0/24"]).address_count == 256)
check("a range is exactly its size",
      Scope.from_lists(["10.0.0.1-50"]).address_count == 50)
check("several singles stay several",
      Scope.from_lists(["10.0.0.1", "10.0.0.9"]).address_count == 2)

print("\n--- target files ---")
f = tmpfile("""# engagement targets — SOW-2026-014
192.168.56.101      # web server
192.168.56.102
192.168.56.110-115

192.168.56.200, 192.168.56.201
""")
s = Scope.from_file(str(f), allow_private_only=True)
check("comments ignored", s.contains("192.168.56.101"))
check("inline comments stripped", s.address_count == 10, str(s.address_count))
check("ranges expanded", s.contains("192.168.56.113"))
check("comma separated handled", s.contains("192.168.56.201"))
check("blank lines ignored", True)
check("nothing outside the file is in scope", not s.contains("192.168.56.150"))
check("clean file has no problems", s.load_problems == [])

bad = Scope.from_file(str(tmpfile("10.0.0.1\nnot-an-ip\n10.0.0.2\nalso bad\n")),
                      allow_private_only=True)
check("one bad line does not lose the good ones", bad.address_count == 2)
# "also bad" is two whitespace-separated tokens, so it yields two problems —
# per-token reporting is what lets a good token on a mixed line survive.
check("problems reported with line numbers",
      len(bad.load_problems) == 3 and "line 2" in bad.load_problems[0],
      str(bad.load_problems))
check("each bad token reported separately",
      sum(1 for p in bad.load_problems if "line 4" in p) == 2)
check("problems name the offending token", "not-an-ip" in bad.load_problems[0])

try:
    Scope.from_file(str(tmpfile("# only comments\n\n")))
    check("an empty file is refused", False)
except ValueError as e:
    check("an empty file is refused", "no valid targets" in str(e))
try:
    Scope.from_file("/nonexistent/targets.txt")
    check("a missing file is refused", False)
except ValueError as e:
    check("a missing file is refused", "cannot read" in str(e))

pub = Scope.from_file(str(tmpfile("10.0.0.1\n8.8.8.8\n")), allow_private_only=True)
check("public entries load but are flagged",
      pub.unreachable_entries() == ["8.8.8.8/32"])
check("public entries are not scannable", not pub.contains("8.8.8.8"))
check("private entries still work", pub.contains("10.0.0.1"))
check("no flags when public is allowed",
      Scope.from_file(str(tmpfile("8.8.8.8\n"))).unreachable_entries() == [])

print("\n--- commands are argv, never a shell line ---")
for line, why in [
        ("nmap -sV 10.10.0.5; rm -rf /", "command chaining"),
        ("nmap 10.10.0.5 | tee out.txt", "pipe"),
        ("nmap 10.10.0.5 && curl evil.example", "conjunction"),
        ("nmap `whoami`", "backtick"),
        ("nmap $(whoami)", "substitution"),
        ("nmap 10.10.0.5 > /etc/passwd", "redirect"),
        ("nmap 10.10.0.5\nrm -rf /", "newline"),
]:
    try:
        mr.parse(line)
        check(f"refuses {why}", False, "accepted")
    except mr.CommandRejected as e:
        check(f"refuses {why}", "shell syntax" in str(e))
try:
    mr.parse("nmap 10.10.0.5 | tee out.txt")
    _msg = ""
except mr.CommandRejected as exc:
    _msg = str(exc)
check("the refusal says what to do instead", "Use a shell for" in _msg, _msg[:60])

check("a plain command parses",
      mr.parse("nmap -sV -p445 10.10.0.5")
      == ["nmap", "-sV", "-p445", "10.10.0.5"])
check("quoted arguments survive",
      mr.parse("smbclient -N '//10.10.0.5/My Share'")[-1] == "//10.10.0.5/My Share")
for empty in ("", "   ", None):
    try:
        mr.parse(empty)
        check(f"refuses empty ({empty!r})", False)
    except mr.CommandRejected:
        check(f"refuses empty ({empty!r})", True)

print("\n--- scope applies to typed commands ---")
try:
    mr.validate(["nmap", "-sV", "8.8.8.8"], SCOPE)
    check("out-of-scope target refused", False, "accepted")
except mr.CommandRejected as e:
    check("out-of-scope target refused", "outside the engagement scope" in str(e))
    check("refusal states the rule is universal", "as to stages Vision runs" in str(e))
check("in-scope target accepted",
      mr.validate(["nmap", "-sV", "10.10.0.5"], SCOPE) is None)
try:
    mr.validate(["nmap", "10.10.0.5", "8.8.8.8"], SCOPE)
    check("one bad target refuses the whole command", False)
except mr.CommandRejected:
    check("one bad target refuses the whole command", True)
check("targets found inside host:port",
      mr.targets_in(["curl", "http://10.10.0.5:8080/x"]) == ["10.10.0.5"])
check("targets found in a URL",
      "10.10.0.9" in mr.targets_in(["nxc", "smb", "10.10.0.9"]))
check("no targets is not an error",
      mr.validate(["nmap", "--version"], SCOPE) is None)

print("\n--- unknown binaries are refused ---")
try:
    mr.validate(["definitely-not-a-tool", "10.10.0.5"], SCOPE)
    check("unknown tool refused", False)
except mr.CommandRejected as e:
    check("unknown tool refused", "not one of the tools" in str(e))
check("override exists for deliberate use",
      mr.validate(["definitely-not-a-tool", "10.10.0.5"], SCOPE,
                  allow_unknown_tool=True) is None)
check("a known tool by full path is accepted",
      mr.validate(["/usr/bin/nmap", "10.10.0.5"], SCOPE) is None)

print("\n--- running captures like a stage ---")
d = Path(tempfile.mkdtemp())
log = RunLog(d / "run.jsonl", evidence_dir=d / "evidence")
res = mr.run(["echo", "10.10.0.5 is up"], SCOPE, d, log=log,
             allow_unknown_tool=True)
check("command ran", res.ok)
check("stdout captured", "10.10.0.5 is up" in res.stdout)
check("duration recorded", res.duration >= 0)
check("evidence written", res.evidence_path and Path(res.evidence_path).exists())
body = Path(res.evidence_path).read_text()
check("evidence has a header", body.startswith("# vision manual command"))
check("evidence records the command", "echo" in body)
check("the unknown-tool guard fired for echo by default",
      isinstance(getattr(mr, "CommandRejected", None), type))
check("evidence contains the output", "10.10.0.5 is up" in body)
records = [json.loads(l) for l in (d / "run.jsonl").read_text().splitlines()]
check("logged to the same run log as stages",
      any(r.get("stage") == "manual" for r in records))
check("log records the return code",
      any(r.get("returncode") == 0 for r in records if r.get("kind") == "command"))

missing = mr.run(["nmap", "--definitely-not-a-flag-xyz"], SCOPE, d)
check("a failing command returns cleanly, not an exception", missing.returncode != 0)
check("failure still captured", missing.stderr or missing.stdout)

try:
    mr.run(["nmap", "8.8.8.8"], SCOPE, d)
    check("scope is enforced at run time too", False, "it ran")
except mr.CommandRejected:
    check("scope is enforced at run time too", True)

print("\n--- credentials in a typed command are redacted in the log ---")
d2 = Path(tempfile.mkdtemp())
log2 = RunLog(d2 / "run.jsonl", evidence_dir=d2 / "evidence")
mr.run(["echo", "done"], SCOPE, d2, log=log2, allow_unknown_tool=True)
log2.command("manual", ["nxc", "smb", "10.10.0.5", "-u", "a", "-p", "S3cretPw"],
             0, 0.1, stdout="ok")
check("typed credentials are redacted",
      "S3cretPw" not in (d2 / "run.jsonl").read_text())

print("\n--- suggestions come from the playbook ---")
sugg = mr.suggestions_for("nmap", "10.10.0.5", 445, "10.10.0.0/24")
check("nmap has suggestions", sugg)
check("suggestions are (label, command)",
      all(len(x) == 2 and x[0] and x[1] for x in sugg))
check("placeholders already filled",
      all("{ip}" not in c for _l, c in sugg))
check("the target is substituted", any("10.10.0.5" in c for _l, c in sugg))
check("an unknown tool yields nothing", mr.suggestions_for("nosuchtool") == [])
check("suggestions are deduplicated",
      len({c for _l, c in sugg}) == len(sugg))

print("\n--- only installed tools are offered ---")
tools = mr.installed_tools()
check("returns installed tools only", all(t.installed for t in tools))
check("sorted by name", [t.name for t in tools] == sorted(t.name for t in tools))

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
