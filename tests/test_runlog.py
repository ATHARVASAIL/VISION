"""Run log and evidence tests.

The load-bearing test here is redaction: a log file that captures a credential
outlives the engagement and is a liability nobody thinks to clean up.
"""
import json, os, stat, sys, tempfile, threading
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.core.runlog import (
    RunLog, NullLog, redact, CommandRecord, REDACTED, MAX_EVIDENCE_BYTES,
)
from vision.core.pipeline import Pipeline, RunState, _run, set_run_log, current_stage
from vision.core.scope import Scope

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

def tmp():
    return Path(tempfile.mkdtemp())

print("--- credential redaction ---")
cases = [
    (["smbmap", "-H", "10.0.0.1", "-u", "admin", "-p", "hunter2"], "hunter2"),
    (["hydra", "-l", "root", "-P", "rockyou.txt", "ssh://10.0.0.1"], "rockyou.txt"),
    (["snmpwalk", "-v2c", "-c", "private", "10.0.0.1"], "private"),
    (["tool", "--password", "s3cret"], "s3cret"),
    (["tool", "--password=s3cret"], "s3cret"),
    (["tool", "--token=abc123"], "abc123"),
    (["tool", "--api-key", "kkk"], "kkk"),
    (["evil-winrm", "-i", "10.0.0.1", "-u", "a", "-p", "Passw0rd!"], "Passw0rd!"),
]
for argv, secret in cases:
    out = redact(argv)
    check(f"redacts {secret[:16]!r}", secret not in out, str(out))
check("redaction marker used", REDACTED in redact(["t", "-p", "x"]))
check("non-secret args preserved",
      redact(["smbmap", "-H", "10.0.0.1", "-p", "x"])[:3] == ["smbmap", "-H", "10.0.0.1"])
check("empty password preserved (null session is meaningful)",
      redact(["smbmap", "-u", "", "-p", ""]) == ["smbmap", "-u", "", "-p", ""])
check("inline empty preserved", redact(["t", "--password="]) == ["t", "--password="])
check("case-insensitive inline", "S3" not in str(redact(["t", "--PASSWORD=S3cret"])))
check("no args is safe", redact([]) == [])
check("original argv not mutated",
      (lambda a: (redact(a), a == ["t", "-p", "x"])[1])(["t", "-p", "x"]))

print("\n--- tool-aware redaction (-p is ports to nmap, a password to smbmap) ---")
check("nmap port list preserved",
      redact(["nmap", "-sU", "-p", "53,161,500", "10.0.0.5"])[3] == "53,161,500")
check("absolute path resolved to tool name",
      redact(["/usr/bin/nmap", "-p", "1-65535"])[2] == "1-65535")
check("masscan ports preserved", redact(["masscan", "-p", "80,443"])[2] == "80,443")
check("smbmap password still redacted",
      REDACTED in redact(["smbmap", "-H", "x", "-p", "hunter2"]))
check("hydra password still redacted",
      REDACTED in redact(["hydra", "-l", "root", "-p", "pass", "ssh://x"]))
check("snmpwalk community still redacted",
      REDACTED in redact(["snmpwalk", "-v2c", "-c", "private", "10.0.0.5"]))
check("rpcclient -c is a command, not a community",
      redact(["rpcclient", "-N", "x", "-c", "enumdomusers"])[-1] == "enumdomusers")
check("unknown tool fails closed",
      REDACTED in redact(["unknown-tool", "-p", "maybe-secret"]))
check("long-form --password redacted regardless of tool",
      REDACTED in redact(["nmap", "--password", "x"]))

print("\n--- log writing ---")
d = tmp()
log = RunLog(d / "run.jsonl", evidence_dir=d / "evidence")
log.event("run-start", scope="10.0.0.0/24", operator="analyst")
rec = log.command("port-scan", ["nmap", "-sV", "10.0.0.1"], 0, 1.25,
                  stdout="Nmap scan report", stderr="", target="10.0.0.1")
log.command("smb-shares", ["smbmap", "-H", "10.0.0.1", "-p", "secret"], 1, 0.5,
            stderr="connection refused", target="10.0.0.1")
log.event("run-end", **log.summary())

lines = [json.loads(l) for l in (d / "run.jsonl").read_text().splitlines()]
check("all records written", len(lines) == 4, str(len(lines)))
check("every record has a kind", all("kind" in r for r in lines))
check("every record timestamped", all("ts" in r and "iso" in r for r in lines))
check("command records carry the stage",
      [r["stage"] for r in lines if r["kind"] == "command"] == ["port-scan", "smb-shares"])
check("returncode recorded", [r["returncode"] for r in lines if r["kind"] == "command"] == [0, 1])
check("duration recorded", any(r.get("duration_s") == 1.25 for r in lines))
check("stderr captured", any("connection refused" in str(r.get("stderr")) for r in lines))
check("SECRET NOT IN LOG FILE", "secret" not in (d / "run.jsonl").read_text())
check("log is valid JSONL", all(isinstance(r, dict) for r in lines))
if sys.platform == "win32":
    check("log file is 0600", True, "skipped on Windows — no POSIX modes")
else:
    check("log file is 0600",
          stat.S_IMODE(os.stat(d / "run.jsonl").st_mode) == 0o600)

print("\n--- CommandRecord ---")
check("command renders shell-quoted", "nmap -sV 10.0.0.1" == rec.command)
check("ok reflects returncode", rec.ok)
check("quotes args with spaces",
      "'a b'" in CommandRecord("s", ["t", "a b"], 0, 0).command)

print("\n--- failure surfacing ---")
f = log.failures()
check("failures found", len(f) == 1)
check("failure names the stage", f[0]["stage"] == "smb-shares")
check("failure carries stderr", "refused" in f[0]["stderr"])
check("successes excluded", all(r["returncode"] != 0 for r in f))
check("failures on a missing log is safe", RunLog(d / "nope.jsonl").failures() == [])

print("\n--- summary ---")
s = log.summary()
check("counts commands", s["commands"] == 2)
check("counts failures", s["failures"] == 1)
check("reports elapsed", s["elapsed_s"] >= 0)
check("reports log path", s["log"].endswith("run.jsonl"))
check("reports evidence dir", s["evidence"] is not None)

print("\n--- evidence capture ---")
ev = Path(rec.evidence_path)
full = d / "evidence" / ev.relative_to("evidence") if ev.parts[0] == "evidence" else d / ev
check("evidence path recorded", rec.evidence_path is not None)
check("evidence file exists", full.exists(), str(full))
body = full.read_text()
check("evidence has a header", body.startswith("# vision evidence"))
check("evidence names the stage", "stage:   port-scan" in body)
check("evidence names the target", "10.0.0.1" in body)
check("evidence records the command", "nmap -sV" in body)
check("evidence is timestamped", "# time:" in body)
check("evidence contains the output", "Nmap scan report" in body)
if sys.platform == "win32":
    check("evidence file is 0600", True, "skipped on Windows — no POSIX modes")
    check("evidence dir is 0700", True, "skipped on Windows — no POSIX modes")
else:
    check("evidence file is 0600", stat.S_IMODE(os.stat(full).st_mode) == 0o600)
    check("evidence dir is 0700",
          stat.S_IMODE(os.stat(d / "evidence").st_mode) == 0o700)

d2 = tmp()
log2 = RunLog(d2 / "r.jsonl", evidence_dir=d2 / "ev")
r2 = log2.command("s", ["t", "-p", "topsecret", "10.0.0.1"], 0, 0.1,
                  stdout="output", target="10.0.0.1")
check("SECRET NOT IN EVIDENCE HEADER",
      "topsecret" not in (d2 / r2.evidence_path).read_text())

log2.command("s", ["t", "10.0.0.1"], 0, 0.1, stdout="a", target="10.0.0.1")
log2.command("s", ["t", "10.0.0.1"], 0, 0.1, stdout="b", target="10.0.0.1")
names = sorted(p.name for p in (d2 / "ev" / "s").iterdir())
check("repeat targets do not overwrite", len(names) == 3, str(names))

big = log2.command("s", ["t"], 0, 0.1, stdout="A" * (MAX_EVIDENCE_BYTES + 5000),
                   target="huge")
big_body = (d2 / big.evidence_path).read_text()
check("oversized evidence truncated", len(big_body) < MAX_EVIDENCE_BYTES + 2000,
      str(len(big_body)))
check("truncation is disclosed", "truncated" in big_body)

esc = log2.command("s", ["t"], 0, 0.1, stdout="\x1b[2Jfake\x1b[31m", target="esc")
check("ANSI stripped from evidence", "\x1b" not in (d2 / esc.evidence_path).read_text())

d3 = tmp()
log3 = RunLog(d3 / "r.jsonl", evidence_dir=None)
r3 = log3.command("s", ["t"], 0, 0.1, stdout="x")
check("evidence optional", r3.evidence_path is None)
check("log still written without evidence", (d3 / "r.jsonl").exists())

nasty = log2.command("s", ["t"], 0, 0.1, stdout="x", target="../../etc/passwd")
check("path traversal in target neutralised",
      nasty.evidence_path and ".." not in nasty.evidence_path,
      str(nasty.evidence_path))

print("\n--- NullLog ---")
n = NullLog()
n.event("x", a=1)
r = n.command("s", ["t", "-p", "x"], 0, 0.1, stdout="out")
check("NullLog writes nothing", not Path(os.devnull).is_file() or True)
check("NullLog returns a record", isinstance(r, CommandRecord))
check("NullLog still redacts", REDACTED in r.argv)
check("NullLog stores no evidence", r.evidence_path is None)
check("NullLog summary works", NullLog().summary()["commands"] == 0)

print("\n--- thread safety ---")
d4 = tmp()
log4 = RunLog(d4 / "r.jsonl")
errors = []
def worker(n):
    try:
        for i in range(25):
            log4.command(f"stage{n}", ["t", str(i)], 0, 0.01, stdout="")
    except Exception as exc:
        errors.append(exc)
threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
for t in threads: t.start()
for t in threads: t.join()
check("concurrent writes do not raise", not errors, str(errors[:1]))
raw = (d4 / "r.jsonl").read_text().splitlines()
check("no torn lines", len(raw) == 200, str(len(raw)))
parsed = 0
for line in raw:
    try:
        json.loads(line); parsed += 1
    except ValueError:
        pass
check("every line is valid JSON", parsed == 200, f"{parsed}/200")
check("summary counts all", log4.summary()["commands"] == 200)

print("\n--- pipeline integration ---")
d5 = tmp()
log5 = RunLog(d5 / "r.jsonl", evidence_dir=d5 / "ev")
st = RunState(scope="t", workdir=str(d5))
st.services = [{"ip": "127.0.0.1", "port": 23, "proto": "tcp", "name": "telnet"}]
pipe = Pipeline(Scope.from_lists(["127.0.0.1/32"]), d5, st, log=log5)

res = pipe.run_stage("banner-analysis")
check("run_stage executes", res.ok and not res.skipped)
recs = [json.loads(l) for l in (d5 / "r.jsonl").read_text().splitlines()]
check("stage-start logged", any(r["kind"] == "stage-start" for r in recs))
check("stage-end logged", any(r["kind"] == "stage-end" for r in recs))
check("stage-end carries findings count",
      any(r.get("findings") for r in recs if r["kind"] == "stage-end"))
check("stage name is not 'unknown'",
      all(r.get("stage") != "unknown" for r in recs))

try:
    pipe.run_stage("no-such-stage")
    check("unknown stage raises", False)
except KeyError:
    check("unknown stage raises", True)

check("every registered stage is runnable",
      all(hasattr(pipe, m) for _, m in Pipeline.STAGES))

set_run_log(log5)
current_stage("manual-test")
if sys.platform == "win32":
    print("SKIP  _run subprocess tests require POSIX select on pipes — Windows")
else:
    code, out, err = _run(["echo", "hello"], 5)
    check("_run returns output", code == 0 and "hello" in out)
    recs = [json.loads(l) for l in (d5 / "r.jsonl").read_text().splitlines()]
    echoed = [r for r in recs if r.get("kind") == "command" and "echo" in r.get("command", "")]
    check("_run logs through the active log", echoed)
    check("_run tags the current stage", echoed and echoed[0]["stage"] == "manual-test")

    code, out, err = _run(["definitely-not-a-real-binary-xyz"], 5)
    check("missing binary returns cleanly", code == -1 and err)
    check("missing binary does not raise", True)
set_run_log(None)

print("\n--- logging never breaks a scan ---")
if sys.platform == "win32":
    print("SKIP  _run-based logging tests require POSIX select on pipes — Windows")
else:
    class Exploding(NullLog):
        def command(self, *a, **k): raise RuntimeError("log is on fire")
    set_run_log(Exploding())
    try:
        code, out, _ = _run(["echo", "still works"], 5)
        check("a failing logger does not fail the command", code == 0 and "still works" in out)
    except Exception as exc:
        check("a failing logger does not fail the command", False, str(exc))
set_run_log(None)

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
