"""Manual playbook and scan narration tests.

Two things must hold. Vision must never run a playbook command itself — these
are suggestions printed as text, several of them intrusive. And every stage the
pipeline can run must have a plain-language description, or the narration
silently degrades back to bare stage names.
"""
import inspect, re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.analysis import playbook as pb
from vision.core.pipeline import Pipeline
from vision.core import ui

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

S = lambda **kw: {"ip": "10.0.0.5", "proto": "tcp", **kw}

print("--- every stage is narrated ---")
missing = [n for n, _ in Pipeline.STAGES if not pb.describe(n)]
check("every registered stage has a description", not missing, str(missing))
check("descriptions are substantive",
      all(len(pb.describe(n)) > 30 for n, _ in Pipeline.STAGES))
check("descriptions explain, not just name",
      all(pb.describe(n).lower() != n.replace("-", " ")
          for n, _ in Pipeline.STAGES))
check("unknown stage returns empty, not a crash", pb.describe("nope") == "")

print("\n--- service matching keys on identity, then port ---")
check("redis by name on any port",
      pb.for_service(S(port=54321, name="redis")))
check("redis by port when unidentified", pb.for_service(S(port=6379)))
check("nmap naming something else wins",
      not any("redis-cli" in st.command
              for st in pb.for_service(S(port=6379, name="http", product="nginx"))))
check("http on 8080 matched", pb.for_service(S(port=8080, name="http")))
check("smb matched by microsoft-ds", pb.for_service(S(port=445, name="microsoft-ds")))
check("unknown service yields nothing", pb.for_service(S(port=9999)) == [])
check("empty dict is safe", pb.for_service({}) == [])

print("\n--- finding-level follow-up ---")
check("SMB signing gets a relay step",
      any("ntlmrelayx" in st.command
          for st in pb.for_finding({"title": "SMB signing not required"})))
check("exposed .env gets a retrieval step",
      any("curl" in st.command
          for st in pb.for_finding({"title": "Environment file exposed"})))
check("MS17-010 gets an independent verification step",
      any("smb-vuln-ms17-010" in st.command
          for st in pb.for_finding({"title": "MS17-010 SMB RCE"})))
check("unrelated finding yields nothing",
      pb.for_finding({"title": "Something benign"}) == [])
check("missing title is safe", pb.for_finding({}) == [])

print("\n--- placeholders resolve ---")
steps = pb.for_service(S(port=6379, name="redis"))
rendered = pb.render(steps, "10.0.0.5", 6379, "10.0.0.0/24")
check("ip substituted", all("10.0.0.5" in c or "{" not in c for _s, c in rendered))
check("port substituted", any("6379" in c for _s, c in rendered))
check("no unfilled placeholders left",
      not any(re.search(r"\{(ip|port|scope)\}", c) for _s, c in rendered))
blank = pb.render(steps, "", None, "")
check("missing values degrade to readable tokens",
      all("TARGET" in c or "PORT" in c or "{" not in c for _s, c in blank))
check("scope placeholder fills",
      all("{scope}" not in c for _s, c in
          pb.render(pb.for_finding({"title": "SMB signing"}), "10.0.0.5", 445,
                    "10.0.0.0/24")))

print("\n--- every step is well formed ---")
all_steps = [st for _n, _p, steps in pb.SERVICE_PLAYBOOK for st in steps]
all_steps += [st for _p, steps in pb.FINDING_PLAYBOOK for st in steps]
check(f"{len(all_steps)} steps defined", len(all_steps) >= 30)
check("every step has a label", all(len(st.label) > 4 for st in all_steps))
check("every step has a command", all(len(st.command) > 5 for st in all_steps))
check("every step explains why", all(len(st.why) > 25 for st in all_steps))
check("intrusive flag is boolean",
      all(isinstance(st.intrusive, bool) for st in all_steps))
check("some steps are marked intrusive",
      sum(1 for st in all_steps if st.intrusive) >= 4)

print("\n--- destructive commands are commented out, not ready to paste ---")
# A suggestion that lands in the shell buffer ready to run is not a suggestion.
for st in all_steps:
    if any(w in st.command.lower() for w in ("hydra ", "medusa ", "ncrack ")):
        if not st.command.strip().startswith("#"):
            check(f"credential attack is commented: {st.label}", False, st.command[:40])
check("all credential-attack suggestions are commented out", True)

print("\n--- Vision never executes a playbook command ---")
# These are text. The moment anything here reaches subprocess, an operator's
# 'show me what to run' turns into 'run it'.
src = inspect.getsource(pb)
for danger in ("subprocess", "os.system", "popen", "eval(", "exec("):
    check(f"playbook module contains no {danger}", danger not in src.lower())
from vision.core import console
csrc = inspect.getsource(console)
run_calls = re.findall(r"_playbook\.\w+", csrc)
check("console only reads from the playbook",
      all(c.split(".")[1] in ("describe", "for_service", "for_finding",
                              "for_situation", "situations", "render")
          for c in run_calls), str(set(run_calls)))

print("\n--- progress rendering ---")
line = ui.progress_line(7, 20, 96)
check("shows a percentage", "35%" in line)
check("shows stage counts", "7/20" in line)
check("shows elapsed", "1m 36s" in line)
check("projects remaining", "left" in line)
check("no estimate at the start", "left" not in ui.progress_line(0, 20, 1))
check("no estimate when complete", "left" not in ui.progress_line(20, 20, 100))
check("zero total is safe", ui.progress_line(0, 0, 0) == "")
check("duration formats hours", "1h" in ui._dur(3700))
check("duration formats minutes", "2m" in ui._dur(125))
check("duration formats seconds", ui._dur(45) == "45s")
check("negative duration is safe", ui._dur(-5) == "0s")

print("\n--- command rendering ---")
cl = ui.command_line(["nmap", "-sV", "10.0.0.5"])
check("renders the command", "nmap -sV 10.0.0.5" in cl)
check("quotes args with spaces", "'a b'" in ui.command_line(["t", "a b"]))
check("long commands truncate",
      len(ui.command_line(["x"] * 400, width_limit=60)) < 200)
check("empty argv is safe", isinstance(ui.command_line([]), str))

print("\n--- the command hook cannot break a scan ---")
import vision.core.pipeline as plmod
import sys as _sys
if _sys.platform == "win32":
    print("SKIP  _run-based hook tests require POSIX select on pipes — Windows")
else:
    plmod.set_command_hook(lambda a, rc, d: (_ for _ in ()).throw(RuntimeError("boom")))
    try:
        code, out, _e = plmod._run(["echo", "still works"], 5)
        check("a failing display hook does not fail the command",
              code == 0 and "still works" in out)
    except Exception as exc:
        check("a failing display hook does not fail the command", False, str(exc))
    plmod.set_command_hook(None)

    seen = []
    plmod.set_command_hook(lambda a, rc, d: seen.append((a[0], rc)))
    plmod._run(["echo", "hi"], 5)
    plmod.set_command_hook(None)
    check("hook receives argv and returncode", seen == [("echo", 0)], str(seen))
    check("hook detaches cleanly", (plmod._run(["echo", "x"], 5), len(seen))[1] == 1)

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
