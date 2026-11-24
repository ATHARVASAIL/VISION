"""Regression tests for crashes reported from live engagements.

Each test here maps to a specific traceback a user hit in the field:

  1. Loading targets from a FILE in the interactive console left the run-state
     unset, so the pipeline crashed with
     'NoneType' object has no attribute 'live_hosts' the moment
     host-discovery found a host.
  2. The analysis subcommands (paths / frameworks / diff / advise) read a
     findings file with no guards, so a truncated, hand-edited or
     wrong-shaped file produced a raw JSONDecodeError / AttributeError /
     TypeError traceback instead of a one-line error.
  3. A missing or malformed targets file crashed set_target instead of
     returning the operator to the menu.

They are deliberately I/O-light and tool-free so they run everywhere.
"""
import builtins
import io
import contextlib
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.cli import build_parser, load_findings
from vision.core import console as C
from vision.core.console import Console
from vision.core.pipeline import Pipeline, RunState
from vision.core.scope import Scope

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        fails.append(label)


def _drive(console, text, inline=True):
    """Call set_target feeding `text`, then 'n' for any auth prompt."""
    it = iter([text, "n", "n", "0"])
    orig_in, orig_pause = builtins.input, C._pause
    builtins.input = lambda *a, **k: next(it)
    C._pause = lambda *a, **k: None
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            return console.set_target(inline=inline)
    finally:
        builtins.input, C._pause = orig_in, orig_pause


def _console(tmp):
    args = build_parser().parse_args(
        ["menu", "-o", os.path.join(tmp, "run"), "--no-banner"])
    return Console(args)


# ---------------------------------------------------------------------------
# 1. File target must build a usable run-state (the live_hosts crash)
# ---------------------------------------------------------------------------
tmp = tempfile.mkdtemp()
tf = os.path.join(tmp, "targets.txt")
Path(tf).write_text("192.168.56.0/30\n")

c = _console(tmp)
ok = _drive(c, "file " + tf)
check("file target returns True", ok is True)
check("file target sets a scope", c.scope is not None)
check("file target builds a run-state (not None)", c.state is not None)
check("run-state exposes live_hosts", hasattr(c.state, "live_hosts"))

# the exact line that crashed in the field: merging discovered hosts
try:
    c.state.live_hosts = sorted(set(c.state.live_hosts) | {"192.168.56.1"})
    merge_ok = c.state.live_hosts == ["192.168.56.1"]
except Exception as e:  # pragma: no cover
    merge_ok = False
    check("discover_hosts merge detail", False, str(e))
check("host-discovery merge into file-target state works", merge_ok)

# a typed target must still work identically
c2 = _console(tmp)
ok2 = _drive(c2, "192.168.56.101")
check("typed target also builds a run-state", ok2 is True and c2.state is not None)


# ---------------------------------------------------------------------------
# 2. discover_hosts with a real (mocked) host, file-target state — end to end
# ---------------------------------------------------------------------------
import vision.core.pipeline as P

c3 = _console(tmp)
_drive(c3, "file " + tf)
c3.workdir.mkdir(parents=True, exist_ok=True)
pipe = Pipeline(c3.scope, c3.workdir, c3.state, timeout=5)

orig_have = P._have
orig_run = P._run
P._have = lambda name: True                      # pretend nmap exists
P._run = lambda *a, **k: (0, "", "")             # pretend it ran fine
Pipeline._parse_hosts = staticmethod(lambda xml: ["192.168.56.1"])
try:
    (c3.workdir / "discovery.xml").write_text("<nmaprun/>")
    res = pipe.discover_hosts()
    disc_ok = (res.ok and "192.168.56.1" in c3.state.live_hosts)
except Exception as e:
    disc_ok = False
    check("discover_hosts end-to-end detail", False, str(e))
finally:
    P._have, P._run = orig_have, orig_run
check("discover_hosts completes against file-target state", disc_ok)


# ---------------------------------------------------------------------------
# 3. set_target survives missing / empty / all-bad / no-path files
# ---------------------------------------------------------------------------
missing = os.path.join(tmp, "nope_zzz.txt")
empty = os.path.join(tmp, "empty.txt"); Path(empty).write_text("")
allbad = os.path.join(tmp, "bad.txt"); Path(allbad).write_text("foo\nbar\n")

for label, text in [
    ("missing file", "file " + missing),
    ("empty file", "file " + empty),
    ("all-invalid file", "file " + allbad),
    ("'file' with no path", "file"),
    ("bare '@'", "@"),
    ("malformed typed target", "notanip"),
]:
    cc = _console(tmp)
    try:
        r = _drive(cc, text)
        check(f"set_target handles {label} without crashing", r is False)
    except Exception as e:
        check(f"set_target handles {label} without crashing", False, str(e))

# a file mixing valid and invalid lines keeps the valid ones
mixed = os.path.join(tmp, "mixed.txt")
Path(mixed).write_text("192.168.56.1\nNOTANIP\n10.0.0.0/30\n# comment\n\n")
cm = _console(tmp)
rm = _drive(cm, "file " + mixed)
check("mixed valid/invalid file loads the valid lines",
      rm is True and cm.scope is not None)


# ---------------------------------------------------------------------------
# 4. load_findings tolerates malformed input instead of crashing
# ---------------------------------------------------------------------------
def write(name, content):
    p = os.path.join(tmp, name)
    Path(p).write_text(content)
    return p

good = write("good.json", json.dumps({"findings": [
    {"ip": "10.0.0.5", "port": 445, "title": "SMB", "severity": "high"}]}))
missing_ip = write("noip.json", json.dumps({"findings": [{"title": "bare"}]}))
broken = write("broken.json", "not json {")
wrongshape = write("wrong.json", "[1, 2, 3]")
notlist = write("notlist.json", json.dumps({"findings": {"a": 1}}))
nondict = write("nondict.json", json.dumps({"findings": [1, 2, 3]}))

# valid file loads
f, _ = load_findings(good)
check("load_findings reads a valid file", len(f) == 1 and f[0].ip == "10.0.0.5")

# a finding missing a required field is skipped, not fatal
f, _ = load_findings(missing_ip)
check("load_findings skips a finding missing 'ip'", f == [])

# non-dict entries in the list are skipped
f, _ = load_findings(nondict)
check("load_findings skips non-dict finding entries", f == [])

# findings not being a list is tolerated
f, _ = load_findings(notlist)
check("load_findings tolerates non-list 'findings'", f == [])

# unreadable / wrong-shape files raise a CLEAN ValueError (no raw traceback)
for label, path in [("broken JSON", broken), ("wrong top-level shape", wrongshape)]:
    try:
        load_findings(path)
        check(f"load_findings rejects {label} with ValueError", False, "no error raised")
    except ValueError:
        check(f"load_findings rejects {label} with ValueError", True)
    except Exception as e:
        check(f"load_findings rejects {label} with ValueError", False,
              f"{type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# 5. scan_config (profile / evasion / external) round-trips through state
#    save/load, so the report can state the methodology after a resume.
# ---------------------------------------------------------------------------
sd = Path(tempfile.mkdtemp())
st = RunState(scope="203.0.113.0/24",
              scan_config={"profile": "normal", "evade": True, "external": True})
st.save(sd / "state.json")
st_back = RunState.load(sd / "state.json")
check("scan_config survives save/load",
      st_back.scan_config == {"profile": "normal", "evade": True, "external": True})
# an older state file without scan_config loads with an empty dict, not a crash
(sd / "old.json").write_text(json.dumps({"scope": "x", "findings": []}))
check("state file without scan_config loads cleanly",
      RunState.load(sd / "old.json").scan_config == {})

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
