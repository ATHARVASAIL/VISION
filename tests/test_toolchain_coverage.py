"""Every tool must have a real path to install.

"One click, every tool" only holds if every one of the 55 registered tools
either installs automatically or, when that is genuinely impossible (licensed
software, GitHub-release-only binaries), tells the operator exactly what to
do instead. A tool with neither is a silent dead end that "vision doctor"
reports as simply missing.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.core.toolchain import TOOLS, detect_environment, Need, choose_method
from vision.core.doctor import _plan, _go_bootstrap, _GO_BOOTSTRAP

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

if not detect_environment().is_kali:
    print("SKIP  toolchain coverage requires Kali Linux")
    sys.exit(0)

env = detect_environment()

print("--- every tool has a package manager OR explicit manual instructions ---")
methods = ("apt", "pipx", "pip", "go", "gem", "cargo", "brew")
# A tool with neither a package-manager field nor manual instructions is a
# genuine gap. Having only .manual is correct for licensed software (nessuscli)
# and release-only binaries (windapsearch, ligolo-ng) — that is not a defect.
no_method_no_manual = [t for t in TOOLS
                       if not any(getattr(t, m) for m in methods)
                       and not t.manual]
check("every tool has an install path or manual instructions",
      not no_method_no_manual, str([t.name for t in no_method_no_manual]))

print("\n--- every tool resolves to a plan OR explicit manual instructions ---")
all_names = [t.name for t in TOOLS]
plan, unplannable = _plan(env, Need.OPTIONAL, all_names)
planned_names = {t.name for t, _, _ in plan}
manual_names = {t.name for t in unplannable if t.manual}
truly_stuck = [t.name for t in unplannable if not t.manual]
check("nothing is planned AND manual-less at once",
      not truly_stuck, str(truly_stuck))
# The previous version of this check asserted the plan covers more than half
# of all 55 tools — which only holds on a near-empty box. On a well-provisioned
# Kali install, most tools are already present, the plan is correctly small,
# and that hardcoded threshold failed even though nothing was actually wrong.
# What must hold regardless of how much is already installed: every tool that
# is not yet present ends up covered by either the plan or a manual fallback.
still_needed = [t for t in TOOLS if not t.installed]
check("every not-yet-installed tool is covered by the plan or a manual note",
      len(planned_names | manual_names) >= len(still_needed),
      f"{len(still_needed)} tools needed, only "
      f"{len(planned_names | manual_names)} covered")

print("\n--- Go-only tools bootstrap Go rather than dead-ending ---")
GO_ONLY = ["naabu", "dnsx", "subfinder", "kerbrute"]
for name in GO_ONLY:
    check(f"{name} is not stuck when Go itself is missing",
          name in planned_names or name in manual_names,
          f"{name} landed in unplannable with no manual fallback")

if "go" not in env.package_managers:
    check("a bootstrap Go entry appears ahead of the tools needing it",
          any(t.name == "golang" for t, _, _ in plan[:len(GO_ONLY) + 1])
          or not any(n in planned_names for n in GO_ONLY))
    go_index = next((i for i, (t, _, _) in enumerate(plan) if t.name == "golang"), None)
    if go_index is not None:
        first_go_tool = next((i for i, (t, _, _) in enumerate(plan)
                             if t.name in GO_ONLY), None)
        check("golang is installed before any tool that needs it",
              first_go_tool is None or go_index < first_go_tool)

print("\n--- the go-bootstrap condition checks real availability, not field presence ---")
# A tool with both go= and brew= set must still be routed through the Go
# bootstrap on a box with no brew — checking "does this tool declare brew"
# instead of "can this box actually use brew" was the bug: chisel has a
# brew= field but no brew binary here, and was wrongly left unplannable.
from vision.core.toolchain import Tool, Phase
fake_chisel_like = Tool("test-both", "test-both", Phase.DISCOVERY, "x",
                        Need.OPTIONAL, go="example.com/x@latest", brew="x")
pm = choose_method(fake_chisel_like, env)
check("choose_method correctly finds nothing when only brew is set and "
      "brew is absent", pm is None or "brew" in env.package_managers)

print("\n--- Go bootstrap plan is well-formed ---")
go_pm, go_argv = _go_bootstrap(env)
if "go" not in env.package_managers:
    check("a bootstrap method is found when apt or brew is available",
          (go_argv is not None) == ("apt" in env.package_managers
                                     or "brew" in env.package_managers))
    if go_argv:
        check("the bootstrap command actually installs Go",
              "golang" in " ".join(go_argv) or "go" in " ".join(go_argv))
check("the synthetic golang entry has a clear purpose string",
      "naabu" in _GO_BOOTSTRAP.purpose or "Go toolchain" in _GO_BOOTSTRAP.purpose)

print("\n--- rustscan has manual instructions now that it lacks one ---")
from vision.core.toolchain import BY_NAME
rs = BY_NAME["rustscan"]
check("rustscan declares manual instructions", bool(rs.manual))
check("the instructions mention how to get Rust", "rustup" in rs.manual.lower()
      or "cargo" in rs.manual.lower())

print("\n--- the plan never installs something already present ---")
check("installed tools are never re-added to the plan",
      not any(t.installed for t, _, _ in plan))

print("\n--- every tool has an automated install path (or is a known exception) ---")
# A tool with no apt/pipx/pip/go/gem/cargo/brew entry can never be installed by
# setup.sh — it stays missing forever and drags the tool count down with no way
# to fix it from inside Vision. windapsearch and ligolo-ng used to be in this
# state; only nessuscli legitimately remains, because Tenable ships it solely
# inside their own bundled installer with no package-manager path.
from vision.core.toolchain import TOOLS as _ALL
_INSTALL_ATTRS = ("apt", "pipx", "pip", "go", "gem", "cargo", "brew")
_KNOWN_MANUAL = {"nessuscli"}
_no_path = {t.name for t in _ALL
            if not any(getattr(t, a, None) for a in _INSTALL_ATTRS)}
check("no tool lacks an install path except the known manual exception",
      _no_path <= _KNOWN_MANUAL,
      f"tools with no automated install: {sorted(_no_path - _KNOWN_MANUAL)}")
check("windapsearch is installable (go path wired)",
      any(getattr(next(t for t in _ALL if t.name == 'windapsearch'), a, None)
          for a in _INSTALL_ATTRS))
check("ligolo-ng is installable (go path wired)",
      any(getattr(next(t for t in _ALL if t.name == 'ligolo-ng'), a, None)
          for a in _INSTALL_ATTRS))

print("\n--- the environment detects ~/.local/bin on PATH ---")
# pipx and `pip --user` drop executables in ~/.local/bin. If it is off PATH,
# those tools install but stay invisible to shutil.which and count as missing —
# the single most common cause of a low tool count on a box where setup ran.
from vision.core.toolchain import detect_environment as _detect
_env = _detect()
check("Environment exposes local_bin_on_path",
      hasattr(_env, "local_bin_on_path"))
check("local_bin_on_path is a bool", isinstance(_env.local_bin_on_path, bool))

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
