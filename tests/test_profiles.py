"""Scan profile tests.

The load-bearing assertions here are the ones that stop intensity from becoming
a back door: turning coverage up must never turn a safety gate off, and the
profile that can take a device offline must be impossible to select by reflex.
"""
import sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.core.profiles import (
    PROFILES, DEFAULT, STEALTH, NORMAL, AGGRESSIVE, get,
    snmp_communities, SNMP_COMMON, SNMP_EXTENDED, PATHS_EXTENDED,
)
from vision.core.pipeline import Pipeline, RunState
from vision.core.scope import Scope

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

print("--- lookup ---")
check("three profiles", set(PROFILES) == {"stealth", "normal", "aggressive"})
check("normal is the default", DEFAULT is NORMAL)
check("get by name", get("aggressive") is AGGRESSIVE)
check("get is case-insensitive", get("AGGRESSIVE") is AGGRESSIVE)
check("get(None) is the default", get(None) is NORMAL)
try:
    get("ludicrous")
    check("unknown name rejected", False)
except ValueError as e:
    check("unknown name rejected", "unknown intensity" in str(e))
    check("error names the valid options", "aggressive" in str(e))

print("\n--- intensity actually escalates ---")
check("port coverage widens",
      STEALTH.tcp_ports == "--top-ports=200"
      and NORMAL.tcp_ports == "--top-ports=1000"
      and AGGRESSIVE.tcp_ports == "-p-")
check("rate escalates",
      STEALTH.min_rate < NORMAL.min_rate < AGGRESSIVE.min_rate)
check("version probing escalates",
      STEALTH.version_intensity < NORMAL.version_intensity < AGGRESSIVE.version_intensity)
check("concurrency escalates",
      STEALTH.workers < NORMAL.workers < AGGRESSIVE.workers)
check("host caps escalate",
      STEALTH.max_hosts_per_stage < NORMAL.max_hosts_per_stage
      < AGGRESSIVE.max_hosts_per_stage)
check("UDP coverage widens",
      len(STEALTH.udp_ports.split(",")) < len(AGGRESSIVE.udp_ports.split(",")))
check("nuclei severity widens",
      len(STEALTH.nuclei_severity.split(",")) < len(AGGRESSIVE.nuclei_severity.split(",")))
check("aggressive includes informational templates",
      "info" in AGGRESSIVE.nuclei_severity)
check("stealth excludes low-value templates",
      "info" not in STEALTH.nuclei_severity)

print("\n--- timing stays inside what is trustworthy ---")
# -T5 shortens timeouts enough that a loaded host reports open ports as closed.
# A faster scan that misses a service is not a better scan.
check("no profile uses -T5", all(p.timing != "-T5" for p in PROFILES.values()))
check("stealth is genuinely slow", STEALTH.timing == "-T2")
check("aggressive stops at -T4", AGGRESSIVE.timing == "-T4")

print("\n--- impacts are disclosed, not summarised ---")
for name, p in PROFILES.items():
    check(f"{name} itemises impacts", len(p.impacts) >= 3, str(len(p.impacts)))
    check(f"{name} impacts are substantive",
          all(len(i.text) > 40 for i in p.impacts))
    check(f"{name} impact levels are valid",
          all(i.level in ("info", "caution", "serious") for i in p.impacts))

check("aggressive declares serious impacts", len(AGGRESSIVE.serious_impacts) >= 3)
check("normal declares none", not NORMAL.serious_impacts)
check("stealth declares none", not STEALTH.serious_impacts)
text = " ".join(i.text.lower() for i in AGGRESSIVE.impacts)
for topic, needle in [("device crashes", "crash"), ("IDS alerting", "ids"),
                      ("authorisation", "authorisation"),
                      ("named equipment at risk", "printer"),
                      ("link saturation", "packets/second")]:
    check(f"aggressive warns about {topic}", needle in text)
check("stealth discloses its coverage gap",
      "not evidence of a clean network" in
      " ".join(i.text for i in STEALTH.impacts))
check("normal states no lockout risk",
      "lock" in " ".join(i.text.lower() for i in NORMAL.impacts))

print("\n--- confirmation strength matches consequence ---")
check("aggressive needs a typed confirmation", AGGRESSIVE.needs_typed_confirmation)
check("normal does not", not NORMAL.needs_typed_confirmation)
check("stealth does not", not STEALTH.needs_typed_confirmation)
check("aggressive is flagged loud", AGGRESSIVE.is_loud)
check("normal is not loud", not NORMAL.is_loud)
check("stealth is not loud", not STEALTH.is_loud)

print("\n--- intensity never relaxes a safety gate ---")
# Coverage and authorisation are different decisions. Turning one up must never
# turn the other down.
import inspect
from vision.analysis import exploit_advisor as adv_mod
adv_src = inspect.getsource(adv_mod)
check("the launcher knows nothing about profiles",
      "profile" not in adv_src.lower(),
      "exploit gating must not vary with scan intensity")
check("no profile carries an exploit setting",
      not any(hasattr(p, a) for p in PROFILES.values()
              for a in ("allow_destructive", "auto_exploit", "exploit")))
check("no profile disables confirmation",
      not any("confirm" in f.lower() and "skip" in f.lower()
              for p in PROFILES.values() for f in vars(p)))

print("\n--- credential handling is not a slider ---")
check("extended SNMP list is still fixed defaults",
      len(SNMP_EXTENDED) < 40, f"{len(SNMP_EXTENDED)} entries")
check("extended builds on the common list",
      set(SNMP_COMMON) <= set(SNMP_EXTENDED))
check("stealth and normal use the common list",
      snmp_communities(STEALTH) == SNMP_COMMON
      and snmp_communities(NORMAL) == SNMP_COMMON)
check("aggressive uses the extended list",
      snmp_communities(AGGRESSIVE) == SNMP_EXTENDED)
check("extended path list stays short — exposure checking, not brute force",
      len(PATHS_EXTENDED) < 20, f"{len(PATHS_EXTENDED)} paths")
check("every extended path has a content signature",
      all(callable(p[3]) for p in PATHS_EXTENDED))
check("every extended path has a severity",
      all(p[1] in ("info", "low", "medium", "high", "critical")
          for p in PATHS_EXTENDED))

print("\n--- nmap flags are well formed ---")
for name, p in PROFILES.items():
    flags = p.nmap_flags()
    check(f"{name} emits timing", p.timing in flags)
    check(f"{name} emits a rate", "--min-rate" in flags)
    check(f"{name} emits version intensity", "--version-intensity" in flags)
    check(f"{name} flags are all strings", all(isinstance(f, str) for f in flags))
check("stealth bounds host time", "--host-timeout" in STEALTH.nmap_flags())
check("describe() is human readable",
      all(len(l) > 10 for p in PROFILES.values() for l in p.describe()))

print("\n--- the pipeline honours the profile ---")
def _pipe(profile):
    wd = Path(tempfile.mkdtemp())
    st = RunState(scope="t", workdir=str(wd))
    st.live_hosts = ["10.10.0.5"]
    return Pipeline(Scope.from_lists(["10.10.0.0/24"]), wd, st, profile=profile)

check("default profile applied", _pipe(None).profile is NORMAL)
check("aggressive sets the all-ports flag", _pipe(AGGRESSIVE).aggressive)
check("normal does not", not _pipe(NORMAL).aggressive)
check("stealth does not", not _pipe(STEALTH).aggressive)
check("worker count comes from the profile",
      _pipe(AGGRESSIVE).profile.workers == AGGRESSIVE.workers)

import vision.core.pipeline as plmod
captured = []
orig = plmod._run
orig_have = plmod._have
# This block tests the ARGUMENTS the profile builds, not whether nmap is
# actually present on the machine running the suite. Gating on the real
# `_have("nmap")` meant the whole block silently skipped to zero captured
# calls, and every downstream check failed with an empty-string false
# negative, on any box without nmap on PATH -- indistinguishable from an
# actual argument-construction bug without reading the stage's early-exit
# reason by hand.
plmod._run = lambda argv, timeout: (captured.append(list(argv)), (1, "", "x"))[1]
plmod._have = lambda tool: True
try:
    _pipe(AGGRESSIVE).port_scan()
    agg_argv = " ".join(captured[-1]) if captured else ""
    captured.clear()
    _pipe(STEALTH).port_scan()
    ste_argv = " ".join(captured[-1]) if captured else ""
finally:
    plmod._run = orig
    plmod._have = orig_have
check("the port-scan stage actually ran (nmap availability did not silently "
      "skip it)", bool(agg_argv) and bool(ste_argv))
check("aggressive scans every port", "-p-" in agg_argv, agg_argv[:80])
check("aggressive uses max version intensity", "--version-intensity 9" in agg_argv)
check("stealth limits the port range", "--top-ports=200" in ste_argv, ste_argv[:80])
check("stealth uses -T2", "-T2" in ste_argv)
check("stealth skips the default script set", "-sC" not in ste_argv)
check("aggressive runs the default script set", "-sC" in agg_argv)

print("\n--- cmd_run resolves the profile before printing it ---")
# `profile` was referenced in the engagement summary twenty lines above its
# assignment, so `vision run` raised NameError before scanning anything.
import ast as _ast
_tree = _ast.parse(Path("vision/cli.py").read_text())
_fn = next(n for n in _ast.walk(_tree)
           if isinstance(n, _ast.FunctionDef) and n.name == "cmd_run")
_assigned = min((n.lineno for n in _ast.walk(_fn)
                 if isinstance(n, _ast.Assign)
                 and any(isinstance(t, _ast.Name) and t.id == "profile"
                         for t in n.targets)), default=10**6)
_used = min((n.lineno for n in _ast.walk(_fn)
             if isinstance(n, _ast.Name) and n.id == "profile"
             and isinstance(n.ctx, _ast.Load)), default=10**6)
check("profile is assigned before it is used", _assigned < _used,
      f"assigned line {_assigned}, first used line {_used}")

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
