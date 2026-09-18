"""Batched verification and newly wired tool coverage.

The load-bearing assertion: batching applies to `check` and to nothing else.
Verification asks a service whether it is vulnerable and delivers no payload —
that is precisely why it can be batched, and precisely why exploitation cannot.
"""
import json, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.core.scope import Scope
from vision.core.schema import Finding, Proto, Confidence
from vision.analysis.msf_index import MsfModule
from vision.analysis.exploit_advisor import (
    ExploitLauncher, ExploitCandidate, ExploitBlocked,
)
from vision.core.pipeline import Pipeline, RunState
from vision.core.toolchain import TOOLS
from vision.analysis import playbook

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

SCOPE = Scope.from_lists(["10.10.0.0/24"])

def mod(i, has_check=True, destructive=False):
    return MsfModule(fullname=f"exploit/x/m{i}", path="/x", name=f"M{i}",
                     rank="Excellent", cves=[f"CVE-2020-{1000+i}"],
                     has_check=has_check, destructive=destructive)

def cand(i, ip=None, **kw):
    return ExploitCandidate(
        module=mod(i, **kw),
        finding=Finding(ip=ip or f"10.10.0.{5+i}", port=445, proto=Proto.TCP,
                        title="t", cves=[f"CVE-2020-{1000+i}"]))

def launcher(audit=None):
    return ExploitLauncher(SCOPE, audit_log=audit or tempfile.mktemp(),
                           msfconsole="/bin/echo")

print("--- one session instead of one per candidate ---")
L = launcher()
cands = [cand(i) for i in range(8)]
script = L._batch_script(cands)
check("all modules in one script", script.count("use exploit") == 8)
check("all checks in one script", script.count("\ncheck") == 8)
check("one exit", script.count("\nexit") == 1)
check("each candidate gets a marker",
      all(f"{L.BATCH_MARK}{i}" in script for i in range(8)))
check("terminator present", f"{L.BATCH_MARK}END" in script)
check("options set per module", script.count("set RHOSTS") == 8)
check("distinct targets preserved",
      all(f"set RHOSTS 10.10.0.{5+i}" in script for i in range(8)))

print("\n--- output is split back per candidate ---")
fake = "".join(f"{L.BATCH_MARK}{i}\nThe target is vulnerable.\n" if i % 2 == 0
               else f"{L.BATCH_MARK}{i}\nThe target is not exploitable.\n"
               for i in range(8)) + f"{L.BATCH_MARK}END\n"
parts = L._split_batch_output(fake, cands)
check("one section per candidate", len(parts) == 8)
check("verdicts parse per section",
      [L._parse_verdict(p) for p in parts[:4]]
      == ["vulnerable", "not-vulnerable", "vulnerable", "not-vulnerable"])
check("a section holds only its own output", "vulnerable" in parts[0]
      and parts[0].count(L.BATCH_MARK) == 1)

print("\n--- missing markers degrade to inconclusive, never to a wrong verdict ---")
# An msfconsole build that swallows `echo`, or a crash partway, must not
# produce a confident slice belonging to another candidate.
blind = L._split_batch_output("no markers at all, just noise", cands)
check("every candidate still gets a section", len(blind) == 8)
check("no verdict invented", all(L._parse_verdict(p) is None for p in blind))
partial = f"{L.BATCH_MARK}0\nThe target is vulnerable.\n"
p2 = L._split_batch_output(partial, cands)
check("truncated output does not crash", len(p2) == 8)

print("\n--- the gates are unchanged by batching ---")
audit = tempfile.mktemp()
L2 = launcher(audit)
mixed = [cand(0), cand(1, ip="8.8.8.8"), cand(2),
         cand(3, has_check=False), cand(4, destructive=True)]
res = L2.verify_many(mixed, require_confirm=False)
ips = {r.candidate.rhost for r in res}
check("out-of-scope candidate excluded", "8.8.8.8" not in ips)
check("candidate without check() excluded", len(res) == 3, str(len(res)))
check("destructive module may still be CHECKED",
      any(r.candidate.module.destructive for r in res),
      "check delivers no payload, so it is not the destructive gate's concern")

recs = [json.loads(l) for l in open(audit)]
check("refusal audited", any(r["event"].startswith("blocked") for r in recs))
check("every run audited separately",
      sum(1 for r in recs if r["event"] == "finished") == 3)
check("audit names each module",
      len({r["module"] for r in recs if r["event"] == "finished"}) == 3)

print("\n--- exploitation is NOT batched ---")
import inspect
src = inspect.getsource(ExploitLauncher.verify_many)
check("verify_many only ever runs check", '"check"' in src and "exploit -z" not in src)
check("batch script never contains exploit",
      "exploit" not in L._batch_script(cands).replace("use exploit", ""))
check("there is no exploit_many",
      not hasattr(ExploitLauncher, "exploit_many"))
check("single-run path still requires a typed IP",
      "cand.rhost" in inspect.getsource(ExploitLauncher.confirm))

print("\n--- confirmation must be callable BEFORE any spinner starts ---")
# A real run hung for 17+ minutes with the spinner showing "msf exploit ->
# 192.168.88.128 1056s" and no visible prompt. Root cause: the console called
# launcher.run() -- which blocks on input() inside confirm() -- from INSIDE a
# `with ui.Spinner(...)` block. The spinner's background thread rewrites the
# same terminal line every 80ms, so the typed-IP prompt was printed but
# instantly overwritten. The operator was not looking at a slow exploit; they
# were looking at a confirmation prompt that had already been erased.
#
# The fix splits confirmation out so the console calls it BEFORE opening a
# spinner. These checks prove that split exists and actually works standalone
# -- not just that confirmation happens somewhere inside a monolithic call.
check("filter_runnable exists as a standalone, spinner-free step",
      hasattr(ExploitLauncher, "filter_runnable"))
check("confirm_many exists as a standalone, spinner-free step",
      hasattr(ExploitLauncher, "confirm_many"))
check("the old internal name still resolves, for any external caller",
      ExploitLauncher._confirm_batch is ExploitLauncher.confirm_many)

import builtins as _builtins
L4 = launcher()
runnable = L4.filter_runnable([cand(0), cand(1, ip="8.8.8.8")])
check("filter_runnable drops out-of-scope candidates without any prompt",
      len(runnable) == 1 and runnable[0].rhost != "8.8.8.8")
check("filter_runnable never calls input() -- it must be safe to run before "
      "any confirmation exists yet",
      "input(" not in inspect.getsource(ExploitLauncher.filter_runnable))

_real_input = _builtins.input
_builtins.input = lambda p="": "y"
try:
    ok = L4.confirm_many(runnable)
    check("confirm_many can be awaited on its own, with nothing else writing "
          "to the terminal at the same time", ok is True)
finally:
    _builtins.input = _real_input

# The single-exploit path has the same shape: confirm() must not be buried
# inside run() when run() is itself wrapped in a spinner by the caller.
check("run() accepts require_confirm=False so a caller can confirm first",
      "require_confirm" in inspect.signature(ExploitLauncher.run).parameters)
sig = inspect.signature(ExploitLauncher.run)
check("require_confirm defaults to True for any direct caller "
      "(the console opts out explicitly, nothing is silently less safe)",
      sig.parameters["require_confirm"].default is True)

# verify_many must still confirm internally when called directly and asked
# to -- the fix must not remove the safety, only relocate where the console
# invokes it.
_builtins.input = lambda p="": "y"
try:
    res = launcher().verify_many([cand(0)], require_confirm=True)
    check("verify_many still confirms when called directly with the default",
          isinstance(res, list))
finally:
    _builtins.input = _real_input

import builtins
real = builtins.input
builtins.input = lambda p="": "n"
try:
    launcher().verify_many([cand(0)], require_confirm=True)
    check("declining the batch aborts", False, "ran anyway")
except ExploitBlocked as e:
    check("declining the batch aborts", "aborted" in str(e))
finally:
    builtins.input = real

builtins.input = lambda p="": (_ for _ in ()).throw(EOFError)
try:
    launcher().verify_many([cand(0)], require_confirm=True)
    check("EOF never confirms a batch", False, "ran anyway")
except ExploitBlocked:
    check("EOF never confirms a batch", True)
finally:
    builtins.input = real

print("\n--- confirmed findings are upgraded ---")
L3 = launcher()
c = cand(0)
orig = L3._split_batch_output
L3._split_batch_output = lambda out, cs: ["The target is vulnerable."] * len(cs)
L3.verify_many([c], require_confirm=False)
L3._split_batch_output = orig
check("a vulnerable verdict upgrades confidence",
      c.confidence is Confidence.CONFIRMED)

print("\n--- empty and edge input ---")
check("no candidates returns empty", launcher().verify_many([]) == [])
check("all-unverifiable returns empty",
      launcher().verify_many([cand(0, has_check=False)]) == [])
check("all-out-of-scope returns empty",
      launcher().verify_many([cand(0, ip="1.2.3.4")], require_confirm=False) == [])
noexe = ExploitLauncher(SCOPE, audit_log=tempfile.mktemp(), msfconsole=None)
try:
    noexe.verify_many([cand(0)], require_confirm=False)
    check("missing msfconsole refused", False)
except ExploitBlocked as e:
    check("missing msfconsole refused", "msfconsole not found" in str(e))

print("\n--- newly wired tools ---")
NEW = ["masscan-sweep", "arp-discovery", "icmp-sweep", "netbios-scan",
       "smb-deep-enum", "smb-file-listing", "kerberos-userenum",
       "tls-structured"]
registered = {n for n, _ in Pipeline.STAGES}
for n in NEW:
    check(f"{n} registered", n in registered)
check("stage registry keeps growing without duplicates",
      len({n for n, _ in Pipeline.STAGES}) == len(Pipeline.STAGES) >= 28,
      str(len(Pipeline.STAGES)))
check("every stage has a method",
      all(hasattr(Pipeline, m) for _, m in Pipeline.STAGES))
check("every stage sits in exactly one phase",
      {n for _, _, ns in Pipeline.PHASES for n in ns} == registered)
check("every new stage is narrated",
      all(playbook.describe(n) for n in NEW),
      str([n for n in NEW if not playbook.describe(n)]))
check("new stages are in STANDARD",
      all(n in Pipeline.STANDARD for n in NEW))

print("\n--- the batch-invocation exemption is declared, not assumed ---")
check("RANGE_STAGES exists", hasattr(Pipeline, "RANGE_STAGES"))
check("only real stages are exempt", Pipeline.RANGE_STAGES <= registered,
      str(Pipeline.RANGE_STAGES - registered))
_exempt = Pipeline.RANGE_STAGES | Pipeline.SINGLE_SOURCE_STAGES
check("per-host stages are not exempt",
      not ({"smb-shares", "snmp-enumeration", "kerberos-userenum",
            "auth-admin-sprawl", "auth-share-access"} & _exempt))
check("single-source exemptions are real stages",
      Pipeline.SINGLE_SOURCE_STAGES <= registered)
check("the two exemption sets do not overlap",
      not (Pipeline.RANGE_STAGES & Pipeline.SINGLE_SOURCE_STAGES))

print("\n--- new stages skip cleanly without their tool ---")
def pipe(services=None, hosts=None):
    wd = Path(tempfile.mkdtemp())
    st = RunState(scope="t", workdir=str(wd))
    st.services = services or []
    st.live_hosts = hosts or []
    return Pipeline(SCOPE, wd, st)

from vision.core import extra as extra_mod
orig_tool = extra_mod._tool
extra_mod._tool = lambda n: None
p = pipe(hosts=["10.10.0.5"],
         services=[{"ip": "10.10.0.5", "port": 445, "proto": "tcp",
                    "name": "microsoft-ds"}])
crashed = []
for name in NEW:
    method = dict(Pipeline.STAGES)[name]
    try:
        r = getattr(p, method)()
        if not (r.skipped and r.ok):
            crashed.append(f"{name}: skipped={r.skipped} ok={r.ok}")
    except Exception as exc:
        crashed.append(f"{name}: {type(exc).__name__}: {exc}")
extra_mod._tool = orig_tool
check("all new stages skip cleanly when the tool is absent", not crashed,
      "; ".join(crashed[:2]))

print("\n--- tool coverage ---")
executed = set()
srcs = "\n".join(x.read_text(encoding="utf-8") for x in Path("vision/core").glob("*.py"))
for t in TOOLS:
    for n in [t.binary, t.name] + list(t.alt_binaries):
        if f'_tool("{n}")' in srcs or f'_have("{n}")' in srcs or f'BY_NAME["{n}"]' in srcs:
            executed.add(t.name)
            break
check(f"{len(executed)} tools now executed by a stage", len(executed) >= 20,
      str(len(executed)))
# Everything not automated must at least be reachable through the playbook,
# or it is a registered tool the operator has no route to.
pbsrc = Path("vision/analysis/playbook.py").read_text(encoding="utf-8")
idle = [t.name for t in TOOLS if t.name not in executed
        and not any(n in pbsrc for n in [t.binary, t.name] + list(t.alt_binaries))]
check("every registered tool has a route — a stage or the playbook",
      not idle, f"unreachable: {idle}")

print("\n--- situation playbook ---")
sits = playbook.situations()
check("situations defined", len(sits) >= 8, str(len(sits)))
check("every situation has steps", all(s for _k, _t, s in sits))
check("every situation states a goal, not a tool name",
      all(len(t) > 15 and " " in t for _k, t, _s in sits),
      str([t for _k, t, _s in sits if len(t) <= 15]))
check("keys are unique", len({k for k, _t, _s in sits}) == len(sits))
sit_steps = [st for _k, _t, s in sits for st in s]
check("every step explains why", all(len(st.why) > 25 for st in sit_steps))
check("intrusive work is flagged",
      sum(1 for st in sit_steps if st.intrusive) >= 4)
check("responder is flagged intrusive",
      all(st.intrusive for st in sit_steps if "responder" in st.command))
check("bettercap is flagged intrusive",
      all(st.intrusive for st in sit_steps if "bettercap" in st.command))
check("MITM tools ship commented out",
      all(st.command.strip().startswith("#") for st in sit_steps
          if any(w in st.command for w in ("responder ", "bettercap ", "ntlmrelayx"))))
check("for_situation resolves", len(playbook.for_situation("pivoting")) >= 3)
check("unknown situation is empty", playbook.for_situation("nope") == [])

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
