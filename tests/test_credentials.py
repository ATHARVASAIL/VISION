"""Credential tests.

One property dominates: a credential must never reach disk. Not the state
file, not the run log, not the evidence directory, not the report. Everything
Vision writes is designed to be kept — state survives crashes, logs get attached
to reports, evidence is archived for months. A password that leaks into any of
them outlives the engagement it belonged to.

The tests below use a distinctive sentinel and then grep every artefact Vision
produces for it.
"""
import json, os, pickle, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.core.credentials import (
    Credential, CredentialStore, REDACTED, nxc_args, smb_env, impacket_target,
)
from vision.core.runlog import RunLog, redact
from vision.core.pipeline import Pipeline, RunState
from vision.core.scope import Scope
from vision.core.triage import Triage
from vision.report.html import build_report

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

SENTINEL = "Zx9QuietHorse!Sentinel"
CRED = Credential(username="svc_scan", _secret=SENTINEL, domain="CORP")
SCOPE = Scope.from_lists(["10.10.0.0/24"])

print("--- the object refuses to reveal itself ---")
check("repr is redacted", SENTINEL not in repr(CRED))
check("repr says so", REDACTED in repr(CRED))
check("str is identity only", str(CRED) == "CORP\\svc_scan" and SENTINEL not in str(CRED))
check("display is safe", SENTINEL not in CRED.display)
check("f-string is safe", SENTINEL not in f"{CRED}")
check("format() is safe", SENTINEL not in format(CRED))
check("as_dict omits the secret", SENTINEL not in json.dumps(CRED.as_dict()))
check("as_dict keeps identity", CRED.as_dict()["username"] == "svc_scan")
check("secret is reachable when deliberately asked for", CRED.secret == SENTINEL)

print("\n--- serialisation is refused, not merely avoided ---")
try:
    pickle.dumps(CRED)
    check("pickling refused", False, "a credential was pickled")
except TypeError as e:
    check("pickling refused", "not serialisable" in str(e))
try:
    json.dumps(CRED.__dict__)
    check("__dict__ would leak — as_dict is the only safe path",
          SENTINEL in json.dumps(CRED.__dict__),
          "documents why callers must use as_dict")
except TypeError:
    check("__dict__ not serialisable", True)

print("\n--- the store keeps nothing after clear ---")
store = CredentialStore()
check("empty store is falsey", not store)
store.add(CRED)
check("credential retrievable", store.primary().username == "svc_scan")
check("summary is safe", SENTINEL not in store.summary())
check("summary names the account", "svc_scan" in store.summary())
store.add(Credential(username="svc_scan", _secret="other", domain="CORP"))
check("re-adding the same identity replaces it", len(store) == 1)
store.add(Credential(username="other_user", _secret="x"))
check("different identity is additive", len(store) == 2)
store.clear()
check("clear empties the store", len(store) == 0)
check("empty store summary explains itself",
      "unauthenticated" in CredentialStore().summary())
try:
    CredentialStore().add(Credential(username="x", _secret=""))
    check("a credential without a secret is refused", False)
except ValueError:
    check("a credential without a secret is refused", True)

print("\n--- argv construction ---")
args = nxc_args(CRED)
check("username passed", "svc_scan" in args)
check("domain passed", "CORP" in args)
check("password flag used", "-p" in args)
check("hash uses -H",
      "-H" in nxc_args(Credential(username="u", _secret="aad3b", kind="nthash")))
check("no credential means a null session", nxc_args(None) == ["-u", "", "-p", ""])
env = smb_env(CRED)
check("env carries the secret out of argv", env.get("PASSWD") == SENTINEL)
check("env keeps the rest of the environment", "PATH" in env)
check("no credential leaves the environment untouched", "PASSWD" not in smb_env(None))
check("impacket target built", impacket_target(CRED, "10.0.0.5")
      == f"CORP/svc_scan:{SENTINEL}@10.0.0.5")
check("no credential means a bare host", impacket_target(None, "10.0.0.5") == "10.0.0.5")

print("\n--- redaction covers every shape a credential takes in argv ---")
shapes = [
    (["nxc", "smb", "10.0.0.5", *nxc_args(CRED)], "netexec password"),
    (["nxc", "smb", "10.0.0.5", "-u", "u", "-H", SENTINEL], "NT hash"),
    (["impacket-GetUserSPNs", impacket_target(CRED, "10.0.0.5")], "impacket target"),
    (["impacket-secretsdump", f"admin:{SENTINEL}@10.0.0.5"], "domainless target"),
    (["evil-winrm", "-i", "10.0.0.5", "-u", "u", "-p", SENTINEL], "evil-winrm"),
    (["tool", f"--password={SENTINEL}"], "inline form"),
    (["hydra", "-l", "root", "-p", SENTINEL, "ssh://x"], "hydra"),
]
for argv, label in shapes:
    rendered = " ".join(redact(argv))
    check(f"redacted: {label}", SENTINEL not in rendered, rendered[:60])
check("host arguments survive redaction",
      "10.0.0.5" in " ".join(redact(["nxc", "smb", "10.0.0.5", *nxc_args(CRED)])))
check("smbmap -H is still treated as a host",
      "10.0.0.5" in " ".join(redact(["smbmap", "-H", "10.0.0.5", "-u", "x",
                                     "-p", SENTINEL])))
check("nmap ports still readable",
      "53,161" in " ".join(redact(["nmap", "-p", "53,161", "10.0.0.5"])))

print("\n--- nothing Vision writes contains the secret ---")
d = Path(tempfile.mkdtemp())
log = RunLog(d / "run.jsonl", evidence_dir=d / "evidence")
log.event("run-start", scope="10.10.0.0/24", operator="analyst")
log.command("auth-admin-sprawl", ["nxc", "smb", "10.10.0.5", *nxc_args(CRED)],
            0, 1.2, stdout="SMB 10.10.0.5 [+] CORP\\svc_scan (Pwn3d!)",
            stderr="", target="10.10.0.5")
log.command("auth-kerberoast", ["impacket-GetUserSPNs",
                                impacket_target(CRED, "10.10.0.5")],
            0, 2.0, stdout="ServicePrincipalName  Name", target="10.10.0.5")

state = RunState(scope="10.10.0.0/24", workdir=str(d))
state.findings = [{
    "ip": "10.10.0.5", "port": 445, "title": "Account is local administrator",
    "severity": "high", "confidence": "confirmed", "cves": [],
    "source": "netexec:auth", "evidence": "SMB 10.10.0.5 (Pwn3d!)",
    "remediation": "Review local admin membership.",
}]
state.triage = Triage().as_dict()
state.save(d / "state.json")
(d / "findings.json").write_text(json.dumps(
    {"services": [], "findings": state.findings}, indent=2))
(d / "report.html").write_text(build_report(state.findings, []))

leaks = []
for root, _dirs, files in os.walk(d):
    for fname in files:
        path = Path(root) / fname
        try:
            if SENTINEL in path.read_text(errors="replace"):
                leaks.append(str(path.relative_to(d)))
        except OSError:
            pass
check("NO ARTEFACT CONTAINS THE SECRET", not leaks, f"leaked in: {leaks}")
check("artefacts were actually written",
      len(list(d.rglob("*"))) >= 5, "the test would be vacuous otherwise")
check("the run log still records the command",
      "nxc" in (d / "run.jsonl").read_text())
check("the finding survived", "local administrator" in (d / "report.html").read_text())

print("\n--- RunState has no credential field at all ---")
check("no credential attribute", not hasattr(RunState(scope="x", workdir="."), "credential"))
check("credential cannot be serialised by accident",
      "credential" not in json.dumps(
          {k: v for k, v in vars(RunState(scope="x", workdir=".")).items()},
          default=str))

print("\n--- authenticated stages skip cleanly with no credential ---")
def pipe(cred=None):
    wd = Path(tempfile.mkdtemp())
    st = RunState(scope="t", workdir=str(wd))
    st.services = [{"ip": "10.10.0.5", "port": 445, "proto": "tcp",
                    "name": "microsoft-ds"}]
    return Pipeline(SCOPE, wd, st, credential=cred)

AUTH = ["auth-admin-sprawl", "auth-share-access", "auth-password-policy",
        "auth-kerberoast"]
by_method = dict(Pipeline.STAGES)
p = pipe(None)
skipped = []
for name in AUTH:
    r = getattr(p, by_method[name])()
    skipped.append(r.skipped and r.ok and "credential" in r.reason)
check("all four skip and say why", all(skipped), str(skipped))

print("\n--- authenticated stages are registered properly ---")
registered = {n for n, _ in Pipeline.STAGES}
check("all four registered", set(AUTH) <= registered)
check("they form their own phase",
      any(t == "Authenticated Assessment" for t, _, _ in Pipeline.PHASES))
check("every stage still sits in exactly one phase",
      {n for _, _, ns in Pipeline.PHASES for n in ns} == registered)
from vision.analysis import playbook
check("every authenticated stage is narrated",
      all(playbook.describe(n) for n in AUTH),
      str([n for n in AUTH if not playbook.describe(n)]))

print("\n--- read-only: no authenticated stage executes on a host ---")
import inspect
from vision.core import authenticated as auth_mod
# Strip comments and docstrings: prose describing what the module does NOT do
# should not trip a check on what it does.
import ast as _ast, re as _re
_tree = _ast.parse(inspect.getsource(auth_mod))
for _node in _ast.walk(_tree):
    if isinstance(_node, (_ast.FunctionDef, _ast.ClassDef, _ast.Module)) \
            and _ast.get_docstring(_node):
        _node.body = _node.body[1:]
src = _ast.unparse(_tree)
src = _re.sub(r"#.*", "", src)

for danger in ("psexec", "wmiexec", "smbexec", "atexec", "xp_cmdshell"):
    check(f"no command execution via {danger}", danger not in src)
check("no password guessing tool invoked",
      not any(w in src for w in ("hydra", "medusa", "ncrack")))
check("no wordlist iteration over passwords",
      "for password" not in src and "for pw" not in src)
check("--shares and --pass-pol are read-only netexec flags",
      "--shares" in src and "--pass-pol" in src)

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
