"""`vision doctor` and `vision setup`.

doctor  — read-only report of what's installed, what's missing, what vision can
          and cannot do as a result.
setup   — installs missing tools. Shows the exact commands first, requires
          confirmation, and never runs anything the operator hasn't seen.
"""

from __future__ import annotations

import subprocess
from collections import defaultdict

from . import ui
from .ui import S, paint
from .toolchain import (
    TOOLS, BY_NAME, Need, Phase, Tool, Environment,
    detect_environment, choose_method, kali_plan,
)

NEED_STYLE = {
    Need.CORE: (S.RED, "core"),
    Need.STANDARD: (S.YELLOW, "standard"),
    Need.OPTIONAL: (S.GREY, "optional"),
}


def _capability_report(installed: set[str]) -> list[str]:
    """Translate presence into what the operator can actually do. More useful
    than a raw checklist — 'you can't run check' beats 'msfconsole missing'."""
    caps = [
        ("Port and service discovery", {"nmap"}),
        ("Fast large-range sweeps", {"masscan"}),
        ("Layer-2 host discovery", {"arp-scan"}),
        ("SMB / Active Directory enumeration", {"netexec", "smbmap"}),
        ("LDAP and BloodHound collection", {"ldapsearch", "bloodhound-python"}),
        ("Templated CVE scanning", {"nuclei"}),
        ("TLS posture assessment", {"testssl.sh", "sslscan"}),
        ("Exploit advisory (module index)", {"metasploit"}),
        ("Safe verification via check()", {"metasploit"}),
        ("Credential attacks", {"hydra", "hashcat"}),
        ("Kerberos spraying", {"kerbrute"}),
        ("Pivoting and tunnelling", {"chisel", "proxychains"}),
    ]
    out = []
    for label, req in caps:
        have = req & installed
        if have == req:
            out.append(ui.ok(label))
        elif have:
            miss = ", ".join(sorted(req - have))
            out.append(ui.warn(f"{label} " + paint(f"(partial — needs {miss})", S.DIM)))
        else:
            miss = ", ".join(sorted(req))
            out.append(ui.bad(f"{label} " + paint(f"(needs {miss})", S.DIM)))
    return out


def cmd_doctor(args) -> int:
    env = detect_environment()
    print(ui.banner(compact=args.no_banner))

    print(ui.section("Environment"))
    plat = f"{env.os_name} / {env.distro or 'unknown'}"
    if env.is_kali:
        plat += paint("  (Kali — most tools ship preinstalled)", S.GREEN)
    print(ui.info(f"platform        {plat}"))
    print(ui.info(f"package managers {', '.join(env.package_managers) or 'none detected'}"))
    print(ui.info(f"running as       {'root' if env.is_root else 'user'}"))
    if any(t.go for t in TOOLS) and "go" in env.package_managers and not env.go_bin_on_path:
        print(ui.warn("~/go/bin is not on PATH — go-installed tools will not be found"))
        print(paint("      echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc", S.DIM))
    if (any(t.pipx or t.pip for t in TOOLS)
            and any(pm in env.package_managers for pm in ("pipx", "pip"))
            and not env.local_bin_on_path):
        print(ui.warn("~/.local/bin is not on PATH — pipx/pip tools "
                      "(netexec, sslyze, bloodhound-python, ...) install but "
                      "stay invisible, and count as missing"))
        print(paint("      echo 'export PATH=$PATH:~/.local/bin' >> ~/.bashrc",
                    S.DIM))

    groups: dict[Phase, list[Tool]] = defaultdict(list)
    for t in TOOLS:
        groups[t.phase].append(t)

    installed: set[str] = set()
    total_missing: list[Tool] = []

    for phase in Phase:
        tools = groups.get(phase, [])
        if not tools:
            continue
        present = [t for t in tools if t.installed]
        installed |= {t.name for t in present}
        print(ui.section(phase.value.title(),
                         f"{len(present)}/{len(tools)} available"))
        rows = []
        for t in sorted(tools, key=lambda x: (x.need.value, x.name)):
            if t.installed:
                ver = t.version() if args.versions else "installed"
                rows.append([paint("✓", S.GREEN), t.name,
                             paint(ver or "?", S.DIM), t.purpose])
            else:
                total_missing.append(t)
                style, lbl = NEED_STYLE[t.need]
                rows.append([paint("✗", S.RED), paint(t.name, style),
                             paint(lbl, S.DIM), paint(t.purpose, S.DIM)])
        print(ui.table(rows, ["", "TOOL", "VERSION", "PURPOSE"]))

    print(ui.section("Capabilities"))
    for line in _capability_report(installed):
        print(line)

    print(ui.section("Summary"))
    core_missing = [t for t in total_missing if t.need is Need.CORE]
    std_missing = [t for t in total_missing if t.need is Need.STANDARD]
    lines = [
        f"{paint(str(len(TOOLS) - len(total_missing)), S.GREEN, S.BOLD)} of {len(TOOLS)} tools installed",
    ]
    if core_missing:
        lines.append(paint(f"{len(core_missing)} CORE tools missing — "
                           "vision will not function fully", S.RED))
    if std_missing:
        lines.append(paint(f"{len(std_missing)} standard tools missing", S.YELLOW))
    if not total_missing:
        lines.append(paint("Everything present. You're ready to scan.", S.GREEN))
    print(ui.box(lines, title="status"))

    if total_missing:
        print("\n" + ui.info("install what's missing:"))
        print(paint("      vision setup --need standard", S.ACCENT))
        print(paint("      vision setup --dry-run        ", S.DIM)
              + paint("# see the commands first", S.DIM))
    return 0


def _plan(env: Environment, need: Need, only: list[str] | None
          ) -> tuple[list[tuple[Tool, str, list[str]]], list[Tool]]:
    order = {Need.CORE: 0, Need.STANDARD: 1, Need.OPTIONAL: 2}
    plan, unplannable = [], []
    go_waiting: list[Tool] = []
    for t in TOOLS:
        if only and t.name not in only:
            continue
        if not only and order[t.need] > order[need]:
            continue
        if t.installed:
            continue
        pm = choose_method(t, env)
        if pm:
            plan.append((t, pm, t.install_plan(pm, env.is_root)))
        elif t.go and "go" not in env.package_managers:
            # choose_method already tried every *available* manager and found
            # none that works — the tool having a brew= field is irrelevant on
            # a box with no brew. What matters is whether Go itself could be
            # bootstrapped to unlock the go= path that choose_method could not
            # use because Go wasn't there yet.
            go_waiting.append(t)
        else:
            unplannable.append(t)

    if go_waiting:
        go_pm, go_argv = _go_bootstrap(env)
        if go_argv:
            # Installing Go is itself a step in the plan, ordered first, so it
            # prints and is confirmed like any other row rather than being a
            # special case the operator has to understand separately.
            plan.insert(0, (_GO_BOOTSTRAP, go_pm, go_argv))
            for t in go_waiting:
                plan.append((t, "go", t.install_plan("go", env.is_root)))
        else:
            unplannable.extend(go_waiting)

    return plan, unplannable


# Synthetic entry so bootstrapping Go is one visible row in the install plan,
# not a silent side effect.
_GO_BOOTSTRAP = Tool(
    "golang", "go", Phase.DISCOVERY,
    "Go toolchain — required to install naabu, dnsx, subfinder, kerbrute",
    Need.OPTIONAL, apt="golang-go", brew="go")


def _go_bootstrap(env: Environment) -> tuple[str | None, list[str] | None]:
    for pm in ("apt", "brew"):
        if pm in env.package_managers:
            argv = _GO_BOOTSTRAP.install_plan(pm, env.is_root)
            if argv:
                return pm, argv
    return None, None


def _setup_kali(args, env: Environment) -> int:
    """Kali path: install curated metapackages rather than 40 loose packages.

    Falls back to per-tool installs if the operator passes --no-metapackages,
    since Kali derivatives and minimal images don't always carry them."""
    plan = kali_plan(is_root=env.is_root)
    still_missing = [t for t in TOOLS if not t.installed]

    print(ui.section("Kali detected", "using curated metapackages"))
    print(ui.info(f"{len(TOOLS) - len(still_missing)}/{len(TOOLS)} tools already present"))

    # Kali's metapackages are apt bundles; they do not and cannot cover the
    # four tools that only exist as `go install` targets (naabu, dnsx,
    # subfinder, kerbrute). Left unmentioned, this path silently installs
    # everything else and those four are simply never present — the operator
    # has no reason to suspect a "successful" setup left anything out.
    go_only_missing = [t for t in still_missing
                      if t.go and not choose_method(t, env)]
    if go_only_missing:
        print(ui.warn(
            f"{len(go_only_missing)} tool(s) need Go and are not in any "
            "metapackage: " + ", ".join(t.name for t in go_only_missing)))
        print(paint("      run 'vision setup --no-metapackages --only "
                    + " ".join(t.name for t in go_only_missing)
                    + "' to get these too", S.DIM))

    if not still_missing:
        print(ui.ok("Everything vision needs is already installed."))
        print("\n" + ui.info("next: " + paint("vision index", S.ACCENT)))
        return 0

    print(ui.section("Install plan", f"{len(plan)} metapackage(s)"))
    rows = [[paint(pkg, S.ACCENT), covers[:52]] for pkg, covers, _ in plan]
    print(ui.table(rows, ["METAPACKAGE", "COVERS"]))
    print("\n" + ui.warn("these are large — several GB and 10-30 minutes"))
    print(ui.info("for a minimal install instead: "
                  + paint("vision setup --no-metapackages --need core", S.ACCENT)))

    if args.dry_run:
        print("\n" + ui.info("dry run — nothing was installed"))
        for _, _, argv in plan:
            print(paint(f"      {' '.join(argv)}", S.DIM))
        return 0

    print()
    try:
        answer = input(paint(f"  Install {len(plan)} metapackage(s)? [y/N] ",
                             S.BOLD)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return 130
    if answer not in ("y", "yes"):
        print(ui.info("aborted"))
        return 0

    print(ui.section("Installing"))
    ok_list, fail_list = [], []
    for i, (pkg, _covers, argv) in enumerate(plan, 1):
        print(ui.step(i, len(plan), pkg))
        with ui.Spinner(f"installing {pkg}") as sp:
            try:
                r = subprocess.run(argv, capture_output=True, text=True,
                                   timeout=max(args.timeout, 3600))
                code, err = r.returncode, (r.stderr or "")[-400:]
            except subprocess.TimeoutExpired:
                code, err = -1, "timed out"
            except OSError as e:
                code, err = -1, str(e)
            el = sp.elapsed
        if code == 0:
            ok_list.append(pkg)
            print(ui.ok(f"{pkg} " + paint(f"{el:.0f}s", S.DIM)))
        else:
            fail_list.append((pkg, err))
            print(ui.bad(f"{pkg} " + paint(f"exit {code}", S.DIM)))
            if args.verbose and err:
                print(paint(f"      {err.strip()[:300]}", S.DIM))

    remaining = [t for t in TOOLS if not t.installed]
    print(ui.section("Result"))
    lines = [f"{paint(str(len(ok_list)), S.GREEN, S.BOLD)} metapackage(s) installed",
             f"{len(TOOLS) - len(remaining)}/{len(TOOLS)} tools now present"]
    if fail_list:
        lines.append(paint(f"{len(fail_list)} failed", S.RED))
    print(ui.box(lines, title="setup"))

    # Metapackages won't cover go/pipx-only tools like kerbrute or netexec.
    leftover = [t for t in remaining if t.need is not Need.OPTIONAL]
    if leftover:
        print("\n" + ui.warn(f"{len(leftover)} tool(s) not in any metapackage:"))
        print(paint("      " + ", ".join(t.name for t in leftover[:12]), S.DIM))
        print(ui.info("get them with: "
                      + paint("vision setup --no-metapackages", S.ACCENT)))

    print("\n" + ui.info("next: " + paint("vision index", S.ACCENT)
                         + paint("  (build the Metasploit module index)", S.DIM)))
    return 1 if fail_list else 0


def cmd_setup(args) -> int:
    env = detect_environment()
    # Called from the console's readiness check, this is a step inside an
    # existing flow — printing the banner again breaks it in half.
    if not getattr(args, "inline", False):
        print(ui.banner(compact=args.no_banner))

    # On Kali, prefer metapackages unless the operator asked for specific tools.
    if env.is_kali and not args.only and not args.no_metapackages:
        return _setup_kali(args, env)

    need = Need(args.need)
    only = args.only or None
    if only:
        unknown = [n for n in only if n not in BY_NAME]
        if unknown:
            print(ui.bad(f"unknown tool(s): {', '.join(unknown)}"))
            return 1

    plan, unplannable = _plan(env, need, only)

    if not plan and not unplannable:
        print(ui.section("Setup"))
        print(ui.ok("Nothing to install — everything requested is already present."))
        return 0

    print(ui.section("Install plan", f"{len(plan)} tool(s)"))
    if not env.package_managers:
        print(ui.bad("No supported package manager found (apt/brew/pipx/go/gem/cargo)."))
        return 1

    rows = [[t.name, paint(pm, S.ACCENT), paint(" ".join(argv), S.DIM)]
            for t, pm, argv in plan]
    print(ui.table(rows, ["TOOL", "VIA", "COMMAND"]))

    if unplannable:
        print("\n" + ui.warn(f"{len(unplannable)} tool(s) need manual installation:"))
        for t in unplannable:
            print(paint(f"      {t.name:<18}", S.YELLOW)
                  + paint(t.manual or "no package available for this platform", S.DIM))

    if args.dry_run:
        print("\n" + ui.info("dry run — nothing was installed"))
        return 0

    if not plan:
        return 0

    print()
    if not env.is_root and any(p[1] == "apt" for p in plan):
        print(ui.warn("apt installs will prompt for sudo"))
    try:
        answer = input(paint(f"  Install {len(plan)} tool(s)? [y/N] ", S.BOLD)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return 130
    if answer not in ("y", "yes"):
        print(ui.info("aborted"))
        return 0

    print(ui.section("Installing"))
    succeeded, failed = [], []
    for i, (t, pm, argv) in enumerate(plan, 1):
        print(ui.step(i, len(plan), f"{t.name} " + paint(f"via {pm}", S.DIM)))
        with ui.Spinner(f"installing {t.name}") as sp:
            try:
                r = subprocess.run(argv, capture_output=True, text=True,
                                   timeout=args.timeout)
                code, err = r.returncode, (r.stderr or "")[-400:]
            except subprocess.TimeoutExpired:
                code, err = -1, f"timed out after {args.timeout}s"
            except OSError as e:
                code, err = -1, str(e)
            el = sp.elapsed
        if code == 0:
            succeeded.append(t)
            print(ui.ok(f"{t.name} " + paint(f"{el:.1f}s", S.DIM)))
            if t.notes:
                print(paint(f"      note: {t.notes}", S.DIM))
        else:
            failed.append((t, err))
            print(ui.bad(f"{t.name} " + paint(f"exit {code}", S.DIM)))
            if args.verbose and err:
                print(paint(f"      {err.strip()[:300]}", S.DIM))

    print(ui.section("Result"))
    lines = [f"{paint(str(len(succeeded)), S.GREEN, S.BOLD)} installed"]
    if failed:
        lines.append(f"{paint(str(len(failed)), S.RED, S.BOLD)} failed")
    print(ui.box(lines, title="setup"))

    if failed:
        print("\n" + ui.warn("failed installs — try manually:"))
        for t, err in failed:
            pm = choose_method(t, env)
            argv = t.install_plan(pm, env.is_root) if pm else None
            print(paint(f"      {t.name:<18}", S.YELLOW)
                  + paint(" ".join(argv) if argv else (t.manual or "n/a"), S.DIM))

    if any(t.name == "nuclei" for t in succeeded):
        print("\n" + ui.info("run " + paint("nuclei -update-templates", S.ACCENT)
                             + " before your first scan"))
    if any(t.name == "metasploit" for t in succeeded):
        print(ui.info("run " + paint("vision index", S.ACCENT)
                      + " to build the module index"))
    return 1 if failed else 0
