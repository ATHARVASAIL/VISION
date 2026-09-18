"""Documentation consistency.

Numbers in the docs drift the moment code changes, and a README claiming a test
count that no longer holds quietly undermines everything else it says. This
recomputes the ground truth — stage count, tool count, test count, command list
— and fails if any document contradicts it, so the docs cannot rot silently.

Also checks that every documented command actually exists and every internal
link resolves.
"""
import os, re, pathlib, subprocess, sys
sys.path.insert(0, '.')
from vision.core.pipeline import Pipeline
from vision.core.toolchain import TOOLS
from vision.analysis.correlate import CHAINS
from vision.cli import build_parser, VERSION

suites = [l.split("=(")[1].rstrip(")\n").split() for l in
          open("run_tests.sh") if l.startswith("SUITES=")][0]
# This suite counts the others, so it must never count itself — doing so makes
# run_tests.sh invoke this file, which invokes run_tests.sh's suites again.
countable = [s for s in suites if s != "test_docs"]

# run_tests.sh already ran every suite; reuse its total rather than running
# them all a second time. Falls back to computing it when invoked directly.
_env_total = os.environ.get("VISION_TEST_TOTAL")
if _env_total and _env_total.isdigit():
    tests = int(_env_total)
else:
    tests = 0
    for name in countable:
        r = subprocess.run([sys.executable, f"{name}.py"],
                           capture_output=True, text=True)
        tests += len(re.findall(r"^PASS", r.stdout, re.M))

T = {"stages": len(Pipeline.STAGES), "phases": len(Pipeline.PHASES),
     "tools": len(TOOLS), "chains": len(CHAINS), "suites": len(suites),
     "tests": tests, "version": VERSION,
     "cmds": sorted(build_parser()._subparsers._group_actions[0].choices)}
print("--- code ground truth ---")
for k, v in T.items():
    if k != "cmds":
        print(f"PASS  {k}: {v}")
print(f"PASS  commands: {', '.join(T['cmds'])}")

bad = []
CHECKS = [
    (r"tests-(\d+)%20across%20(\d+)%20suites", lambda g: (int(g[0]), int(g[1])) == (T["tests"], T["suites"])),
    (r"stages-(\d+)%20across%20(\d+)%20phases", lambda g: (int(g[0]), int(g[1])) == (T["stages"], T["phases"])),
    (r"orchestrates-(\d+)%20tools",        lambda g: int(g[0]) == T["tools"]),
    (r"(\d+) tests across (\d+) suites",   lambda g: (int(g[0]), int(g[1])) == (T["tests"], T["suites"])),
    (r"all \w+ suites, (\d+) tests",       lambda g: int(g[0]) == T["tests"]),
    (r"the (\d+)-test suite",              lambda g: int(g[0]) == T["tests"]),
    (r"(\d+) stages across (\d+) phases",  lambda g: (int(g[0]), int(g[1])) == (T["stages"], T["phases"])),
    (r"drives (\d+) existing",             lambda g: int(g[0]) == T["tools"]),
    (r"the (\d+)-tool toolchain",          lambda g: int(g[0]) == T["tools"]),
    (r"Audit (\d+) tools",                 lambda g: int(g[0]) == T["tools"]),
    (r"(\d+) chains ship",                 lambda g: int(g[0]) == T["chains"]),
    (r"Twenty stages",                     lambda g: T["stages"] == 20),
]
for doc in ["README.md", "MANUAL.md", "SECURITY.md", "KALI.md", "lab/LAB.md"]:
    text = pathlib.Path(doc).read_text(encoding="utf-8")
    for pat, ok in CHECKS:
        for m in re.finditer(pat, text):
            if not ok(m.groups()):
                bad.append(f"  {doc}: '{m.group(0)}' contradicts the code")

# every documented command must exist
for doc in ["README.md", "MANUAL.md"]:
    text = pathlib.Path(doc).read_text(encoding="utf-8")
    for cmd in set(re.findall(r"`vision (\w+)", text)):
        if cmd not in T["cmds"] and cmd not in ("run",):
            bad.append(f"  {doc}: documents `vision {cmd}` which does not exist")

# every internal link must resolve
for doc in ["README.md", "MANUAL.md", "SECURITY.md", "KALI.md", "lab/LAB.md"]:
    base = pathlib.Path(doc).parent
    for link in re.findall(r"\]\(([^)h][^)]*)\)", pathlib.Path(doc).read_text(encoding="utf-8")):
        if link.startswith("#"): continue
        if not (pathlib.Path(link).exists() or (base / link).exists()):
            bad.append(f"  {doc}: broken link -> {link}")

print("\n--- shipped SVGs survive a strict renderer ---")
# GitHub's SVG sanitiser strips xml:space, which silently collapsed every
# table's column alignment in the demo when it rendered on the repo page.
# Alignment must be geometry, and the resting state must be the finished frame.
import xml.etree.ElementTree as _ET
for _name in ("header.svg", "demo.svg"):
    _p = pathlib.Path("docs") / _name
    if not _p.exists():
        bad.append(f"  docs/{_name} is missing")
        continue
    _s = _p.read_text(encoding="utf-8")
    try:
        _ET.parse(_p)
    except Exception as _e:
        bad.append(f"  docs/{_name}: invalid XML — {_e}")
        continue
    _checks = [
        ("contains no <script>", "<script" not in _s),
        ("needs no xml:space", "xml:space" not in _s),
        ("every tspan is positioned",
         not re.search(r"<tspan(?![^>]*\sx=)", _s)),
        ("does not render blank without animation",
         not re.search(r"opacity:0[;\"]?[^}]*animation:[^;]*forwards", _s)),
        ("honours prefers-reduced-motion", "prefers-reduced-motion" in _s),
        ("has an aria-label", "aria-label" in _s),
    ]
    for _label, _ok in _checks:
        if _ok:
            print(f"PASS  docs/{_name} {_label}")
        else:
            bad.append(f"  docs/{_name}: {_label} — FAILED")

print("\n--- bare `vision` accepts flags ---")
# `vision -o dir` used to fail with "invalid choice: 'dir'", pointing at the
# output directory rather than the missing subcommand. The docs tell people
# bare `vision` is the way in, so adding a flag to it is the obvious next move.
import vision.cli as _cli
_cmds = set(_cli.build_parser()._subparsers._group_actions[0].choices)
for _case in ([], ["-o", "somewhere"], ["--debug"],
              ["-o", "x", "--intensity", "stealth"]):
    _raw = list(_case)
    if not _raw or (_raw[0].startswith("-")
                    and _raw[0] not in ("-h", "--help", "--version")):
        _raw = ["menu"] + _raw
    try:
        _a = _cli.build_parser().parse_args(_raw)
        if _a.func.__name__ != "cmd_menu":
            bad.append(f"  `vision {' '.join(_case)}` did not reach the menu")
        else:
            print(f"PASS  `vision {' '.join(_case) or '(bare)'}` opens the console")
    except SystemExit:
        bad.append(f"  `vision {' '.join(_case)}` failed to parse")

for _c in (["doctor"], ["run", "--scope", "10.0.0.0/24"], ["index"]):
    try:
        _a = _cli.build_parser().parse_args(_c)
        print(f"PASS  `vision {_c[0]}` still routes to {_a.func.__name__}")
    except SystemExit:
        bad.append(f"  `vision {_c[0]}` broke")

print("\n--- commands in the docs actually work ---")
# A doc that tells someone to run a path that has moved is broken, and no
# number check catches it. Test files moved into tests/ and one reference was
# left pointing at the old flat layout.
_cmd_re = re.compile(r"python3 (tests/)?(test_\w+\.py)")
for _doc in ("README.md", "MANUAL.md", "SECURITY.md", "KALI.md"):
    _text = pathlib.Path(_doc).read_text(encoding="utf-8")
    for _m in _cmd_re.finditer(_text):
        _path = (_m.group(1) or "") + _m.group(2)
        if not pathlib.Path(_path).exists():
            bad.append(f"  {_doc}: '{_m.group(0)}' — {_path} does not exist")
        else:
            print(f"PASS  {_doc} references {_path} correctly")
for _doc in ("README.md", "MANUAL.md"):
    if "./run_tests.sh" in pathlib.Path(_doc).read_text(encoding="utf-8"):
        print(f"PASS  {_doc} points at the suite runner")

print("\n--- repository hygiene ---")
# Scan output is engagement data. Committing one directory of it leaks a
# client's network to anyone who clones the repo.
_gi = pathlib.Path(".gitignore")
if not _gi.exists():
    bad.append("  .gitignore is missing — scan output would be committable")
else:
    _rules = _gi.read_text(encoding="utf-8")
    for _needed, _why in [
            ("evidence/", "raw tool output from real targets"),
            ("findings.json", "live findings"),
            ("*.jsonl", "run logs"),
            ("state.json", "session state"),
            (".venv/", "the virtualenv"),
            ("__pycache__/", "bytecode")]:
        if _needed in _rules:
            print(f"PASS  .gitignore excludes {_needed} ({_why})")
        else:
            bad.append(f"  .gitignore does not exclude {_needed} — {_why}")
    if "!docs/sample-report.html" in _rules:
        print("PASS  the shipped example report is still tracked")
    else:
        bad.append("  the example report would be ignored by the report.html rule")

# Nothing in the repo should be a file only the maintainer needs.
for _stray in ("TESTPLAN.md", "NOTES.md", "TODO.md", "scratch.py"):
    if pathlib.Path(_stray).exists():
        bad.append(f"  {_stray} is maintainer-only and should not ship")

print("\n--- the header SVG states real numbers ---")
# The header carries its own stat panel — stage count, tool count, test count.
# Nothing checked these against the code, and they drifted silently: the SVG
# said 20 stages / 1022 tests long after the real counts became 32 / 1564.
_hdr = pathlib.Path("docs/header.svg")
if _hdr.exists():
    _hs = _hdr.read_text(encoding="utf-8")
    for _n, _label in [(len(Pipeline.STAGES), "stage count"),
                       (len(Pipeline.PHASES), "phase count"),
                       (len(TOOLS), "tool count")]:
        if f">{_n}<" in _hs or str(_n) in _hs:
            print(f"PASS  header.svg states the current {_label} ({_n})")
        else:
            bad.append(f"  docs/header.svg: {_label} is not {_n} — stale")
    if str(tests) in _hs:
        print(f"PASS  header.svg states the current test count ({tests})")
    else:
        bad.append(f"  docs/header.svg: test count is not {tests} — stale")

print("\n--- no stale project-name residue anywhere in the shipped tree ---")
# The original rename swept only recognised source extensions (.py/.md/.sh/
# etc), which is exactly how .gitignore and lab/docker-compose.yml were
# missed — .gitignore has no extension at all, and .yml was simply outside
# the list. This check has no extension list: it walks every tracked file.
# Two categories are allowed to keep the old name, and only these two:
#   - historical evidence (captured tool output, e.g. a real nmap XML
#     transcript) — rewriting it would falsify the record of what a real
#     scan actually printed
#   - this comment itself, and the guard above it, which describe the bug
_old_name_re = re.compile(r"nexis", re.I)
_allowed_paths = {"tests/fixtures", "tests/test_docs.py"}
_hits = []
for _f in pathlib.Path(".").rglob("*"):
    if not _f.is_file():
        continue
    _parts = _f.parts
    if any(_p in (".venv", "__pycache__", ".git") or
           _p.endswith(".egg-info") for _p in _parts):
        continue
    _f_str = str(_f).replace(chr(92), "/")
    if any(_f_str.startswith(_a) for _a in _allowed_paths):
        continue
    try:
        _text = _f.read_text(errors="ignore")
    except OSError:
        continue
    if _old_name_re.search(_text) and "nonexistent" not in _text.lower().replace(
            _old_name_re.search(_text).group(0).lower(), "", 1):
        # Cheap check: a real hit is the standalone word, not a substring of
        # an unrelated word like "nonexistent".
        for _m in _old_name_re.finditer(_text):
            _ctx = _text[max(0, _m.start() - 6):_m.start() + 10].lower()
            if "nonexist" not in _ctx:
                _hits.append(str(_f))
                break
if _hits:
    bad.append(f"  stale project-name residue in: {', '.join(_hits[:8])}")
else:
    print("PASS  no stale project-name residue outside allowed historical fixtures")

print("\n--- the README's animated title states real numbers too ---")
# The typing-SVG title embeds stage/phase/test counts inside a URL query
# string. The header.svg check above never looks there, and it drifted
# silently: 20 Stages / 5 Phases long after the real counts became 32 / 6.
_readme = pathlib.Path("README.md").read_text(encoding="utf-8")
_typing = re.search(r"lines=([^\"]+)", _readme)
if _typing:
    _line = _typing.group(1)
    for _n, _label in [(len(Pipeline.STAGES), "stage count"),
                       (len(Pipeline.PHASES), "phase count")]:
        if str(_n) in _line:
            print(f"PASS  README typing title states the current {_label} ({_n})")
        else:
            bad.append(f"  README.md: animated title {_label} is stale "
                       f"(does not contain {_n})")

print("\n--- no build artefacts committed to the repository ---")
# .egg-info is regenerated by every `pip install -e .`, so it legitimately
# exists in any installed working copy — flagging that would fail on every
# correctly set-up machine. What matters is that it never reaches git or a
# shipped archive, which .gitignore already handles. This verifies the
# ignore rules actually cover each artefact rather than checking the disk.
_gi_text = pathlib.Path(".gitignore").read_text(encoding="utf-8")
for _artefact, _pattern in (("vision.egg-info", "*.egg-info/"),
                            ("build", "build/"),
                            ("dist", "dist/")):
    if _pattern in _gi_text:
        print(f"PASS  .gitignore excludes {_artefact} build artefacts")
    else:
        bad.append(f"  .gitignore does not exclude {_pattern} — a build "
                   f"artefact could be committed")

print("\n--- .gitignore matches the real default output directory ---")
# .gitignore has no recognised extension, so a blanket text-substitution pass
# over *.py/*.md/*.sh files silently skipped it during the project rename —
# it kept excluding "nexis-run/" while every default output path had already
# become "vision-run/". A gap here means the first real scan's output
# directory is NOT ignored, which is exactly the engagement-data leak
# .gitignore exists to prevent.
import re as _re2
_cli_src = pathlib.Path("vision/cli.py").read_text(encoding="utf-8")
_defaults = set(_re2.findall(r'default="\./([\w-]+)"', _cli_src))
_gi = pathlib.Path(".gitignore").read_text(encoding="utf-8")
for _d in _defaults:
    if f"{_d}/" in _gi or _d in _gi:
        print(f"PASS  .gitignore excludes the real default output dir ({_d}/)")
    else:
        bad.append(f"  .gitignore does not exclude the actual default "
                   f"output directory ({_d}/) — engagement data would "
                   f"not be ignored by default")

print("\n--- SECURITY.md's test table lists every real suite with a real count ---")
# This table drifted badly before anything checked it: it claimed "all twelve
# suites" when there were 26, was missing 12 suites entirely, and every count
# it did list was stale. Nothing about the doc-number checks above covers a
# markdown table's row contents, only inline numeric claims — so this table
# rotted silently for rounds. Checked explicitly here.
_sec_text = pathlib.Path("SECURITY.md").read_text(encoding="utf-8")
_table_suites = set(re.findall(r"\| `(test_\w+)` \|", _sec_text))
_real_suites = set(countable) | {"test_docs"}
_missing_from_table = _real_suites - _table_suites
_extra_in_table = _table_suites - _real_suites
if _missing_from_table:
    bad.append(f"  SECURITY.md test table is missing: {sorted(_missing_from_table)}")
else:
    print("PASS  SECURITY.md test table lists every real suite")
if _extra_in_table:
    bad.append(f"  SECURITY.md test table lists suites that no longer exist: "
               f"{sorted(_extra_in_table)}")
else:
    print("PASS  SECURITY.md test table has no stale suite entries")

print("\n--- README anchors and licence ---")
# A table of contents that points at nothing is invisible until someone clicks
# it. GitHub drops emoji in place and leaves the space behind, which is why
# these anchors carry a leading hyphen.
def _gh_slug(t):
    t = t.lower()
    t = "".join(c if (c.isalnum() or c in " -_") else "" for c in t)
    return t.replace(" ", "-")

_readme = pathlib.Path("README.md").read_text(encoding="utf-8")
_slugs = {_gh_slug(h) for h in re.findall(r"^#{2,3} (.+)$", _readme, re.M)}
_dead = [a for a in re.findall(r"\]\(#([^)]+)\)", _readme) if a not in _slugs]
if _dead:
    bad.append(f"  README.md: table of contents points at missing headings: {_dead}")
else:
    _n = len(re.findall(r"\]\(#", _readme))
    print(f"PASS  README.md all {_n} in-page anchors resolve")

if not pathlib.Path("LICENSE").exists():
    bad.append("  LICENSE file is missing")
else:
    _lic = pathlib.Path("LICENSE").read_text(encoding="utf-8")
    if "MIT License" not in _lic:
        bad.append("  LICENSE is not the MIT licence")
    elif "[" in _lic.split("Copyright")[1][:60]:
        bad.append("  LICENSE still has a placeholder copyright holder")
    else:
        print("PASS  LICENSE present and filled in")
    if "LICENSE" not in _readme:
        bad.append("  README.md does not link the LICENSE")
    else:
        print("PASS  README.md links the licence")

print("\n--- documentation ---")
if bad:
    for b in bad:
        print("FAIL " + b.strip())
else:
    for doc in ["README.md", "MANUAL.md", "SECURITY.md", "KALI.md", "lab/LAB.md"]:
        print(f"PASS  {doc} agrees with the code")
print("\n" + "=" * 52)
print("ALL PASS" if not bad else f"FAILURES ({len(bad)})")
sys.exit(1 if bad else 0)
