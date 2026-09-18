# vision — User Manual

---

## 1. Install

**Kali Linux is the recommended platform** — see `KALI.md` for VM setup,
network configuration, and the Kali-specific install path. Vision also runs on
Ubuntu, Debian, Parrot, and macOS.

Quickest path:

```bash
unzip vision.zip && cd vision
./install.sh              # venv + deps + self-test
./install.sh --system     # also put `vision` on your PATH
```

Manual install:

```bash
unzip vision.zip && cd vision
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
vision --help
```

Requires Python 3.10+. Metasploit Framework is optional for `index` and
`advise`, required only to actually run `check`/`exploit`.

```bash
# Debian/Kali — already present on Kali
sudo apt install metasploit-framework
which msfconsole
```

Verify the install:

```bash
./run_tests.sh                    # the whole suite
python3 tests/test_advisor.py     # just the exploit gates, no Metasploit needed
```

---

## 1a. Setup — one command

```bash
./setup.sh              # install + index + ready
./setup.sh --tools      # also install the security toolchain
```

This replaces the old four-step ritual (`install.sh`, `vision doctor`,
`vision setup`, `sudo msfdb init`, `vision index`). Each step is skipped if it
is already done, so re-running costs nothing.

The Metasploit index step matters more than it looks: without it the exploit
advisory returns nothing, which reads as *"there are no exploits for this
host"* rather than *"the index was never built"*.

---

## 2. First run — one command

```bash
vision
```

That is the whole setup. Vision checks what it needs, offers to fix anything
missing, then walks you through target and depth:

```
▸ Readiness  41/55 tools installed
  ✗ missing core tools: nuclei, metasploit
      Vision will run, but these stages cannot: exploitation, vulnerability
  Install them now? [Y/n]
  ! no Metasploit module index — exploit advisory unavailable
  Build it now? (about 10 seconds) [Y/n]

  Start a new assessment? [Y/n]
```

Previously this was four separate commands, and you only discovered the index
was missing after the advisory came back empty. Anything fixable is offered
where the problem is found.

Findings announce themselves as they are discovered rather than waiting for the
summary — on a fifteen-minute scan, learning at minute two that a host runs
unauthenticated Redis is the difference between acting on it and reading about
it afterwards:

```
  [7/13] datastore-exposure
    CRITICAL 192.168.56.104:6379   Redis exposed without authentication
              +PONG  ·  no credential required
    HIGH     192.168.56.104:11211  Memcached exposed without authentication
```

Only medium and above are announced — surfacing every informational banner
would bury the two lines that matter under forty that do not.

Any finding can be opened in full from the findings list: evidence, the tool
that reported it, what its confidence rating actually means, remediation, and
the controls it maps to — enough to write it up without leaving the console.

An empty result is reported honestly. "No findings" is ambiguous, so Vision says
which stages ran, which did not, and why:

```
  ✓ 2 stage(s) ran and found nothing
  ! 3 stage(s) did not run:
      smb-shares              smbmap not installed
      snmp-enumeration        onesixtyone/snmpwalk not installed

  · 2 stage(s) were skipped for missing tools — a clean result here is not
    full coverage.
```

After a scan, the next menu is built from what you actually have:

```
▸ Results   192.168.56.0/24  ·  6 hosts  ·  23 services  ·  9 high/critical
  ████████████████████████████████
  4 critical   5 high   3 medium   1 low

▸ What next?
  [1]  Findings              13 total, 9 need attention
  [2]  Attack paths          2 chain(s) derived
  [3]  Open ports            23 service(s)
  [4]  Exploit advisory      verify or run, one target at a time
  [5]  Export report         HTML, JSON, Markdown, CSV
  [6]  Scan again            same target, different depth
  [0]  Main menu
```

Every option carries a count, so the useful path is visible rather than
something you work out. `--no-wizard` goes straight to the menu, and
`--no-preflight` skips the readiness check.

---

## 2z. The individual commands

```bash
vision doctor          # what's installed, what's missing, what you can do
vision setup           # install the missing toolchain
vision index           # build the Metasploit module index
```

`doctor` is read-only and safe to run anytime. `setup` shows every install
command and asks before running any of them.

---

## 2a. The commands

| Command | Does | Touches the network? |
|---|---|---|
| `vision doctor` | Audit the 55-tool toolchain | No |
| `vision setup` | Install missing tools | Downloads only |
| `vision index` | Parse local MSF modules into a cache | No |
| `vision run` | Automated discovery to advisory | Yes — scanning only |
| `vision advise` | Map findings to modules, ranked | No |
| `vision exploit` | Interactive verify or run | Only on explicit selection |

---

## 2b. `vision doctor`

Audits 55 tools across discovery, enumeration, vulnerability scanning,
exploitation, credentials, pivoting, and traffic analysis. Reports per-tool
presence and version, then translates that into capabilities:

```
▸ Capabilities
  ✓ Port and service discovery
  ✗ SMB / Active Directory enumeration (needs netexec, smbmap)
  ✗ Safe verification via check() (needs metasploit)
```

Capabilities matter more than a raw checklist — "you can't verify findings"
is more actionable than "msfconsole missing".

---

## 2c. `vision setup`

```bash
vision setup --need core        # just the essentials (nmap, nuclei, msf, impacket)
vision setup --need standard    # everything a normal engagement needs (default)
vision setup --need optional    # all 55 tools
vision setup --only nuclei kerbrute
vision setup --dry-run          # print the commands, install nothing
```

Picks a package manager per tool: apt on Debian/Kali (signed, maintained),
go for ProjectDiscovery tooling (the distro packages lag by months), pipx for
Python tools, gem for evil-winrm, brew on macOS. Tools with no package
(ligolo-ng, windapsearch, Nessus) are listed with their download URL rather
than silently skipped.

sudo is prefixed only when you're not already root and sudo exists.

---

## 2d. `vision run` — the automated pipeline

```bash
vision run --scope 192.168.56.0/24 --rfc1918-only
```

Runs six stages in order, each skipped gracefully if its tool is absent:

**Phase 1 — Reconnaissance:** host discovery (ICMP + TCP probes)

**Phase 2 — Service Enumeration:** TCP port and version scan, a supplementary
scan of high-value ports outside nmap's top-1000, banner rules, and a targeted
UDP scan (53, 67, 69, 123, 137, 161, 500, 623, 1434, 1900, 5353)

nmap's top-1000 does not include Redis (6379), Memcached (11211), MongoDB
(27017) or several other high-value services, so a second short scan covers
them. Without it `datastore-exposure` could not fire in the default profile.
`--aggressive` scans all 65535 ports and skips the supplementary pass.

The UDP scan is a fixed short list rather than a top-N sweep, because a full
`-sU` waits out ICMP rate limiting on every closed port and can take hours. It
needs root; without it the stage skips and SNMP falls back to probing every live
host. Without UDP discovery the `ike-vpn` stage cannot fire at all, since it
keys on UDP 500.

**Phase 3 — Deep Enumeration:** SMB shares, RPC users, SNMP communities, NFS
exports, LDAP anonymous bind, IKE aggressive mode, unauthenticated datastores

**Phase 4 — Web Assessment:** security headers, server disclosure, directory
listing, dangerous HTTP methods, exposed paths, TLS certificate validity

**Phase 5 — Vulnerability Assessment:** TLS posture, Exploit-DB correlation,
nuclei templates, deep TLS, nmap vuln scripts

Four stages need no external tool at all — `banner-analysis`,
`web-assessment`, `web-exposed-paths`, `tls-certificate`, and
`datastore-exposure` are pure Python, so a box with only nmap installed still
produces real findings.

Then correlates everything into deduplicated findings and prints the exploit
advisory. **Scanning is automated; exploitation is not.** `run` never fires an
exploit — it ends with a ranked candidate list and tells you the `vision
exploit` command to verify them.

| Flag | Meaning |
|---|---|
| `--aggressive` | All 65535 ports instead of top 1000 |
| `--resume` | Continue an interrupted run (state saved after every stage) |
| `--skip STAGE...` | Skip named stages |
| `-o DIR` | Output directory (default `./vision-run`) |

State is written after every stage, so a scan that dies in hour three resumes
rather than restarting.

---

## 3. `vision index`

Builds the offline module index. Run once after install, and again after
`msfupdate`.

```bash
vision index
vision index --msf-path /opt/metasploit-framework/embedded/framework/modules
```

```
Building Metasploit module index...
  modules indexed : 2847
  with CVE refs   : 1893
  with check()    : 612
  destructive     : 341
  cached to       : ~/.vision/msf_index.json
```

Takes ~10s on a full tree. Everything after this is instant — shelling out to
`msfconsole -x search` costs 20s per lookup and is unusable in a loop.

**Options**

| Flag | Default | Meaning |
|---|---|---|
| `--cache PATH` | `~/.vision/msf_index.json` | Where to write the index |
| `--msf-path DIR...` | auto-detect | Module tree(s) to parse |

Auto-detected paths: `/usr/share/metasploit-framework/modules`,
`/opt/metasploit-framework/embedded/framework/modules`, `~/.msf4/modules`.

---

## 4. Findings input format

Both `advise` and `exploit` read a JSON file:

```json
{
  "services": [
    {"ip": "10.10.0.55", "port": 3306, "proto": "tcp",
     "name": "mysql", "product": "MySQL", "version": "5.5.28", "source": "nmap"}
  ],
  "findings": [
    {"ip": "10.10.0.55", "port": 3306, "proto": "tcp",
     "title": "MySQL authentication bypass",
     "severity": "critical", "confidence": "firm",
     "cves": ["CVE-2012-2122"], "source": "nmap"}
  ]
}
```

**Finding fields**

| Field | Required | Values |
|---|---|---|
| `ip` | yes | IPv4/IPv6 address |
| `title` | yes | Short description |
| `severity` | no | `info` `low` `medium` `high` `critical` |
| `confidence` | no | `tentative` `firm` `confirmed` |
| `port`, `proto` | no | int, `tcp`/`udp` |
| `cves` | no | `["CVE-2012-2122"]` — the primary join key |
| `cvss` | no | float; auto-derives severity if not given |
| `source` | no | which tool produced it |

`services` is optional but improves matching — findings with no CVE fall back to
product-name matching against the service banner.

Until the parser layer lands, generate this from an nmap scan:

```bash
nmap -sV -oX scan.xml 10.10.0.0/24
python3 vision/tools/nmap2findings.py scan.xml > run.json
```

---

## 5. `vision advise`

Read-only. Shows what's exploitable, ranked.

```bash
vision advise --findings run.json --scope 10.10.0.0/24
```

```
2847 modules indexed | scope: allow=['10.10.0.0/24']
7 candidates across 3 hosts (4 verifiable, 2 locked)

  #  SEV      RANK      SAFETY       TARGET             MODULE
--------------------------------------------------------------------------------
  1  critical Excellent verify-only  10.10.0.55:3306    exploit/multi/mysql/mysql_authbypass_hashdump ✓
  2  critical Great     verify-only  10.10.0.55:21      exploit/unix/ftp/vsftpd_234_backdoor ✓
  3  critical Average   destructive  10.10.0.60:445     exploit/windows/smb/ms17_010_eternalblue 🔒
--------------------------------------------------------------------------------
  ✓ = supports check() — verifiable without exploiting
  🔒 = locked, needs --allow-destructive
```

**Options**

| Flag | Default | Meaning |
|---|---|---|
| `--findings FILE` | required | Input JSON |
| `--scope CIDR...` | required | Engagement boundary |
| `--exclude CIDR...` | — | Denies; always beat allows |
| `--scope-file FILE` | — | One entry per line, `#` comments |
| `--rfc1918-only` | off | Hard refuse any public address |
| `--min-rank N` | 2 | Drop modules below this MSF rank (0–6) |
| `--per-finding N` | 5 | Cap candidates per finding |
| `--hide-destructive` | off | Omit DoS modules entirely |
| `--json` | off | Machine-readable output |
| `--no-color` | off | Plain text |

---

## 6. `vision exploit`

The interactive picker. **Nothing fires without an explicit selection.**

```bash
vision exploit --findings run.json --scope 10.10.0.0/24 --operator omkar
```

```
  [number] select   [c N] check only   [s N] show command   [q] quit
vision>
```

| Input | Action |
|---|---|
| `1` | Run candidate 1 with `--default-action` (default: `check`) |
| `c 1` | Verify only — runs MSF's `check`, no payload |
| `s 1` | Print full details + copy-pasteable msfconsole one-liner |
| `q` | Quit |

**Confirmation.** Before anything runs you get:

```
==============================================================
ABOUT TO RUN: EXPLOIT
==============================================================
  module     exploit/multi/mysql/mysql_authbypass_hashdump
  rank       Excellent (6/6)
  target     10.10.0.55:3306
  matched    cve:CVE-2012-2122
  safety     verify-only
  check()    yes — can verify without exploiting
--------------------------------------------------------------
Operator: omkar
Scope:    allow=['10.10.0.0/24']
==============================================================
Type the target IP (10.10.0.55) to proceed, anything else aborts:
```

You type the **IP**, not `y`. Muscle-memory `y` is how the wrong box gets hit.

**Check verdicts**

| Verdict | Meaning |
|---|---|
| `vulnerable` | Confirmed. Finding upgraded to `confirmed` confidence. |
| `likely-vulnerable` | Version/behaviour match, not proven |
| `detected-unconfirmed` | Service reachable, exploitability unknown |
| `not-vulnerable` | Target reports patched |
| `inconclusive` / `error` | Check couldn't run |

**Options**

| Flag | Default | Meaning |
|---|---|---|
| `--operator NAME` | `$USER` | Recorded in audit log |
| `--audit PATH` | `./vision-audit.jsonl` | Append-only log |
| `--default-action` | `check` | What a bare number does |
| `--allow-destructive` | off | Unlock DoS/destructive `exploit` |
| `--dry-run` | off | Print resource script, run nothing |
| `--timeout N` | 300 | Per-module seconds |
| `--verbose` | off | Dump msfconsole output |

---

## 7. Safety model

Enforced in code, verified by tests:

1. **No autonomous firing.** Nothing runs as a side effect of scanning or
   reporting.
2. **No batch mode.** One module, one target, one confirmation. There is no
   `exploit_all()` and adding one is out of scope for this tool.
3. **Scope re-validated at fire time.** A finding loaded from a file is not a
   trusted source of IPs.
4. **`check` before `exploit`.** Verifiable modules rank highest. For most
   engagements a confirmed `check` is the deliverable — you don't need a shell
   to write the finding up.
5. **Destructive modules visible but locked.** Hiding MS17-010 would leave you
   blind; instead it's shown with 🔒 and `exploit` requires
   `--allow-destructive`. `check` on them stays allowed — verification doesn't
   deliver a payload.
6. **Audit log.** Every planned and executed action: operator, timestamp,
   target, module, verdict.

```bash
jq -c '{iso,operator,event,module,target,verdict}' vision-audit.jsonl
```

---

## 8. Typical engagement flow

```bash
# 0. once
vision index

# 1. scan
sudo nmap -sV -sC -oX scan.xml -iL scope.txt
nuclei -l hosts.txt -json -o nuclei.jsonl

# 2. normalize (parser layer — see repo status)
python3 vision/tools/nmap2findings.py scan.xml > run.json

# 3. triage, read-only
vision advise --findings run.json --scope-file scope.txt

# 4. verify — safe, no payloads
vision exploit --findings run.json --scope-file scope.txt \
  --operator omkar --default-action check

# 5. exploit only what needs proving, one at a time
vision exploit --findings run.json --scope-file scope.txt \
  --operator omkar --default-action exploit
```

---

## 7b. Run log and evidence

Every scan writes `run.jsonl` to its output directory: one JSON object per
command executed, with the exact argv, exit code, duration and stderr.

```bash
vision run --scope 192.168.56.0/24 --rfc1918-only --debug   # print commands live
jq -c 'select(.returncode != 0)' vision-run/run.jsonl        # what failed
jq -r 'select(.kind=="command") | .command' vision-run/run.jsonl
```

This exists for two reasons that only matter on a real engagement:

**Diagnosis.** When a stage produces nothing, `reason` alone doesn't say
whether the command was wrong, the tool errored, or it timed out. The run log
has the argv and the stderr. Failed commands are also printed at the end of a
run rather than left in the file.

**Defensibility.** Raw tool output is saved under `evidence/<stage>/`, each file
headed with the stage, target, command and timestamp. Six weeks after delivery,
"smbmap said the share was writable" is much weaker than the smbmap output.
Disable with `--no-evidence`.

**Credentials are redacted before anything is written.** `-p`, `-c`,
`--password`, `--token` and their inline forms are replaced in both the log and
the evidence headers. Empty values are kept, because `-u '' -p ''` is a null
session and hiding it would misrepresent what ran. Log and evidence files are
0600, the evidence directory 0700.

---

## 7e. Scan intensity

Depth and intensity are separate questions. Depth is *which stages run*;
intensity is *how hard each one pushes*. Conflating them hides the trade-off.

| Intensity | Ports | Rate | Probes | Use when |
| :-- | :-- | :-- | :-- | :-- |
| **Stealth** | top 200 | 100 pkt/s | intensity 2 | Detection is in scope, or the target is fragile |
| **Normal** | top 1000 + extras | 1000 pkt/s | intensity 7 | Default for most engagements |
| **Aggressive** | all 65535 | 5000 pkt/s | intensity 9 | Maximum findings, with written authorisation |

```bash
vision run --scope 10.0.0.0/24 --intensity aggressive
vision run --scope 10.0.0.0/24 --intensity aggressive --yes   # scripted
```

Each profile states its impacts before running, itemised rather than
summarised. Aggressive declares three serious ones and requires you to type
`AGGRESSIVE` — a yes/no is muscle memory, and this profile has real
consequences:

- **It can crash fragile targets.** Printers, IP cameras, VoIP handsets,
  building-management controllers and industrial equipment are known to hang or
  reboot under intensive service probing. This is the most common way an
  assessment causes an outage, and it happens during *scanning*, not
  exploitation.
- **It will trigger alerting.** Without prior notice it is handled as a live
  intrusion.
- **It needs authorisation that explicitly covers intensive scanning**, and a
  named client contact reachable while it runs.

Stealth discloses its own cost too: it misses services outside the top 200
ports, so a clean result there is not evidence of a clean network.

**Intensity never relaxes a safety gate.** Turning coverage up does not turn
confirmation off — the exploit launcher has no knowledge of scan profiles at
all, and a test asserts it.

No profile uses `-T5`. It shortens timeouts enough that a loaded host reports
open ports as closed, and a faster scan that misses a service is not a better
scan.

---

## 7c. Triage

Open any finding and record a judgement on it:

```
▸ Record a decision?  currently: new
  [1]  Confirmed             real — keep it in the report
  [2]  False positive        excluded, with the reason disclosed
  [3]  Accepted risk         real, but the client has accepted it
  [4]  Clear                 back to not reviewed
```

Excluding a finding **requires a reason**. An unexplained exclusion is the first
thing a reviewer questions, and the analyst will not remember it six weeks
later.

Excluded findings are **disclosed, never dropped**. They appear in an
"Excluded findings" appendix in the report with the decision and the reason, so
the judgement can be checked rather than taken on trust — a report that silently
omits findings is indistinguishable from a scan that missed them.

Decisions are keyed on host, port and CVE, so they survive a rescan: something
marked false-positive on Monday is still marked on Friday even though the scan
ran again.

---

## 7d. Hosts, filtering and resume

**Hosts view** gathers everything about one machine — services, findings and
attack paths — in one place. Findings arrive grouped by stage, but remediation
happens per machine.

**Filter** the findings list by severity, host, triage state, or any text:

```
  [f] filter → critical
  [f] filter → 192.168.56.101
  [f] filter → false-positive
```

**Session resume.** Quitting used to discard everything, including the triage
decisions that took longest to make. On start, Vision offers to reload the last
run from the output directory:

```
▸ Previous session found  ./vision-run/state.json
  scope        192.168.56.0/24
  scanned      2h ago
  findings     13
  triaged      4 decision(s) recorded

  Reload it? [Y/n]
```

---

## 7n. Running tools by hand

Option **8** in the results menu. Pick any installed tool, get the playbook
commands for it as a starting point, edit, and run — without leaving Vision.

```
▸ Run a tool   47 installed · scope-checked, logged, output saved as evidence
  #   TOOL        PHASE          PURPOSE
  12  enum4linux-ng  enumeration  Full SMB/AD enumeration

  starting points from the playbook:
    1  Full enumeration
       enum4linux-ng -A 192.168.56.101

  $ enum4linux-ng -A 192.168.56.101 -u guest
```

What this buys over a second terminal: the target is scope-checked before it
runs, the command lands in the **same run log** as every automated stage, output
is written to `evidence/manual/`, and you can record a finding from it straight
away with the output already filled in. An assessment where half the work
happened in an untracked terminal is one you cannot reconstruct six weeks later.

**Commands are argv, never a shell line.** `;`, `|`, backticks and `$(...)` are
refused with an explanation. That is not distrust of the operator — a command
built from a playbook template plus a hostname plus a pasted share name has
several places for a metacharacter to arrive unnoticed, and a scan tool that can
be turned into a shell by a share called `; rm -rf /` is a bad tool. Use a shell
for pipelines.

Unknown binaries are refused too, with `allow_unknown_tool` for deliberate use.

---

## 7o. Targets: exactly what you ask for

**A single IP scans one address.** `192.168.56.101` becomes `192.168.56.101/32`
and nothing else is touched. The scan plan states the exact count before
anything runs:

```
  targets      1 address   nothing outside this is touched
```

**Target files** work anywhere a scope does:

```bash
vision run --targets engagement-hosts.txt --rfc1918-only
```

or in the console, at the target prompt: `file /path/to/targets.txt`

```
# engagement targets — SOW-2026-014
192.168.56.101      # web server
192.168.56.102
192.168.56.110-115
192.168.56.200, 192.168.56.201
```

Comments, blank lines, ranges and comma or space separators are all handled. A
bad line is **reported with its line number and skipped**, not fatal — a typo on
line 40 of a 200-host list should not cost you the other 199. Public addresses
in the file are flagged rather than silently ignored, because loading them and
then scanning nothing reads as a broken scan rather than a refused one.

---

## 7m. Engagement details and the executive summary

Option **6** in the main menu. Client, assessment name, assessor, authorisation
reference and contact. Dates stamp themselves from the run rather than being
typed twice.

Without these the HTML is a scan output with good typography. A client receives
a *document*, and its first page is read by someone who will never reach the
findings table.

**The executive summary.** Vision drafts one from what it actually found —
counts, the worst issues by name, whether findings chain into attack paths, and
how much of the toolchain ran:

```
The assessment examined 6 live hosts and identified 23 network services.
17 assessment stages ran.

13 findings were recorded, of which 9 are rated high or critical. The most
severe issues are rated critical.

Principal issues: Redis exposed without authentication; SMB shares
accessible without authentication.

Coverage note: 4 stages did not run, 2 of them because the required tooling
was unavailable (nuclei, testssl.sh). A finding count is only meaningful
alongside what was examined to produce it.
```

It is deliberately factual and slightly dry, and it is **labelled as a draft** in
the report. An auto-written risk narrative that reads as polished prose invites
someone to ship it unread.

Write your own with option 6 → *Executive summary*, and the draft disappears
entirely. Your words always win.

**Coverage is stated, never implied.** A summary reporting four findings without
mentioning that eleven stages never ran is technically true and materially
misleading.

---

## 7l. Authenticated assessment

```bash
vision run --scope 10.0.0.0/24 --user svc_scan --domain CORP
#   password (not echoed, never written)>
```

Or **Credentials** in the console menu. Four stages then run that anonymous
scanning cannot reach:

| Stage | Finds |
| :-- | :-- |
| `auth-admin-sprawl` | Every host where the account is local admin — usually the most surprising finding on an internal network |
| `auth-share-access` | What an ordinary logged-in user can actually read and write |
| `auth-password-policy` | The real minimum length and lockout threshold |
| `auth-kerberoast` | Service accounts whose tickets are crackable offline |

**A credential never reaches disk.** Not the state file, the run log, the
evidence directory or the report. There is no `--password` flag, because a
password in argv is visible in `ps` and shell history. Closing Vision forgets
them, which is the right behaviour for something the client lent you.

All four stages are **read-only**. Finding out where an account has admin rights
is not the same as using it — executing on a host stays behind the exploitation
gate.

---

## 7s. When no exploit module exists — critical findings are still flagged

A brand-new CVE with no Metasploit module yet used to produce the exact same
message as "nothing here is exploitable": `no exploit modules matched these
findings`. Those are completely different situations for an operator, and
the tool treated them identically.

Now, if nothing matches, Vision checks whether any critical or high finding
went unmatched and says so:

```
! no exploit module exists yet for 1 critical finding — this does not
  mean it is safe, it means Metasploit has no automated module for it
    [critical] 10.10.0.5:8443 Brand new appliance RCE
      verify these by hand — the manual playbook (option 8) has commands
      for exactly this situation
```

A genuinely quiet result (only low-severity findings, or nothing worth
investigating) still gets the plain `no exploit modules matched` message,
unchanged.

---

## 7u. The HUD

The console is themed as an arc-reactor heads-up display, and the colours carry
meaning rather than being decoration:

| Colour | Means |
| :-- | :-- |
| **Arc cyan** | live, in progress, structural chrome |
| **Armour gold** | what you must read — headings, callsigns, targets |
| **Crimson** | danger only: critical findings and blocked actions |
| **Green** | nominal — a step that completed cleanly |

Crimson is deliberately reserved. If it is used for ordinary errors it stops
meaning "stop and look", which is the one job it has.

```
╭─◈ PROBE  [3/6]  Deep Enumeration
│   shares, directories, datastores
╰──────────────────────────────────────────────────────────
  ▸ [1/4] smb-enumeration
```

Everything degrades to clean text when piped to a file, and `NO_COLOR` is
honoured — the theme never gets in the way of `vision run > log.txt`.

**The report is not themed.** It stays light, printable and professional,
because it goes to a client rather than sitting in your terminal.

---

## 7t. Live tool output during every scan

Every one of the 32 stages streams its tool's output as it is produced, rather
than staying silent until the tool exits:

```
  ⠹ port-scan: Discovered open port 445/tcp on 192.168.88.128      42s
  ⠼ port-scan: Completed SYN Stealth Scan at 14:22, 8.31s elapsed   50s
  ⠦ nuclei: [ssl-dns-names] [info] 192.168.88.128:443              71s
```

This is the `nmap -v` behaviour applied across the whole toolchain. All nmap
stages now pass `-v`, and the long ones add `--stats-every` so they report
periodic completion estimates.

**Why it matters more than it sounds:** without it, a nine-minute scan and a
hung scan are indistinguishable — both show a spinner and a climbing number.
With it, the difference is obvious at a glance.

The spinner label is *replaced* rather than scrolled, because a verbose tool
emits thousands of lines and printing them all would bury the findings the
scan is actually for. The complete output is still written to the run log
either way.

---

## 7r. Live exploit progress — what is actually happening

Before this, the exploit spinner showed a static label and an elapsed-seconds
counter — `msf exploit -> 10.0.0.5 1056s`, with only the number moving. A
genuinely slow module and a hung one looked identical, which is exactly what
cost an operator 17 minutes on a real Kali box: the run had actually finished
and was sitting at an unanswered confirmation prompt, but the counter kept
climbing regardless.

msfconsole announces what it's doing as it goes — connecting, sending the
exploit, sending the payload stage, opening a session. Vision now reads that
output line by line as it's printed, not all at once when the process exits,
and updates the spinner to show it:

```
  ⠹ msf exploit -> 10.0.0.5: sending exploit         12s
  ⠼ msf exploit -> 10.0.0.5: sending payload stage    14s
  ⠦ msf exploit -> 10.0.0.5: session opened            15s
```

This required switching from a single blocking call to reading the process's
output through a poll loop, while keeping the same process-group timeout kill
that already existed — a slow module now looks like progress, and a genuinely
stuck one still gets killed on schedule rather than hanging indefinitely.

---

## 7q. Proof of impact

When an exploit opens a session, Vision captures what was actually obtained:

```
  ╭─ ACCESS OBTAINED ─────────────────────────────────
  │ session      command shell #1
  │ identity     root
  │ host         metasploitable
  │ privilege    privileged
  ╰───────────────────────────────────────────────────
      identity captured with read-only commands; session closed afterwards
```

It then records a **confirmed, critical** finding with the transcript as
evidence, and writes the full session output to `evidence/exploit/`.

This is the difference between three report sentences:

| | |
| :-- | :-- |
| *"vsftpd 2.3.4 is vulnerable to CVE-2011-2523"* | a version string |
| *"the check reported the target as vulnerable"* | a tool's opinion |
| *"root shell obtained; uid=0(root) captured 14:22"* | **a fact** |

**What runs in the session:** `id`, `whoami`, `hostname`, `uname -a`,
`getuid`, `sysinfo`. That is the minimum needed to prove impact and the maximum
that can run without judgement about the client's environment. Nothing reads
user data, dumps credentials, moves laterally or persists — those are operator
decisions made with the engagement terms in hand, and the manual playbook holds
them.

**The session is closed afterwards.** Leaving shells open on a client's estate
after a test is how an assessment becomes an incident.

An unprivileged session is recorded as `high`, not `critical` — the report says
what was obtained, not what might have been.

---

## 7j2. Batch verification bugs found on a real target

A live run exposed three bugs in the batching added last round:

- **The timeout never fired.** `subprocess.run(timeout=)` kills only the
  direct child process; msfconsole's children inherit the output pipe and keep
  it open, so `communicate()` blocked forever. A 30-minute cap ran for 5.7
  hours. Fixed by running the whole tree in its own process group and killing
  the group on timeout — partial output is kept rather than discarded.
- **The same module was queued repeatedly.** A vulners scan produces one
  finding per CVE, and 8 CVEs on one port queued the identical check 8 times.
  Deduplication now happens on the module, host and port — the actual unit of
  work — before the per-finding cap is applied.
- **Exploits matched services they don't target.** The no-CVE fallback
  searched a module's description, and WordPress/Pandora FMS exploits both
  mention MySQL in prose, so they matched a bare MySQL service on 3306. The
  fallback now matches only the module's name and path.

---

## 7j. Why verification used to be slow

msfconsole takes 20–40 seconds to boot. Vision used to spawn it once per
candidate, so verifying fifteen findings cost ten minutes of framework startup
before a single packet moved — slow enough that people skipped verification,
and a verification step people skip is worthless.

`[v]` in the exploit menu now runs every check in **one session**:

```
  [v] verify all 15 in one pass   [c N] verify one   [x N] exploit
```

**Batching applies to `check` and to nothing else.** A check asks a service
whether it is vulnerable and delivers no payload — that is exactly why it can be
batched, and exactly why exploitation cannot. Every target is still
scope-validated individually before the session opens, every result is audited
separately, and `exploit` remains one module, one target, one typed
confirmation. There is no `exploit_many`, and a test asserts it.

---

## 7k. Tool coverage

Vision registers 55 tools. They now fall into two groups, and every one has a
route:

- **28 stages** execute tools directly — nmap, masscan, fping, arp-scan,
  nbtscan, netexec, enum4linux-ng, smbmap, smbclient, rpcclient, snmpwalk,
  showmount, ldapsearch, ike-scan, kerbrute, sslscan, sslyze, testssl.sh,
  nuclei, searchsploit and more.
- **The playbook** covers the rest, organised by situation rather than service:
  pivoting, offline cracking, AD enumeration, credential capture, traffic
  analysis, payload generation.

The split is not arbitrary. chisel, proxychains, evil-winrm, hashcat and
responder need a foothold, credentials, or a human deciding what to pivot
where. Wrapping them in an automated stage would produce a stage that always
skips — which looks like coverage and delivers none.

---

## 7g. Scan narration

Every command is shown as it runs, each stage says what it's attempting, and a
progress bar tracks the whole assessment:

```
  [2/17] port-scan
        identifying open TCP ports and fingerprinting the service on each
    $ nmap -sV -n -Pn -sC --top-ports=1000 -T4 --min-rate 1000 …   1.3s
    $ nmap -sV -n -Pn -p 989,2375,2376,5984,6379,6380,7474,9042 …   0.3s
  ✓ 4 services, 2 findings  1.5s  (+2 from supplementary ports)
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  35%  7/28 stages · 1m 36s elapsed · ~2m 58s left
```

A tool that hides what it runs cannot be audited by the person responsible for
the engagement — and reading the actual nmap invocation is how an analyst learns
what the tool is doing. Credentials are redacted in this display exactly as they
are in the run log.

The remaining-time estimate is a linear projection from completed stages, marked
`~` because stages differ wildly in cost. It answers "wait or get coffee", not
more.

---

## 7h. Manual testing playbook

Option **7** in the results menu. Per service and per finding, the commands a
competent analyst would run next by hand — ready to paste, each with the reason
it matters, intrusive ones flagged ⚠.

Vision never runs them. They are printed as text, and credential-attack
suggestions ship commented out so they cannot land in a shell buffer ready to
fire.

---

## 7i. Recording manual findings

Option **8** in the results menu. Guided entry for anything you found by hand:
target, port, title, severity, confidence, multi-line evidence, remediation and
CVEs.

Manual findings are **permanently marked as manual** — the report shows
*"recorded manually"* with the analyst's name. A reviewer asks different
questions of a tool finding than of a human one, so hiding the difference would
make the report harder to check.

They deduplicate against scan results using the same fingerprint the stages use,
so recording something the scan already found does not create a second copy. And
scope applies: an engagement boundary that stops the scanner but not the
keyboard is not a boundary.

---

## 7r. How long will this take?

The scan plan states it before you commit:

```
  intensity    normal
  time         14 min–42 min for 1 host   estimate, not a guarantee
      nuclei is roughly 38% of that (~12 min) — skip it with --skip nuclei
```

Rough guide, normal intensity, all stages:

| Hosts | Stealth | Normal | Aggressive |
| :-- | :-- | :-- | :-- |
| 1 | 42 min – 2.1 hr | **14 – 42 min** | 31 min – 1.5 hr |
| 10 | 71 min – 3.6 hr | **24 – 71 min** | 52 min – 2.6 hr |
| 254 (/24) | 22 – 68 hr | **7.6 – 22.7 hr** | 16 – 50 hr |

These are calibrated against a measured Metasploitable run — 32 stages, one
host, 22 open ports, **49.7 minutes** — and host parallelism is modelled, so a
/24 is nowhere near 254× a single host.

**The expensive stages are named so you can skip them.** In the reference run
`nuclei` alone was 31.7 minutes of 49.7, and `nmap-vuln-scripts` another 7.0:

```bash
vision run --scope 10.0.0.0/24 --skip nuclei tls-deep nmap-vuln-scripts
```

Roughly halves it.

**Exploitation is separate and unpredictable.** A batched `check` of ~20
modules is one msfconsole boot plus a few seconds per module — typically
**2–5 minutes**. A single `exploit` is seconds once the session opens. The
variance is msfconsole's startup (20–40s) and whichever module is slowest, so
Vision caps the batch at 15 minutes and kills the process group if it overruns.

---

## 7p. Coverage — did we look everywhere?

Option **6** in the results menu, and a section in the HTML report.

A finding count answers *"what did you find"*. It says nothing about whether
every service was examined, and the second question is the one a client is
really asking.

```
▸ Coverage  93% of services assessed · 2 not covered by any stage · 1 timed out
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  93%  28/30 services

  ! 2 service(s) no stage covers
    36346/nlockmgr   no stage covers this service
    60969/status     no stage covers this service
```

Three outcomes are distinguished, because they look identical in a findings
list and only one of them is a clean result:

- **the stage ran and found nothing** — a real result
- **the stage never ran** (tool missing) — a gap
- **no stage covers this service at all** — a gap

---

## 7f. Remediation plan

A findings list is ordered for the assessor. A remediation plan is ordered for
whoever has to fix it, and those are different orderings.

```
▸ Remediation plan  13 finding(s) reduce to 6 action(s)
  #  WORST     HOSTS  FIXES  ACTION
  1  critical  1      1      Set requirepass and bind Redis to localhost.
  2  high      3      3      Restrict Telnet to trusted networks or disable it.
  3  medium    3      3      Enforce SMB signing to prevent relay attacks.

  one change, several hosts
    3 hosts   Restrict Telnet to trusted networks or disable it.
    3 hosts   Enforce SMB signing to prevent relay attacks.
```

The unit of work is the **action**, not the finding. "Enforce SMB signing" is
one change that closes seven findings across three hosts; listing it seven
times makes it look like seven jobs.

**Severity dominates the ordering, breadth orders within a tier.** An earlier
version ranked purely on summed severity weight, which put three Telnet
findings above an unauthenticated Redis instance — no assessor would hand a
client a plan that ranks a critical below a set of highs. The "one change fixes
twelve hosts" view is still there as *quick wins*, where it reads as what it is
rather than being smuggled into the priority order.

Actions resting only on `tentative` findings are flagged, so a change window
isn't spent on something unverified.

**Effort is not estimated.** Vision cannot know whether a host is a spare VM or
a production controller with a six-week change process, and a made-up estimate
would be treated as real and then be wrong.

The same plan leads the HTML report, before the findings detail — that is the
reading order for someone scheduling the work: what to change, then why.

---

## 8a. Attack paths

```bash
vision paths --findings run.json
```

Findings arrive as a flat list; chains explain what they mean together.

```
1. CRITICAL  Unauthenticated SYSTEM via MS17-010 on 10.0.0.6
     outcome    SYSTEM-level code execution without credentials
     chain      MS17-010 present
     confidence confirmed

3. HIGH  NTLM relay to authenticated SMB access on 10.0.0.5
     outcome    Authenticated access to file shares, often code execution
     chain      SMB signing not enforced → Name-resolution poisoning surface
     confidence confirmed
```

Ten chains ship by default, covering NTLM relay, MS17-010, unauthenticated
Redis to RCE, exposed secrets to database, writable shares, SNMP to device
credentials, user enumeration to spraying, cleartext credential capture, NFS
to SSH keys, and Tomcat WAR deployment.

Two rules keep this honest. A chain is only as confident as its weakest
*load-bearing* step, and a chain built entirely on tentative evidence is capped
at medium — it describes a possibility, not a finding. Steps that merely
establish context (a database port being open) are marked non-load-bearing so
they cannot drag a well-evidenced chain down.

Attack paths lead the HTML report, because breaking one step breaks the chain.

---

## 8d. Control frameworks

```bash
vision frameworks --findings run.json
```

Maps findings to MITRE ATT&CK, CIS Controls v8, PCI DSS v4.0 and OWASP Top 10
(2021), and shows how many findings relate to each control. The same table
appears in the HTML report.

**This is indicative, not an audit.** A mapping says "this finding is evidence
relevant to that control" — which is what an assessment report needs. It is not
a compliance determination: that requires defined scope, consideration of
compensating controls, and a qualified assessor. Both the CLI and the report
say so explicitly, because a tool that implies a PCI pass it cannot justify
creates real liability for whoever signs the report.

Mappings are deliberately narrow. Where a finding could arguably touch five
controls, it lists the one or two an assessor would actually cite — an
over-broad mapping makes everything look like it breaches everything, which is
worse than no mapping.

Framework revisions change. Check the current release before quoting a control
ID in a deliverable.

---

## 8e. Custom rules

Team-specific checks live in rule files rather than Python, so they can be
written per engagement:

```bash
vision paths --findings run.json --rules ./client-rules.json
```

Files in `~/.vision/rules/` load automatically. JSON always works; YAML works
when PyYAML is installed.

```json
{
  "chains": [{
    "id": "acme.legacy-appliance",
    "name": "Legacy appliance with management interface exposed",
    "outcome": "Administrative access to an unsupported device",
    "severity": "high",
    "steps": [
      {"label": "Unsupported firmware", "title": "Outdated .*ApplianceOS"},
      {"label": "Management reachable", "port": [443, 8443],
       "load_bearing": false}
    ],
    "narrative": "The appliance runs firmware the vendor no longer patches.",
    "remediation": "Replace the appliance or isolate its management interface."
  }]
}
```

A step matches on `title` (regex), `cve`, `port`, or any combination — multiple
criteria in one step are alternatives. Mark context steps `load_bearing: false`
so they don't constrain the chain's confidence.

A custom rule sharing an id with a built-in replaces it, so a team can correct
a shipped rule without forking.

**Rule files are data, never code.** There is no `eval`, no import hook and no
callable field: a bad rule can produce a wrong finding but cannot execute
anything. Malformed rules are reported individually and the rest of the file
still loads, so one typo doesn't silently disable a whole ruleset.

---

## 8c. Retests

```bash
vision diff baseline.json retest.json
vision diff baseline.json retest.json --all   # also list still-open findings
```

```
╭─ delta ──────────────╮
│ resolved     3       │
│ still open   1       │
│ new          1       │
│ worsened     1       │
│ remediation  60%     │
╰──────────────────────╯

  ! 1 new high/critical finding(s) since the baseline
```

Findings are matched on host, port and CVE — not on wording — so a re-rated or
reworded finding is recognised as the same issue rather than reported as one
fixed plus one new. New high and critical findings are called out next to the
remediation percentage, because a good rate means little if the retest surfaced
fresh criticals.

---

## 8b. Reports

Export from the console menu (`[6]`) or after any run.

| Format | Use |
|---|---|
| **HTML** | Client deliverable. Self-contained single file — no CDN, no JS, opens offline, prints straight to PDF. |
| JSON | Machine-readable, feeds `vision advise` and `vision exploit`. |
| Markdown | Quick internal review, pastes into tickets and wikis. |
| CSV | Findings table for spreadsheets and tracking. |

The HTML report contains:

- **Masthead** — scope, operator, timestamp, host and service counts
- **Posture bar** — severity distribution as one continuous rule
- **Findings by host** — hosts ordered by worst severity present
- **Findings** — grouped by severity, each with evidence, the tool that
  reported it, a confidence rating, CVE links, and remediation
- **Open services** — full port and version inventory
- **Methodology** — every stage attempted, including ones skipped for missing
  tooling and why

Two deliberate choices worth knowing about. Confidence is shown on every
finding rather than hidden: `tentative` means inferred from a banner and not
verified, and the summary says so in plain language — a report that overstates
certainty is worse than one with fewer findings. And informational findings
collapse behind a disclosure when there are more than six, so they don't bury
the results that need a decision.

Everything in the report is HTML-escaped. Findings carry service banners and
share names straight from the target, so an unescaped report would be stored
XSS against whoever reviews it.

---

## 9. Scope syntax

```
10.0.0.0/24              CIDR
10.0.0.5                 single host
10.0.0.1-10.0.0.50       full range
10.0.0.1-50              shorthand range
2001:db8::/32            IPv6
```

Scope file:

```
# engagement ACME-2026-Q3
10.10.0.0/24
192.168.50.0/24
```

Hostnames are **rejected** by the scope check by design — resolve them first, so
DNS can't be used to slip a target past the boundary.

---

## 9b. Parser reliability

Tool output parsing lives in `vision/core/parsers.py` as pure functions, covered
by 108 tests against realistic output from several tool versions.

This matters because the failure is silent: a parser that stops matching after
an `apt upgrade` returns nothing, the stage reports zero findings, and the
report says the network is clean. Parsers match on structure rather than column
spacing for that reason.

If you hit output a parser mishandles, the raw text is already saved under
`evidence/<stage>/` — that file is exactly what a fix needs.

---

## 10. Troubleshooting

| Symptom | Cause |
|---|---|
| `No Metasploit module tree found` | Pass `--msf-path` explicitly |
| `msfconsole not found on PATH` | Only needed for real runs; `--dry-run` works without it |
| `BLOCKED: ... outside engagement scope` | Target not in `--scope` — working as intended |
| `BLOCKED: ... classed DESTRUCTIVE` | Needs `--allow-destructive` + client sign-off |
| `has no check method` | Use the bare number to run it for real |
| No candidates | Findings have no CVEs and no matching `services` entry |
| Stale results after `msfupdate` | Re-run `vision index` |
