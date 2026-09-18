# Security design

Vision parses data from hosts that may be hostile. Every service banner,
share name, and certificate field it handles is attacker-influenced by
definition. This documents what that means for the code.

## Threat model

| # | Vector | Mitigation | Tested |
|---|---|---|---|
| 1 | Argument injection — a banner becomes a `searchsploit` term | `safe_arg()` strips leading dashes and shell metacharacters; no `shell=True` anywhere | 13 tests |
| 2 | Terminal escape injection — banner rewrites the screen to forge output | `safe_display()` strips CSI/OSC escapes and bare CR | 7 tests |
| 3 | XML entity expansion (billion laughs) | `parse_xml_safely()` refuses DOCTYPE internal subsets and ENTITY declarations | 5 tests |
| 4 | Path traversal — share name becomes a filename | `safe_filename()` reduces to `[A-Za-z0-9._-]` | 8 tests |
| 5 | Sensitive artefacts world-readable | `secure_open()` / `harden_path()` force 0600 on every output | 7 tests |
| 6 | Module shadowing via `sys.path` | Replaced dynamic path insertion with package-relative imports | — |
| 7 | Unbounded subprocess spawning on a large scope | Per-stage host caps and `bounded()` | 5 tests |
| 8 | Stored XSS in the HTML report — banners rendered as markup | Every field escaped via `html.escape`; 10 payload classes tested | 12 tests |
| 9 | Attacker-controlled text interpolated into report URLs | CVE IDs validated against the NVD format before being linked | 8 tests |
| 10 | Code execution via a malicious rule file | Rule files are data only — no `eval`, no import hook, no callable field; patterns and file sizes bounded | 9 tests |
| 11 | Credentials persisted in logs and evidence | `redact()` strips secret flags and inline forms before any write; tool-aware so nmap port lists stay readable, unknown tools fail closed; log 0600, evidence dir 0700 | 31 tests |

## Notes on specific decisions

**No `shell=True`, anywhere.** Every subprocess call passes an argv list. This
removes command injection entirely, but *not* argument injection: a banner of
`--output /etc/cron.d/x` is still a valid flag to the child process even as a
single list element. `safe_arg()` exists for that residual case.

**DOCTYPE handling is deliberately narrow.** nmap emits a bare
`<!DOCTYPE nmaprun>`, so refusing every DOCTYPE would break the tool's primary
input. What enables billion-laughs is the *internal subset* — the `[ ... ]`
block that defines entities. That is refused; the bare declaration is allowed.

**Carriage returns are stripped from display, newlines are not.** A bare CR
rewinds the cursor to column 0, letting hostile tool output overwrite a line
already printed — including a scope warning or a finding count.

**0600 on everything.** The audit log names the operator, every target, and
every module fired. Scan artefacts contain the full network map. On a shared
jump box the default umask would make all of it world-readable. Files are
created with the restrictive mode via `os.open` rather than created-then-
chmod'd, so there is no window where they are readable.

**Credential attacks are absent from the automated path.** hydra, medusa,
ncrack and kerbrute are in the toolchain registry but no pipeline stage calls
them. Account lockout is a client-impacting decision that belongs to the
operator, not to a scan preset.

The datastore and web stages stay on the right side of that line: Redis `PING`,
Memcached `version`, MongoDB `isMaster` and an Elasticsearch health GET all
read state without sending a credential, so there is nothing to lock out. Path
checking is seven known-interesting URLs, not a wordlist — a long list turns an
assessment into an attack and floods the target's logs.

**The scanner defends itself against hostile responses.** Response bodies are
capped at 256 KB (an endpoint streaming gigabytes would otherwise exhaust the
scanning box), redirects are never followed (a 302 to another host would walk
the scanner straight out of scope), every socket has a timeout, and all
server-controlled text passes through `safe_display` before reaching a terminal
or report.

## Exploitation gates

Unchanged from the original design and enforced in code, not documentation:

1. No autonomous firing — nothing runs as a side effect of scanning
2. No batch mode — one module, one target, one confirmation
3. Scope re-validated at fire time, not inherited from imported data
4. `check` before `exploit` — verifiable modules rank highest
5. Destructive modules visible but locked behind `--allow-destructive`
6. Confirmation is typing the target IP, not `y`
7. Append-only 0600 audit log of every planned, executed, **and refused**
   action — a blocked attempt is the evidence the gates held, so it is logged
   before the exception propagates

## Running the tests

```bash
./run_tests.sh             # all 26 suites,  tests
```

| Suite | Tests | Covers |
|---|---|---|
| `test_advisor` | 158 | Advisory ranking, every exploit gate, batched verification, proof of impact, live phase streaming |
| `test_enrich` | 88 | Enumeration stages, output parsing, graceful skip |
| `test_security` | 49 | Injection, XXE, path traversal, terminal escapes, file permissions |
| `test_accuracy` | 66 | Version logic, concurrency, false-positive suppression |
| `test_edge` | 84 | Malformed input, corrupt state, resource limits, fuzz |
| `test_report` | 67 | Report escaping, completeness, print output, scale |
| `test_web` | 51 | Web/datastore detection, false positives, scanner self-defence |
| `test_correlate` | 93 | Attack-path chaining, confidence capping, retest diff |
| `test_frameworks` | 77 | Control mapping accuracy, rule-file validation and sandboxing |
| `test_runlog` | 87 | Credential redaction, evidence capture, thread-safe logging |
| `test_parsers` | 106 | Tool output parsing across version and formatting variation |
| `test_triage` | 50 | Analyst decisions, and that excluded findings are disclosed |
| `test_profiles` | 81 | Intensity escalation, impact disclosure, and that intensity never relaxes a gate |
| `test_remediation` | 48 | Action grouping, and that a critical never ranks below lesser findings |
| `test_playbook` | 52 | Manual playbook narration, service/finding matching |
| `test_manual` | 62 | Manually recorded findings, scope enforcement |
| `test_batch` | 71 | Batched exploit verification, one msfconsole boot instead of many |
| `test_credentials` | 59 | Credentials never reach disk, tool-aware redaction |
| `test_engagement` | 76 | Session resume, engagement metadata, exclusion audit trail |
| `test_manualrun` | 70 | Manual tool runner, output capture, evidence |
| `test_realworld` | 62 | Fixtures from a real captured Metasploitable engagement |
| `test_estimate` | 34 | Scan-duration estimation against measured real-run data |
| `test_selfcheck` | 20 | Vision's own claims audited against its own code |
| `test_toolchain_coverage` | 16 | Every registered tool resolves to an install plan or manual instructions |
| `test_console_safety` | 10 | Confirmation prompts cannot be buried inside a spinner; live phase streaming is wired |
| `test_cvss` | 75 | CVSS v3.1 vector parsing and base scoring against official reference vectors; malformed vectors rejected |
| `test_integration` | 48 | Full scan → report → advisory against a live target |
| `test_docs` | 53 | Documentation numbers, commands and links checked against the code |

## Validated against a real target

Vision was tested against a live Metasploitable 2 host. That run found four bugs
no synthetic test had caught, which is the argument for the `tests/fixtures/`
directory: fixtures I write are fixtures that match the parser I wrote.

| Bug | Impact |
| :-- | :-- |
| Worker threads lost the stage name | 10 commands logged as `unknown`. Masked in most stages because a single item runs inline; on any network large enough to fan out, it was every parallel stage. |
| `smbmap` timed out and the stage reported "ok, 0 findings" | A partial scan reading as a clean one — the most dangerous failure this tool has. |
| Classic `enum4linux` output parsed as nothing | Kali ships it alongside `enum4linux-ng` with entirely different output. A full null session was dumped and nothing was extracted. |
| One CVSS score applied to every CVE in a block | 148 criticals on one host. Corrected to 23 critical / 39 high / 73 medium / 12 low. |

Every one is now a regression test running against the captured real output.

## Parser reliability

The output parsers are this project's largest exposure to reality: everything
else is logic under our control, but these read text produced by other people's
tools, which reformat between releases.

The failure mode that matters is silent. A parser that stops matching after a
tool update returns nothing, the stage reports zero findings, and the report
says the network is clean. That is worse than crashing, because nobody
investigates a clean result.

Parsers therefore live in `core/parsers.py` as pure functions — text in,
structured data out — so they can be tested against realistic output without
spawning the tool. They match on structure and keywords rather than column
widths, and where output is ambiguous they return nothing rather than guessing:
a missed finding is a gap, an invented one destroys the report's credibility.

## Reporting

Vision is a security tool that can cause harm if misused or if it misbehaves.
If you find a flaw in the gates — a way to make it fire without confirmation,
scan outside scope, or execute attacker-controlled input — that is a serious
bug. Please report it rather than publishing a working bypass.
