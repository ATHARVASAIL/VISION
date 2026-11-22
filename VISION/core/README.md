# core/ — the engine

## Scanning
| File | Role |
| :-- | :-- |
| `pipeline.py` | Stage registry, phase ordering, the run loop, `RunState`. **Start here.** |
| `enrich.py` | Per-host enumeration stages (SMB, RPC, SNMP, NFS, LDAP, IKE) |
| `web.py` | HTTP, TLS certificate and datastore stages |
| `extra.py` | Stages for tools added later (masscan, arp-scan, nbtscan, enum4linux, sslyze, kerbrute) |
| `authenticated.py` | Stages that only run when a credential is supplied |
| `parsers.py` | Pure functions turning tool output into data. **Most exposed to reality — most likely to break on a new tool version.** |

## Safety and correctness
| File | Role |
| :-- | :-- |
| `scope.py` | The engagement boundary. Enforced identically everywhere. |
| `safety.py` | Escaping, redaction, safe XML, 0600 writes, bounded iteration |
| `credentials.py` | In-memory only. A credential must never reach disk. |
| `runlog.py` | Every command executed, with argv/exit/stderr — credentials redacted |
| `version.py` | Numeric version comparison (string comparison got this wrong) |

## Operator-facing
| File | Role |
| :-- | :-- |
| `console.py` | The interactive menu — the primary interface |
| `ui.py` | Terminal rendering: colour, tables, spinners, progress |
| `doctor.py` | Toolchain audit and installation |
| `toolchain.py` | The registry of 55 tools and how to find/install each |
| `profiles.py` | Scan intensity (stealth/normal/aggressive) and its disclosed impacts |

## Analyst workflow
| File | Role |
| :-- | :-- |
| `triage.py` | Confirmed / false-positive / accepted-risk decisions |
| `manual.py` | Recording a finding discovered by hand |
| `manualrun.py` | Running a tool by hand, scope-checked and logged |
| `engagement.py` | Client, authority, dates, executive summary |
| `schema.py` | The `Service` and `Finding` shapes everything else speaks |
| `concurrency.py` | Bounded thread pools for per-host probing |
