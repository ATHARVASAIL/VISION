# tests/

Run everything with `./run_tests.sh` from the project root.

## The suites that matter most

| Suite | Why it exists |
| :-- | :-- |
| `test_realworld.py` | Runs against **real captured output** from a live Metasploitable host in `fixtures/`. Every bug it guards was invisible to synthetic tests. |
| `test_parsers.py` | Tool output parsing across version and formatting variation. A parser that silently stops matching reports a vulnerable network as clean. |
| `test_advisor.py` | Every exploit safety gate, plus regressions for the batch-verification bugs found on a real target |
| `test_credentials.py` | Writes a sentinel credential through a whole run, then greps every artefact for it |
| `test_enrich.py` | Asserts shared invariants across *all* stages — scope, concurrency, remediation. Catches bugs no per-stage test would. |
| `test_docs.py` | Recomputes every number in the docs from the code. The docs cannot silently go stale. |

## fixtures/

Real tool output, captured by Vision's own evidence directory during a live
engagement against Metasploitable 2. Fixtures written by hand match the parser
that was written alongside them; these do not.
