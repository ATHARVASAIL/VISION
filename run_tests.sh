#!/usr/bin/env bash
# Run the full Vision test suite. Exit non-zero if anything fails.
set -uo pipefail
cd "$(dirname "$0")"
GRN=$'\033[32m'; RED=$'\033[31m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; OFF=$'\033[0m'
SUITES=(test_advisor test_enrich test_security test_accuracy test_edge test_report test_web test_correlate test_frameworks test_runlog test_parsers test_triage test_profiles test_remediation test_playbook test_manual test_batch test_credentials test_engagement test_manualrun test_realworld test_estimate test_selfcheck test_toolchain_coverage test_console_safety test_cvss test_integration)
# Run last: it audits the docs against the totals every other suite produced.
DOC_SUITE=test_docs
total=0; failed=0
printf '%s\n' "${BOLD}Vision test suite${OFF}"
for s in "${SUITES[@]}"; do
  printf '  %-20s ' "$s"
  if out=$(python3 "tests/$s.py" 2>&1); then
    n=$(grep -c '^PASS' <<<"$out" || true)
    total=$((total + n))
    printf '%sPASS%s  %s tests\n' "$GRN" "$OFF" "$n"
  else
    failed=$((failed + 1))
    printf '%sFAIL%s\n' "$RED" "$OFF"
    grep '^FAIL' <<<"$out" | sed 's/^/      /'
  fi
done
# The doc audit needs the final tally, so it runs after everything else.
printf '  %-20s ' "$DOC_SUITE"
doc_checks=0
if out=$(VISION_TEST_TOTAL=$total python3 "tests/$DOC_SUITE.py" 2>&1); then
  doc_checks=$(grep -c '^PASS' <<<"$out" || true)
  printf '%sPASS%s  %s checks\n' "$GRN" "$OFF" "$doc_checks"
else
  failed=$((failed + 1))
  printf '%sFAIL%s\n' "$RED" "$OFF"
  grep '^FAIL' <<<"$out" | sed 's/^/      /'
fi

echo
if [[ $failed -eq 0 ]]; then
  # Report the test total separately from the doc checks: the docs quote the
  # test count, and folding the audit into it would make the README contradict
  # the runner that validates the README.
  printf '%s%s tests passed across %s suites%s' "$GRN" "$total" "${#SUITES[@]}" "$OFF"
  printf '%s   ·   %s documentation checks%s\n' "$DIM" "$doc_checks" "$OFF"
else
  printf '%s%s suite(s) failed%s\n' "$RED" "$failed" "$OFF"
fi
exit $failed
