#!/bin/bash
# =============================================================================
#  run-and-annotate.sh -- run one test command and surface its verdict
#
#  Usage:  run-and-annotate.sh "<title>" <command> [args...]
#
#  The two test scripts end with a single verdict line (PASS / FAIL /
#  INCONCLUSIVE) and distinguish exit 1 from exit 2. A CI log buries both. This
#  wrapper prints the output unchanged, then repeats the verdict as a workflow
#  annotation, so the result is readable from the run summary without opening a
#  log -- and, on failure, carries the last lines of output with it.
#
#  The exit code of the command is passed through untouched. Exit 2
#  (INCONCLUSIVE) therefore fails the job, which is the point: a test that could
#  not run has proven nothing and must not show up green.
# =============================================================================

set -u

TITLE=$1; shift
OUT=$(mktemp) || exit 2
trap 'rm -f "$OUT"' EXIT INT TERM HUP

"$@" 2>&1 | tee "$OUT"
RC=${PIPESTATUS[0]}

# Annotation messages are single-line; %0A is how a newline is carried.
encode() { sed -e 's/%/%25/g' -e 's/\r//g' | awk '{ printf "%s%%0A", $0 }'; }

if [ "$RC" = "0" ]; then
  # The scanner-exit line rides along with the verdict on purpose. A scanner
  # that died in section 1 also leaves a tree byte-identical, so "PASS" is only
  # worth reading next to how many sections actually ran.
  VERDICT=$( { grep -E 'scanner exit:' "$OUT"; sed -n '/^PASS/,$p' "$OUT"; } | encode )
  echo "::notice title=$TITLE::${VERDICT:-exit 0}"
else
  echo "::error title=$TITLE (exit $RC)::$(tail -n 25 "$OUT" | encode)"
fi
exit "$RC"
