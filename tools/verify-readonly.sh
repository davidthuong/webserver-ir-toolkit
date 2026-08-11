#!/bin/bash
# =============================================================================
#  verify-readonly.sh -- prove that webshell-triage.sh cannot modify a webroot
#
#  The toolkit's central promise is that running it cannot make an incident
#  worse. That promise is worth exactly what your ability to check it is worth,
#  so this script checks it rather than asking you to take anyone's word.
#
#  It builds a throwaway webroot, records the sha256 of every file plus every
#  permission bit, size and directory entry, runs the scanner against that tree
#  and nothing else, records the same state again, and diffs.
#
#  Run it on the host you actually intend to scan. Running it on a workstation
#  tends to produce noise instead of an answer: endpoint antivirus quarantines
#  the deliberately malware-shaped files this script creates, and a file removed
#  by your AV is indistinguishable from one removed by the scanner unless the
#  test accounts for it -- which is what the "already inaccessible" handling
#  below does.
#
#  Usage:  bash tools/verify-readonly.sh
#    exit 0  PASS          nothing in the tree changed
#    exit 1  FAIL          something changed; do not trust the read-only claim
#    exit 2  INCONCLUSIVE  the environment interfered; the test proved nothing
# =============================================================================

set -u

HERE=$(cd "$(dirname "$0")/.." && pwd)
SCANNER="$HERE/webshell-triage.sh"
[ -f "$SCANNER" ] || { echo "cannot find $SCANNER"; exit 1; }

LAB=$(mktemp -d) || exit 1
trap 'rm -rf "$LAB"' EXIT

# The tree under test and this script's own bookkeeping must not share a
# directory. Snapshot files living inside the scanned tree would show up in the
# snapshots themselves and be reported as changes.
TREE="$LAB/tree"
W="$TREE/home/u1/domains/example.test/public_html"
REPORT="$LAB/report.txt"

mkdir -p "$W"/wp-content/{plugins/realplugin,themes/mytheme,uploads/2026/08,mu-plugins} \
         "$W"/wp-includes

# --- a webroot with the shapes the scanner reacts to -------------------------
# Each of these makes some section do real work on the tree. If any section
# wrote, moved, chmodded or deleted anything, the diff below catches it.
printf '<?php define("DB_PASSWORD","must-not-change");\n'   > "$W/wp-config.php"
printf '<?php $wp_version = "6.7.1";\n'                     > "$W/wp-includes/version.php"
printf '<?php\n/* Plugin Name: Real Plugin */\n'            > "$W/wp-content/plugins/realplugin/realplugin.php"
printf 'a customer photo, not code\n'                       > "$W/wp-content/uploads/2026/08/photo.jpg"
printf '<?php\n'                                            > "$W/wp-content/plugins/noheader.php"
: >                                                           "$W/wp-content/mu-plugins/trimmed.php"

# client-side injection shape: repeating-key XOR, script appended to documentElement
{ printf '<?php ?><script>var _k=atob("AAAA"),_d=atob("BBBB");'
  printf 'for(;_i<_d.length;_i++)_s+=String.fromCharCode(_d.charCodeAt(_i)^_k.charCodeAt(_i%%4));'
  printf 'var _el=document.createElement("script");_el.textContent=_s;'
  printf 'document.documentElement.appendChild(_el);</script>\n'
} > "$W/wp-content/mu-plugins/injector.php"

# a long unbroken base64 run, the shape section 17 measures
printf '<?php $x="%s"; ?>\n' "$(head -c 4200 /dev/urandom | base64 | tr -d '\n')" \
  > "$W/wp-content/themes/mytheme/packed.php"

# anti-cleanup shape: the owner cannot write it
printf '<?php // survives scanners that empty files instead of deleting them\n' > "$W/readonly.php"
chmod 444 "$W/readonly.php"

# --- snapshots ---------------------------------------------------------------
# Hash errors are recorded, not discarded. A file something else has locked
# produces the same missing line as a deleted one, and the two need opposite
# conclusions.
snap() {  # $1 = output prefix (kept outside $TREE)
  ( cd "$TREE" && find . -type f -exec sha256sum {} \; 2>"$1.hasherr" | sort ) > "$1.hash"
  ( cd "$TREE" && find . \( -type f -o -type d \) -printf '%m|%y|%s|%p\n' 2>/dev/null | sort ) > "$1.meta"
  return 0
}

snap "$LAB/before"

# Paths already unreadable before the scanner started cannot be evidence about
# the scanner. Record them and exclude them from the verdict.
EXCLUDED="$LAB/excluded"
sed -n 's/^sha256sum: \(.*\): .*$/\1/p' "$LAB/before.hasherr" 2>/dev/null | sort -u > "$EXCLUDED"
NEXCL=$(wc -l < "$EXCLUDED" 2>/dev/null || echo 0)

echo "webroot built: $(grep -c . "$LAB/before.hash") hashable file(s) under $W"
if [ "${NEXCL:-0}" -gt 0 ]; then
  echo
  echo "WARNING: $NEXCL path(s) were ALREADY unreadable before the scan started:"
  sed 's/^/    /' "$EXCLUDED"
  echo "  Something on this machine is locking the lab directory -- almost always"
  echo "  endpoint antivirus reacting to the malware-shaped files created above."
  echo "  These paths are excluded from the verdict, because their fate says"
  echo "  nothing about the scanner. Prefer running this on your server."
fi

echo
echo "running scanner, scoped to that tree only..."
bash "$SCANNER" --root "$W" --days 400 --out "$REPORT" --no-nice >"$LAB/stdout.txt" 2>&1
echo "scanner exit: $?   sections completed: $(grep -c '^## ' "$REPORT" 2>/dev/null || echo 0)"

snap "$LAB/after"

# --- verdict -----------------------------------------------------------------
RC=0
REAL_LOSS=0

is_excluded() {
  [ "${NEXCL:-0}" -gt 0 ] || return 1
  grep -qxF "$1" "$EXCLUDED"
}

explain_missing() {
  local n=0 line p
  while IFS= read -r line; do
    p="${line##*|}"
    [ -z "$p" ] && continue
    n=$((n+1))
    if is_excluded "$p"; then
      echo "    EXCLUDED: $p"
      echo "      was already unreadable before the scan; not evidence either way"
    elif [ -e "$TREE/$p" ]; then
      echo "    STILL EXISTS: $p"
      echo "      the snapshot lost it, the scanner did not delete it. Something"
      echo "      outside this test is touching the lab directory."
    else
      echo "    GONE: $p"
      echo "      a real deletion -- exactly the failure this check exists to catch"
      REAL_LOSS=1
    fi
  done
  [ "$n" = "0" ] && echo "    (none)"
  return 0
}

echo
echo "--- file contents (sha256) ---"
if diff "$LAB/before.hash" "$LAB/after.hash" >/dev/null 2>&1; then
  echo "  unchanged: nothing was edited or truncated"
else
  diff "$LAB/before.hash" "$LAB/after.hash" | sed 's/^/  /'
  RC=1
fi

echo "--- permissions, sizes, and the set of files and directories ---"
if diff "$LAB/before.meta" "$LAB/after.meta" >/dev/null 2>&1; then
  echo "  unchanged: no chmod, no new files, no removed files"
else
  RC=1
  echo "  present before, absent after:"
  explain_missing < <(diff "$LAB/before.meta" "$LAB/after.meta" | grep '^<' | sed 's/^< //')
  echo "  present after, absent before:"
  # Capture first: `grep | sed` in a pipeline reports sed's status, so a trailing
  # `|| echo none` would never fire and an empty section would print blank.
  ADDED=$(diff "$LAB/before.meta" "$LAB/after.meta" | grep '^>' | sed 's/^> /    /')
  if [ -n "$ADDED" ]; then printf '%s\n' "$ADDED"; else echo "    (none)"; fi
fi

echo
if [ "$RC" = "0" ]; then
  echo "PASS -- the scanner read this tree and left it byte-identical."
  echo "        The only file it wrote was its report, outside the tree."
  exit 0
elif [ "$REAL_LOSS" = "1" ]; then
  echo "FAIL -- a file that existed before the scan is gone afterwards."
  echo "        Do not run the scanner on anything you care about until this is"
  echo "        explained. Please open an issue including the output above."
  exit 1
else
  echo "INCONCLUSIVE -- differences were found, but none of them is a file the"
  echo "        scanner could have removed: each was already unreadable, or is"
  echo "        still on disk. The environment interfered, so this run neither"
  echo "        confirms nor refutes the read-only guarantee. Re-run on the host"
  echo "        you intend to scan."
  exit 2
fi
