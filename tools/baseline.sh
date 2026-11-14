#!/bin/bash
# =============================================================================
#  baseline.sh -- record a clean state, then report every change from it
#
#  The only detection method that does not depend on recognising the malware.
#  Take a baseline AFTER remediation, once the host is believed clean, then run
#  `compare` daily. Anything new, modified, removed or re-permissioned in the
#  webroots or at a persistence point is reported, whatever it contains.
#
#  It will not find what is already present when the baseline is taken. That
#  is what webshell-triage.sh is for; this is what comes after it.
#
#  Like the scanner it never touches a webroot. It writes only to its state
#  directory (root-only) and to a private temp directory removed on exit.
#
#  Usage:
#    bash tools/baseline.sh take    [--root DIR]... [--report FILE] [--state DIR]
#    bash tools/baseline.sh compare [--state DIR] [--quiet]
#
#    --root DIR     a webroot to watch (repeatable)
#    --report FILE  take the webroots from a webshell-triage.sh report instead;
#                   default when no --root is given: the newest /root/triage-*.txt
#    --state DIR    where the baseline lives (default /root/ir-baseline)
#    --quiet        compare: print nothing when nothing changed (for cron)
#
#  compare exit codes:  0 no change   1 changes found   2 could not compare
#
#  Daily, mailed only when something changed (cron mails any output):
#    0 3 * * * bash /root/webserver-ir-toolkit/tools/baseline.sh compare --quiet
#
#  What is watched besides the webroots -- the places a backdoor comes back
#  from after a cleanup: crontabs (system, per-user, DirectAdmin), systemd
#  units, /etc/ld.so.preload, sudoers, profile.d, rc.local, passwd/group and
#  SSH authorized_keys. Override the list with IR_BASELINE_EXTRA (space-separated).
# =============================================================================

set -u

# Same production courtesy as the scanner: hashing every webroot is I/O heavy.
if [ "${IR_NICED:-0}" != "1" ] && [ -f "$0" ] \
   && command -v nice >/dev/null 2>&1 && command -v ionice >/dev/null 2>&1; then
  IR_NICED=1 exec nice -n 19 ionice -c3 bash "$0" "$@"
fi

CMD="${1:-}"; [ $# -gt 0 ] && shift
ROOTS=(); REPORT=""; STATE="/root/ir-baseline"; QUIET=0
while [ $# -gt 0 ]; do
  case "$1" in
    --root)   ROOTS+=("${2:-}"); shift 2 ;;
    --report) REPORT="${2:-}"; shift 2 ;;
    --state)  STATE="${2:-}"; shift 2 ;;
    --quiet)  QUIET=1; shift ;;
    -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1"; exit 2 ;;
  esac
done
case "$CMD" in take|compare) ;; *) sed -n '2,36p' "$0"; exit 2 ;; esac

EXTRA_DEFAULT="/etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly
  /etc/cron.monthly /var/spool/cron /usr/local/directadmin/data/users /etc/systemd/system
  /etc/ld.so.preload /etc/sudoers /etc/sudoers.d /etc/profile.d /etc/rc.local /etc/passwd
  /etc/group /root/.ssh/authorized_keys"
EXTRA="${IR_BASELINE_EXTRA-$EXTRA_DEFAULT}"

TMPD=$(mktemp -d) || exit 2
trap 'rm -rf "$TMPD"' EXIT
trap 'rm -rf "$TMPD"; exit 2' INT TERM HUP

# One line per file:  path<TAB>sha256<TAB>mode<TAB>owner:group
# Under directories named cache, tmp, logs or sessions only PHP-like files are
# recorded: those directories churn constantly, and PHP inside them is exactly
# what a reinfection looks like. One sha256sum per batch of files, not per file.
snapshot() {  # $1 = output file; reads targets (one per line) on stdin
  local out=$1
  : > "$TMPD/list"
  while IFS= read -r t; do
    if [ -d "$t" ]; then
      # Matched against the path BELOW the watched directory only. Matching
      # the full path silently dropped every non-PHP file of a webroot that
      # merely lives under a directory called tmp or cache -- the test suite
      # caught it, running under /tmp. -type f inside the group: pruning a
      # directory would hide the PHP files under cache/<sub>/.
      # Symlinks are recorded by their target: enabling a unit is nothing but
      # a new symlink under /etc/systemd/system/*.wants/.
      ( cd "$t" 2>/dev/null && find . -xdev \
          \( -type f -regex '\./\(.*/\)?\(cache\|tmp\|logs\|sessions\)/.*' \
             ! \( -name '*.php' -o -name '*.php[0-9]' -o -name '*.phtml' -o -name '*.phar' -o -name '*.inc' \) \) -prune \
          -o -type f -printf '%P\t%m\t%u:%g\t-\n' \
          -o -type l -printf '%P\t%m\t%u:%g\tlink:%l\n' 2>/dev/null ) \
        | awk -F'\t' -v t="${t%/}" 'BEGIN { OFS = "\t" } { $1 = t "/" $1; print }'
    elif [ -f "$t" ]; then
      stat -c $'%n\t%a\t%U:%G\t-' "$t" 2>/dev/null
    fi
  done | sort -u > "$TMPD/list"
  awk -F'\t' '$4 == "-" { print $1 }' "$TMPD/list" | xargs -d '\n' -r sha256sum 2>/dev/null \
    | sed 's/^\([0-9a-f]\{64\}\)  /\1\t/' > "$TMPD/sums"
  awk -F'\t' 'FILENAME == ARGV[1] { sum[$2] = $1; next }
              { s = ($4 != "-") ? $4 : (($1 in sum) ? sum[$1] : "unreadable")
                print $1 "\t" s "\t" $2 "\t" $3 }' \
    "$TMPD/sums" "$TMPD/list" > "$out"
}

targets() {  # the watched set: roots, then persistence points
  local r
  for r in ${ROOTS[@]+"${ROOTS[@]}"}; do printf '%s\n' "$r"; done
  for r in $EXTRA /home/*/.ssh/authorized_keys; do printf '%s\n' "$r"; done
}

if [ "$CMD" = "take" ]; then
  if [ "${#ROOTS[@]}" -eq 0 ]; then
    [ -z "$REPORT" ] && REPORT=$(ls -t /root/triage-*.txt 2>/dev/null | head -n 1)
    if [ -z "$REPORT" ] || [ ! -f "$REPORT" ]; then
      echo "no --root given and no scanner report to read webroots from -- nothing to watch"
      exit 2
    fi
    while IFS= read -r r; do
      r=${r#"${r%%[! ]*}"}; [ -n "$r" ] && [ -d "$r" ] && ROOTS+=("$r")
    done < <(sed -n '/^webroots to scan/,/^$/p' "$REPORT" | tail -n +2)
    [ "${#ROOTS[@]}" -eq 0 ] && { echo "the report lists no existing webroot: $REPORT"; exit 2; }
    echo "webroots taken from $REPORT"
  fi
  mkdir -p "$STATE" && chmod 700 "$STATE" || { echo "cannot create $STATE"; exit 2; }
  targets > "$STATE/targets"
  printf '%s\n' "${ROOTS[@]}" > "$STATE/roots"
  snapshot "$STATE/files.tsv" < "$STATE/targets"
  { echo "host=$(hostname 2>/dev/null)"; echo "taken=$(date '+%F %T %z')"
    echo "files=$(wc -l < "$STATE/files.tsv")"; } > "$STATE/meta"
  chmod 600 "$STATE"/*
  echo "baseline: $(wc -l < "$STATE/files.tsv") files under ${#ROOTS[@]} webroot(s) and the persistence points"
  echo "state:    $STATE"
  echo "sha256:   $(sha256sum "$STATE/files.tsv" | cut -c1-64)"
  echo "Record that hash somewhere off this host. Anyone who can rewrite $STATE can"
  echo "hide a change; the hash is how you would notice."
  exit 0
fi

# --- compare -------------------------------------------------------------------
[ -s "$STATE/files.tsv" ] && [ -s "$STATE/targets" ] && [ -f "$STATE/roots" ] \
  || { echo "no baseline in $STATE -- run: baseline.sh take"; exit 2; }
snapshot "$TMPD/now.tsv" < "$STATE/targets"
# A change is "hot" when it is PHP-like, an .htaccess/.user.ini, or outside every
# webroot -- i.e. at a persistence point. The roots come from the baseline itself.
awk -F'\t' -v php='\\.(php[0-9]?|phtml|phar|inc|suspected)$' '
  function inroot(p,  i) { for (i = 1; i <= nr; i++) if (index(p, R[i] "/") == 1) return 1; return 0 }
  function hot(p) { return (p ~ php) || (p ~ /(^|\/)(\.htaccess|\.user\.ini)$/) || !inroot(p) }
  function add(line, p) { if (hot(p)) H[++nh] = line; else O[++no] = line }
  FILENAME == ARGV[1] { if ($0 != "") R[++nr] = $0; next }
  FILENAME == ARGV[2] { bs[$1] = $2; bm[$1] = $3 " " $4; next }
  { seen[$1] = 1
    if (!($1 in bs))              add("NEW       " $1, $1)
    else if (bs[$1] != $2)        add("MODIFIED  " $1, $1)
    else if (bm[$1] != $3 " " $4) add("PERMS     " $1 "  " bm[$1] " -> " $3 " " $4, $1)
  }
  END {
    for (p in bs) if (!(p in seen)) add("REMOVED   " p, p)
    if (nh + no == 0) exit 0
    print "== changes to PHP, .htaccess/.user.ini and persistence points (" nh + 0 ") =="
    for (i = 1; i <= nh; i++) print "  " H[i]
    print "== other changes in the webroots (" no + 0 ") =="
    for (i = 1; i <= no && i <= 200; i++) print "  " O[i]
    if (no > 200) print "  ... " no - 200 " more"
    exit 1
  }' "$STATE/roots" "$STATE/files.tsv" "$TMPD/now.tsv" > "$TMPD/report"
RC=$?
if [ "$RC" = "0" ]; then
  [ "$QUIET" = "1" ] || echo "no change since the baseline of $(sed -n 's/^taken=//p' "$STATE/meta")"
  exit 0
fi
[ "$RC" = "1" ] || { echo "comparison failed"; exit 2; }
echo "CHANGES on $(hostname 2>/dev/null) since the baseline of $(sed -n 's/^taken=//p' "$STATE/meta")"
echo "baseline sha256: $(sha256sum "$STATE/files.tsv" | cut -c1-64)"
cat "$TMPD/report"
exit 1
