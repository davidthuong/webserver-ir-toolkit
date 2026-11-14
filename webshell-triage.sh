#!/bin/bash
# =============================================================================
#  webshell-triage.sh  --  READ-ONLY triage for compromised web servers
#  Supports: DirectAdmin, Plesk, cPanel, plain nginx/apache (CentOS/Alma/Ubuntu)
#
#  This script NEVER deletes, moves, chmods or edits anything.
#  It only reads and writes one report file.
#
#  RUNNING THIS ON PRODUCTION
#  Safe to do, with one caveat that is about load, not about damage. Nothing in
#  the webroot is modified; the only file written is the report, under /root.
#  But the script reads every webroot on the host, so on a shared server the cost
#  is disk I/O and page-cache pressure -- enough to slow MySQL even though no
#  write ever happens. Mitigations already built in:
#    - re-execs itself under nice -n 19 / ionice -c3   (disable with --no-nice)
#    - candidate files are found with one grep pass per webroot, never a pipeline
#      per file, which on ~100 accounts would be hundreds of thousands of spawns
#    - the two slow or network-dependent checks are opt-in: --checksums, --http
#  Prefer off-peak hours for the first run. Scope it with --root while testing.
#
#  Usage:
#     sudo bash webshell-triage.sh                 # scan auto-detected webroots
#     sudo bash webshell-triage.sh --days 14       # "recent changes" window
#     sudo bash webshell-triage.sh --root /home/user1/domains/site.com/public_html
#                                                  # --root RESTRICTS to that path only
#     sudo bash webshell-triage.sh --out /root/report.txt
#     sudo bash webshell-triage.sh --checksums     # verify WP packages (slow, best check)
#     sudo bash webshell-triage.sh --http          # also fetch each site (section 17)
#     sudo bash webshell-triage.sh --no-nice       # do not lower priority
#
#  If you get "bad interpreter: ^M":  sed -i 's/\r$//' webshell-triage.sh
# =============================================================================

set -u

# --- production safety: run at the lowest CPU and I/O priority -----------------
# This script walks every webroot on the host. On a shared server with a hundred
# accounts that is a great deal of I/O, and the page-cache pressure alone is
# enough to slow MySQL noticeably even though nothing is being written.
# Re-exec under nice/ionice so that examining the sites cannot degrade them.
# Skip with --no-nice, or by setting IR_NICED=1.
case " $* " in *" --no-nice "*) IR_NICED=1 ;; esac
if [ "${IR_NICED:-0}" != "1" ] && [ -f "$0" ] \
   && command -v nice >/dev/null 2>&1 && command -v ionice >/dev/null 2>&1; then
  IR_NICED=1 exec nice -n 19 ionice -c3 bash "$0" "$@"
fi

DAYS=30
EXTRA_ROOTS=()
OUT=""
DO_HTTP=0            # --http: fetch each site over the network (off by default)
DO_SUMS=0            # --checksums: verify WordPress packages (slow, needs network)
MAXHITS=400          # cap lines per section so the report stays readable

while [ $# -gt 0 ]; do
  case "$1" in
    --days)  DAYS="$2"; shift 2 ;;
    --root)  EXTRA_ROOTS+=("$2"); shift 2 ;;
    --out)   OUT="$2"; shift 2 ;;
    --http)  DO_HTTP=1; shift ;;
    --checksums) DO_SUMS=1; shift ;;
    --no-nice)   shift ;;          # already handled before arg parsing
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1"; exit 1 ;;
  esac
done

HOST=$(hostname 2>/dev/null || echo unknown)
STAMP=$(date +%F-%H%M)
[ -z "$OUT" ] && OUT="/root/triage-${HOST}-${STAMP}.txt"
touch "$OUT" 2>/dev/null || OUT="./triage-${HOST}-${STAMP}.txt"

if [ "$(id -u)" != "0" ]; then
  echo "WARNING: not running as root. Many checks will be incomplete."
fi

# Artifacts worth aggregating are collected as the sections run, so the summary
# can answer the two questions every administrator asks first -- how many sites,
# and since when -- without a second pass over the disk.
# Everything the script writes lives under one directory, so it can be excluded
# from its own scans by a single path. Previously each temp file was a separate
# mktemp directly in /tmp, and since /tmp is itself scanned, the run reported its
# own working files as findings -- $SIG worst of all, because it holds the
# signature patterns and therefore matches the signature scan every single time.
WORK=$(mktemp -d) || exit 1
# EXIT alone is not enough: a shell killed by an untrapped SIGTERM or SIGINT
# exits without running its EXIT trap, verified by measurement rather than
# assumed. Since the documented advice for a heavy run is to interrupt it with
# Ctrl+C, the common case would have been the leaky one -- leaving a temp
# directory behind on each abort, on hosts that are often short of disk.
trap 'rm -rf "$WORK"' EXIT INT TERM HUP
ARTIFACTS="$WORK/artifacts"
: > "$ARTIFACTS"

# Pass-through filter: prints its input unchanged, and records any absolute path
# it sees. Handles bare paths and "some prefix /abs/path" lines alike.
art() {
  local l p
  while IFS= read -r l; do
    printf '%s\n' "$l"
    p=${l##* }
    case "$p" in /*) printf '%s\n' "$p" >> "$ARTIFACTS" ;; esac
  done
}

log()  { printf '%s\n' "$*" | tee -a "$OUT" ; }
sec()  { log ""; log "==============================================================="; \
         log "## $*"; log "==============================================================="; }
sub()  { log ""; log "-- $* --"; }
cap()  { head -n "$MAXHITS" | tee -a "$OUT" ; }
have() { command -v "$1" >/dev/null 2>&1 ; }

log "webshell-triage.sh  host=$HOST  date=$(date)  window=${DAYS}d"
log "report: $OUT"

# -----------------------------------------------------------------------------
sec "1. SYSTEM INFO"
log "uname:   $(uname -a 2>/dev/null)"
log "os:      $(cat /etc/redhat-release 2>/dev/null || cat /etc/os-release 2>/dev/null | grep PRETTY)"
log "uptime:  $(uptime 2>/dev/null)"
log "load:    $(cat /proc/loadavg 2>/dev/null)"
sub "logged in / recent logins"
# -w is not optional: without it `last` truncates the user column to 8 characters.
# A panel FTP account named webdeploy2024@example.com shows up as
# "webdeplo", which is not a user that exists -- and an investigation that starts
# by looking up a username that was never real wastes the time it takes to notice.
{ who; last -w -F -n 25; } 2>/dev/null | cap

# -----------------------------------------------------------------------------
sec "2. PANEL + WEBROOT DETECTION"
# Detect by EXECUTABLE, not by directory, and report every panel found.
#
# The previous version tested directories and chained them as
#   [ -d /usr/local/psa ] || [ -d /opt/psa ] && PANEL="Plesk"
# which parses as ( A || B ) && C, so a leftover /usr/local/psa from a panel
# that is no longer installed silently relabelled a DirectAdmin host as Plesk.
# That is not cosmetic: the per-user crontab check, the per-user PHP version
# check and several path choices branch on $PANEL, so a wrong label means those
# checks quietly do not run and the report looks clean because it never looked.
PANELS=()
PANEL="unknown"
[ -x /usr/local/directadmin/directadmin ] && PANELS+=("DirectAdmin")
if [ -x /usr/sbin/plesk ] || [ -x /usr/local/psa/bin/init_conf ] || [ -f /usr/local/psa/version ]; then
  PANELS+=("Plesk")
fi
[ -x /usr/local/cpanel/cpanel ] && PANELS+=("cPanel")
# CyberPanel: the Django app plus its own web daemon, lscpd. Both are required,
# so a CyberCP directory left behind by an uninstall does not count.
[ -d /usr/local/CyberCP ] && [ -x /usr/local/lscp/bin/lscpd ] && PANELS+=("CyberPanel")
# Virtualmin: the CLI plus the Webmin module that holds its domain records.
[ -x /usr/sbin/virtualmin ] && [ -d /etc/webmin/virtual-server ] && PANELS+=("Virtualmin")

case "${#PANELS[@]}" in
  0) log "panel detected: unknown -- no panel binary found" ;;
  1) PANEL="${PANELS[0]}"; log "panel detected: $PANEL" ;;
  *) PANEL="${PANELS[0]}"
     log "panel detected: ${PANELS[*]}  -- MORE THAN ONE. Using ${PANEL}."
     log "  Two panels cannot serve the same host, so one of these is leftover"
     log "  files from a previous install. Confirm which one is live before"
     log "  trusting any path in this report:  ss -ltnp | grep -E ':(2222|8443|2087)'"
     ;;
esac

sub "panel evidence on disk (so a wrong label above is debuggable)"
for p in /usr/local/directadmin/directadmin /usr/sbin/plesk /usr/local/psa/version \
         /usr/local/psa /opt/psa /usr/local/cpanel/cpanel /usr/local/cpanel \
         /usr/local/CyberCP /usr/local/lscp/bin/lscpd /usr/sbin/virtualmin /etc/webmin/virtual-server; do
  [ -e "$p" ] && log "  present: $p"
done

[ -x /usr/local/directadmin/directadmin ] && \
  log "DA version:    $(/usr/local/directadmin/directadmin v 2>/dev/null | head -1)"
have plesk && log "Plesk version: $(plesk version 2>/dev/null | head -3)"
[ -x /usr/local/cpanel/cpanel ] && \
  log "cPanel version: $(/usr/local/cpanel/cpanel -V 2>/dev/null | head -1)"
[ -f /usr/local/CyberCP/version.txt ] && \
  log "CyberPanel version: $(head -c 200 /usr/local/CyberCP/version.txt 2>/dev/null)"
for m in /usr/libexec/webmin/virtual-server/module.info /usr/share/webmin/virtual-server/module.info; do
  [ -f "$m" ] && { log "Virtualmin version: $(sed -n 's/^version=//p' "$m" | head -1)"; break; }
done

ROOTS=()
add_root() { [ -d "$1" ] && ROOTS+=("$1"); }

# --root RESTRICTS the scan to what you name; it does not add to auto-detection.
# Scoping a first run to one site is the main reason to pass it, and a --root that
# still walked every other webroot on the host would defeat that -- so when any
# --root is given, auto-detection is skipped entirely.
if [ "${#EXTRA_ROOTS[@]}" -gt 0 ]; then
  for d in "${EXTRA_ROOTS[@]}"; do add_root "$d"; done
  log "scope: --root given, auto-detection SKIPPED (${#ROOTS[@]} root(s) only)"
else
  # DirectAdmin / cPanel style
  for d in /home/*/domains/*/public_html /home/*/domains/*/private_html /home/*/public_html; do
    add_root "$d"
  done
  # Plesk style (httpdocs + subdomain dirs)
  for d in /var/www/vhosts/*/httpdocs /var/www/vhosts/*/*/httpdocs /var/www/vhosts/*/subdomains/*; do
    add_root "$d"
  done
  # cPanel keeps one file per domain under /var/cpanel/userdata/<user>/, each
  # naming its document root. An addon domain's root may sit beside public_html
  # rather than inside it, where the /home/*/public_html pattern cannot see it.
  # Checked on cPanel 138 with an addon domain created at /home/<user>/addon2.test.
  # It only ever adds directories that exist.
  if [ -d /var/cpanel/userdata ]; then
    while IFS= read -r d; do
      case "$d" in /*) add_root "$d" ;; esac
    done < <(grep -rhs '^documentroot:' /var/cpanel/userdata/ 2>/dev/null \
               | sed 's/^documentroot:[[:space:]]*//' | sort -u)
  fi
  # Plesk records every document root, and that record is the only complete
  # list: a subdomain or additional domain gets a directory named by whoever
  # created it (observed on Plesk 18: <subscription>/site1), which no glob can
  # anticipate. The globs above stay as the fallback for when the database
  # cannot be read -- which is exactly when a panel is most likely to be broken.
  if have plesk; then
    PLESK_ROOTS=$(plesk db -Ne "SELECT www_root FROM hosting" 2>/dev/null) || PLESK_ROOTS=""
    if [ -n "$PLESK_ROOTS" ]; then
      while IFS= read -r d; do
        case "$d" in /*) add_root "$d" ;; esac
      done <<< "$PLESK_ROOTS"
    else
      log "!! could not read document roots from the Plesk database; using path"
      log "!! patterns only. Subdomains outside httpdocs/ may NOT be scanned."
    fi
    add_root /var/www/vhosts/default/htdocs
  fi
  # generic. On a Plesk host /var/www is not a webroot but the parent of every
  # subscription plus the panel's own state (vhosts/system, vhosts/chroot):
  # scanning it reads each site twice and reports the panel's files as findings.
  if [ -d /var/www/vhosts ]; then
    add_root /var/www/html
  else
    for d in /var/www/html /var/www; do add_root "$d"; done
  fi
  for d in /usr/share/nginx/html /srv/www /opt/lampp/htdocs; do
    add_root "$d"
  done
fi

# De-duplicate, and drop any root that lies inside another root: the parent
# already covers it, and scanning both prints every finding twice and doubles
# the I/O. Sorted in the C locale so a parent always precedes its children.
mapfile -t ROOTS < <(printf '%s\n' "${ROOTS[@]:-}" | awk 'NF' | sed 's:/*$::' \
  | LC_ALL=C sort -u | awk '{ for (i = 1; i <= n; i++) if (index($0, keep[i] "/") == 1) next
                             keep[++n] = $0; print }')
if [ "${#ROOTS[@]}" -eq 0 ]; then
  log "!! no webroot found -- pass one with --root /path"
else
  log "webroots to scan (${#ROOTS[@]}):"
  printf '  %s\n' "${ROOTS[@]}" | tee -a "$OUT"
fi

# temp dirs are scanned too: droppers and miners live there
TMPDIRS=()
for d in /tmp /var/tmp /dev/shm /var/spool/cron /home/*/tmp; do
  [ -d "$d" ] && TMPDIRS+=("$d")
done

# -----------------------------------------------------------------------------
sec "2B. WEB SERVER + PHP SAPI"
# Which web server actually serves requests decides which mitigations exist.
# Getting this wrong is the single most common wasted-effort mistake in an IR:
# writing .htaccess rules on a server that never reads them.
WEBSRV="unknown"
HTACCESS="unknown"

if [ -d /usr/local/lsws ]; then
  lsver=$(/usr/local/lsws/bin/lshttpd -v 2>/dev/null | head -1)
  # Never guess the edition: Enterprise reads .htaccess, OpenLiteSpeed does not,
  # so a wrong guess here sends the responder down a mitigation path that does
  # nothing. When the version string is unreadable, say so instead.
  case "$lsver" in
    *[Oo]pen*)     WEBSRV="OpenLiteSpeed" ;;
    *Enterprise*)  WEBSRV="LiteSpeed Enterprise" ;;
    *)
      if [ -x /usr/local/lsws/bin/openlitespeed ]; then
        WEBSRV="OpenLiteSpeed"
      else
        WEBSRV="LiteSpeed (edition UNDETERMINED)"
      fi
      ;;
  esac
  log "litespeed version string: ${lsver:-<unreadable>}"
elif have nginx && { systemctl is-active nginx >/dev/null 2>&1 || pgrep -x nginx >/dev/null 2>&1; }; then
  WEBSRV="nginx"
  # nginx holding 80/443 does not mean nginx serves the site. Plesk's default
  # stack is nginx in front of Apache on 127.0.0.1:7080/7081, with every request
  # proxied through -- and there .htaccess IS read. Calling that host "nginx"
  # told the responder that the one mitigation that works does not.
  if pgrep -x apache2 >/dev/null 2>&1 || pgrep -x httpd >/dev/null 2>&1; then
    WEBSRV="nginx + Apache (proxy)"
  fi
elif have httpd || have apache2; then
  WEBSRV="Apache"
fi

# DirectAdmin records its choice explicitly -- authoritative when present
if [ -f /usr/local/directadmin/custombuild/options.conf ]; then
  sub "DirectAdmin CustomBuild web server / PHP mode"
  grep -E '^(webserver|php[0-9]_release|php[0-9]_mode|mod_security)=' \
    /usr/local/directadmin/custombuild/options.conf 2>/dev/null | cap
  dawebsrv=$(sed -n 's/^webserver=//p' /usr/local/directadmin/custombuild/options.conf 2>/dev/null | head -1)
  case "$dawebsrv" in
    openlitespeed) WEBSRV="OpenLiteSpeed" ;;
    litespeed)     WEBSRV="LiteSpeed Enterprise" ;;
    nginx)         WEBSRV="nginx" ;;
    nginx_apache)  WEBSRV="nginx + Apache (proxy)" ;;
    apache)        WEBSRV="Apache" ;;
  esac
fi

log ""
log "WEB SERVER: $WEBSRV"

sub "what is really listening on 80/443 (most authoritative check)"
if have ss; then ss -ltnp 2>/dev/null | grep -E ':(80|443)\b' | cap
elif have netstat; then netstat -ltnp 2>/dev/null | grep -E ':(80|443)\b' | cap
fi
sub "web service unit state"
for u in httpd apache2 nginx lsws litespeed lshttpd openlitespeed; do
  s=$(systemctl is-active "$u" 2>/dev/null) || true
  [ -n "${s:-}" ] && [ "$s" != "inactive" ] && [ "$s" != "unknown" ] && log "  $u = $s"
done

# --- .htaccess applicability: the part that trips people up ---
case "$WEBSRV" in
  Apache|"nginx + Apache (proxy)")   HTACCESS="yes (subject to AllowOverride)" ;;
  "LiteSpeed Enterprise")            HTACCESS="yes (read natively)" ;;
  OpenLiteSpeed)                     HTACCESS="NO" ;;
  nginx)                             HTACCESS="NO" ;;
  "LiteSpeed (edition UNDETERMINED)") HTACCESS="UNKNOWN -- verify before relying on it" ;;
esac
log ""
log "  .htaccess honored: $HTACCESS"
case "$HTACCESS" in
  UNKNOWN*)
    log "  !! Could not read the LiteSpeed version string, so the edition is unknown."
    log "  !! Enterprise reads .htaccess; OpenLiteSpeed ignores it. Do not assume."
    log "  !! Check manually:  /usr/local/lsws/bin/lshttpd -v"
    log "  !! Or test empirically -- drop a deny rule in a test dir and curl the file."
    ;;
  NO)
    log "  !! Rules in .htaccess are SILENTLY IGNORED on $WEBSRV."
    log "  !! <FilesMatch> / 'Require all denied' will NOT block anything."
    log "  !! Mitigate at the web server config layer, or via ModSecurity/WAF."
    log "  !! See docs: MITIGATION.md (section 16 covers client-side injection)"
    ;;
  yes*)
    if [ "$WEBSRV" = "nginx + Apache (proxy)" ]; then
      log "  nginx and Apache are both running. .htaccess is read only for requests"
      log "  nginx hands to Apache -- it may serve static files itself, and a site"
      log "  whose PHP is passed straight to PHP-FPM by nginx bypasses it entirely."
      log "  Test the rule with curl against a .php AND a static file before relying on it."
      # Plesk writes one nginx config per site, so the exceptions can be named.
      if [ -d /var/www/vhosts/system ]; then
        sub "Plesk sites where nginx does NOT hand PHP to Apache (.htaccess not consulted)"
        for f in /var/www/vhosts/system/*/conf/nginx.conf; do
          [ -f "$f" ] || continue
          site=${f#/var/www/vhosts/system/}; site=${site%%/*}
          if grep -q 'fastcgi_pass' "$f" 2>/dev/null; then
            log "  $site  -- PHP served by nginx via FPM"
          elif ! grep -qE 'proxy_pass[^;]*:708[01]' "$f" 2>/dev/null; then
            log "  $site  -- no proxy to Apache found (nginx-only hosting?)"
          fi
        done
      fi
    fi
    log "  AllowOverride must include AuthConfig or Limit for 'Require' to work;"
    log "  if it does not, Apache returns 500 for the whole directory."
    sub "AllowOverride in effect"
    grep -rhs 'AllowOverride' /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf \
      /etc/apache2/conf/httpd.conf \
      /usr/local/directadmin/data/users/*/httpd.conf /etc/httpd/conf.d/ \
      /etc/apache2/plesk.conf.d/server.conf /var/www/vhosts/system/*/conf/httpd.conf 2>/dev/null \
      | sort -u | head -10 | cap
    ;;
esac

# --- PHP binaries and whether a security extension covers each one ---
sub "PHP binaries found, and security-extension coverage per version"
# A site running a PHP version with no protective extension is unprotected even
# when the scanner dashboard reports "enabled".
phpfound=0
for p in /usr/local/lsws/lsphp*/bin/php /opt/plesk/php/*/bin/php \
         /usr/local/php*/bin/php /opt/cpanel/ea-php*/root/usr/bin/php \
         /opt/alt/php*/usr/bin/php /usr/bin/php /usr/local/bin/php; do
  [ -x "$p" ] || continue
  phpfound=$((phpfound+1))
  # Not every "php" is the CLI. On cPanel /usr/bin/php is a wrapper around
  # php-cgi, which has no -r: it prints its whole usage screen and exits 0, and
  # that screen went into the report as the version. Accept only something
  # shaped like a version, and fall back to the banner line of -v.
  ver=$("$p" -r 'echo PHP_VERSION;' 2>/dev/null | head -n 1)
  case "$ver" in
    [0-9]*.[0-9]*) ;;
    *) ver=$("$p" -v 2>/dev/null | sed -n '1s/^PHP \([0-9][0-9.]*\).*/\1/p') ;;
  esac
  ver=${ver:-?}
  ext=$("$p" -m 2>/dev/null | grep -iE 'imunify|snuffleupagus|suhosin' | tr '\n' ',' )
  if [ -n "$ext" ]; then
    log "  OK      $p  (php $ver)  ext: ${ext%,}"
  else
    log "  NO EXT  $p  (php $ver)  <-- no hardening extension loaded"
  fi
done
[ "$phpfound" = "0" ] && log "  no PHP binary found in the usual locations"

# --- which PHP version each site runs (to cross-reference the list above) ---
# Gated on the data, not the $PANEL label, for the same reason as the crontabs.
if [ -d /usr/local/directadmin/data/users ]; then
  sub "PHP version selected per DirectAdmin user"
  grep -h 'php[0-9]*_select\|php_ver' /usr/local/directadmin/data/users/*/user.conf 2>/dev/null \
    | sort | uniq -c | sort -rn | cap
fi

# -----------------------------------------------------------------------------
sec "3. SUSPICIOUS PROCESSES"
sub "top CPU consumers"
ps aux --sort=-%cpu 2>/dev/null | head -15 | cap
sub "known miner / bot process names"
ps aux 2>/dev/null | grep -aiE 'xmrig|kdevtmpfsi|kinsing|minerd|cpuminer|xmr-stak|nanominer|phpguard|masscan|zgrab|\.ICE-unix|dbused|sysupdate|networkservice|watchbog|redis-cli.*save|/tmp/[a-z0-9]{6,}( |$)' | grep -v ' grep ' | cap
sub "processes whose binary was deleted (classic in-memory malware)"
for p in /proc/[0-9]*; do
  exe=$(readlink "$p/exe" 2>/dev/null) || continue
  case "$exe" in *"(deleted)"*) log "PID ${p#/proc/}  $exe  cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)";; esac
done
sub "processes running from tmp / shm / webroot (very suspicious)"
for p in /proc/[0-9]*; do
  exe=$(readlink "$p/exe" 2>/dev/null) || continue
  case "$exe" in
    /tmp/*|/var/tmp/*|/dev/shm/*|/home/*/domains/*|/var/www/vhosts/*)
      log "PID ${p#/proc/}  $exe  cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)";;
  esac
done
sub "processes owned by web user running a shell (webshell command exec)"
ps -eo user,pid,ppid,etime,cmd 2>/dev/null \
  | grep -aE '^(apache|nginx|www-data|nobody|psaadm|psacln)' \
  | grep -aE '(/bin/(ba)?sh|python|perl|curl|wget|nc |ncat|socat)' | cap

# -----------------------------------------------------------------------------
sec "4. NETWORK"
sub "listening sockets"
if have ss; then ss -lntup 2>/dev/null | cap; else netstat -lntup 2>/dev/null | cap; fi
sub "established outbound connections (look for mining pools / odd ports)"
if have ss; then ss -ntp state established 2>/dev/null | cap; else netstat -ntp 2>/dev/null | grep ESTAB | cap; fi
sub "iptables / firewall rules added by attacker?"
{ iptables -S 2>/dev/null | tail -40; } | cap

# -----------------------------------------------------------------------------
sec "5. PERSISTENCE MECHANISMS"
sub "/etc/ld.so.preload (rootkit indicator -- should normally be absent/empty)"
if [ -e /etc/ld.so.preload ]; then
  log "!! EXISTS:"; cat /etc/ld.so.preload 2>/dev/null | tee -a "$OUT"
else
  log "ok - not present"
fi
log "LD_PRELOAD in env files:"
grep -risE 'LD_PRELOAD' /etc/environment /etc/profile /etc/profile.d /etc/sysconfig 2>/dev/null | cap

sub "user crontabs (/var/spool/cron)"
for f in /var/spool/cron/* /var/spool/cron/crontabs/*; do
  [ -f "$f" ] || continue
  log ">>> $f"
  grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | tee -a "$OUT"
done
sub "system cron dirs"
grep -rsE '(curl|wget|base64|python -c|perl -e|/tmp/|/dev/shm|\.onion|nc |bash -i)' \
  /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null | cap
# Gate these on the data actually being present, not on the $PANEL label. A
# mislabelled panel must not be able to skip a persistence check -- user crontabs
# are one of the first places a backdoor reappears from after a cleanup.
if [ -d /usr/local/directadmin/data/users ]; then
  sub "DirectAdmin per-user crontabs"
  grep -rsE '(curl|wget|base64|/tmp/|python|perl)' /usr/local/directadmin/data/users/*/crontab.conf 2>/dev/null | cap
  sub "DirectAdmin per-user crontabs -- full listing of any that are non-empty"
  for f in /usr/local/directadmin/data/users/*/crontab.conf; do
    [ -s "$f" ] || continue
    n=$(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null)
    [ "${n:-0}" -gt 0 ] && log "  $n line(s): $f"
  done
fi
if have plesk; then
  sub "Plesk scheduled tasks"
  # The column list is tried first and SELECT * second, and a failure of both
  # is printed rather than swallowed. This query named a column that does not
  # exist (`active`; it is `isActive` on Plesk 18), so with stderr discarded
  # the section was empty on every Plesk host -- which reads as "no tasks".
  if   pt=$(plesk db -Ne "SELECT id,sysUserLogin,isActive,type,command,arguments FROM ScheduledTasks" 2>&1); then :
  elif pt=$(plesk db -Ne "SELECT * FROM ScheduledTasks" 2>&1); then :
  else
    log "  !! could not read ScheduledTasks -- this check did NOT run. Plesk said:"
  fi
  [ -n "$pt" ] && printf '%s\n' "$pt" | cap
fi

sub "systemd units modified in last ${DAYS}d"
# /lib is a symlink to /usr/lib on modern systems, so listing both prints every
# unit twice and buries the one entry that matters in a screenful of duplicates.
SDDIRS=(/etc/systemd/system /root/.config/systemd)
[ -d /usr/lib/systemd/system ] && SDDIRS+=(/usr/lib/systemd/system)
[ -d /lib/systemd/system ] && [ ! -L /lib ] && [ ! -L /lib/systemd ] && SDDIRS+=(/lib/systemd/system)
find "${SDDIRS[@]}" 2>/dev/null \
  -type f -mtime -"$DAYS" | cap
sub "systemd units referencing tmp/curl/base64"
grep -rlsE '(/tmp/|/dev/shm|base64|curl |wget )' /etc/systemd/system 2>/dev/null | cap

sub "shell startup files modified in last ${DAYS}d"
find /root /home -maxdepth 3 \( -name '.bashrc' -o -name '.bash_profile' -o -name '.profile' \
     -o -name '.bash_login' -o -name '.zshrc' \) -mtime -"$DAYS" 2>/dev/null | cap
log "/etc/rc.local:"
[ -f /etc/rc.local ] && grep -vE '^[[:space:]]*(#|$)' /etc/rc.local | cap

sub "SSH authorized_keys (attacker backdoor keys)"
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys /var/www/vhosts/*/.ssh/authorized_keys; do
  [ -f "$f" ] || continue
  log ">>> $f  (mtime $(stat -c %y "$f" 2>/dev/null))"
  awk '{print "   " $1 " " substr($2,1,24) "... " $3}' "$f" 2>/dev/null | tee -a "$OUT"
done
sub "sshd_config overrides / new sudoers entries"
grep -sE '^(PermitRootLogin|PasswordAuthentication|Port|AuthorizedKeysFile)' /etc/ssh/sshd_config | cap
find /etc/sudoers.d -type f -mtime -"$DAYS" 2>/dev/null | cap
sub "accounts with UID 0 or shell access added recently"
awk -F: '$3==0 {print "UID0: " $0}' /etc/passwd | cap
find /etc/passwd /etc/shadow /etc/group -mtime -"$DAYS" \
  -printf 'MODIFIED in last '"$DAYS"'d: %TY-%Tm-%Td %p\n' 2>/dev/null | cap

sub "SUID binaries in unusual locations"
find /tmp /var/tmp /dev/shm /home /var/www -xdev -perm -4000 -type f 2>/dev/null | cap

# -----------------------------------------------------------------------------
sec "5B. IMUNIFY360 / MALDET STATE"
# If a commercial scanner is installed but the box still got shelled, the scanner
# is usually disabled, unlicensed, or in log-only mode. Check that before anything else.
if have imunify360-agent; then
  log "imunify360 installed"
  log "version:  $(imunify360-agent version 2>&1 | head -3)"
  sub "license"
  # `register --status` does not exist on agent 8.x; rstatus does, and its JSON
  # form says which product this actually is. That matters more than it sounds:
  # cPanel ships the free ImunifyAV under this same binary name.
  imunify360-agent rstatus 2>&1 | head -3 | cap
  IMLIC=$(imunify360-agent rstatus --json 2>/dev/null \
          | grep -oE '"(license_type|id|expiration)": *[^,}]*' | sort -u)
  [ -n "$IMLIC" ] && printf '%s\n' "$IMLIC" | sed 's/^/  /' | cap
  case "$IMLIC" in
    *[iI]munifyAV*)
      log "  !! This is ImunifyAV, not Imunify360. The free edition scans and reports;"
      log "  !! it has no Proactive Defense, no WAF and no automatic cleanup. A host"
      log "  !! that \"has Imunify\" in this form was never being protected in real time."
      ;;
  esac
  sub "malicious files Imunify already knows about"
  imunify360-agent malware malicious list --limit 100 2>&1 | head -60 | cap
  sub "on-demand scan history"
  imunify360-agent malware on-demand list 2>&1 | head -20 | cap
  sub "KEY SETTINGS -- these decide whether it actually blocks anything"
  # Agent 8.x prints the whole configuration as ONE line of JSON, so a line-based
  # grep with context returned all of it. Pull the settings out by name instead;
  # older agents print multi-line YAML and keep the original treatment.
  # The key is spelled PROACTIVE_DEFENCE. Matching DEFENSE finds nothing.
  IMCFG=$(imunify360-agent config show 2>/dev/null)
  case "$IMCFG" in
    "{"*)
      printf '%s\n' "$IMCFG" \
        | grep -oE '"(PROACTIVE_DEFENCE|WEBSHIELD|MALWARE_CLEANUP)": *\{[^}]*\}|"(enable_scan_inotify|default_action|ruleset)": *[^,}]*' \
        | sed 's/^/  /' | cap
      ;;
    *)
      printf '%s\n' "$IMCFG" \
        | grep -iE -A4 'PROACTIVE_DEFEN[CS]E|MALWARE_SCANNING|WEBSHIELD|enable_scan_inotify|mode|try_restore' \
        | head -60 | cap
      ;;
  esac
  log ""
  log "  -> PROACTIVE_DEFENCE mode must be 'KILL', not 'LOG' or 'DISABLED'"
  log "     (no \"mode\" shown at all means the feature is not in this licence)"
  log "  -> MALWARE_SCANNING enable_scan_inotify must be true (real-time on upload)"
  log "  -> WEBSHIELD enable must be true"
  sub "agent health"
  # Deliberately NOT `imunify360-agent doctor`: it collects a diagnostic bundle
  # and uploads it to the vendor, then prints a key to quote to support. A
  # read-only triage tool has no business sending host data anywhere, least of
  # all mid-incident. Service state answers the question this section asks.
  for u in imunify360 imunify360-agent imunify-antivirus imunify360-webshield; do
    s=$(systemctl is-active "$u" 2>/dev/null) || true
    [ -n "${s:-}" ] && [ "$s" != "unknown" ] && log "  $u = $s"
  done
else
  log "imunify360-agent NOT found in PATH"
fi
if have maldet; then
  sub "maldet recent detections"
  maldet --report list 2>&1 | head -20 | cap
fi

# -----------------------------------------------------------------------------
sec "6. WEBSHELL SIGNATURE SCAN"
SIG="$WORK/sig"
: > "$SIG" || exit 1
cat > "$SIG" <<'PATTERNS'
eval[[:space:]]*\([[:space:]]*(['"]\?>['"][[:space:]]*\.[[:space:]]*)?(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|pack|hex2bin|convert_uudecode|urldecode)
(eval|assert|create_function)[[:space:]]*\([^)]{0,120}\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)
(call_user_func|call_user_func_array|array_map|usort|register_tick_function)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)
(^|[^a-zA-Z0-9_>:$])(system|shell_exec|passthru|popen|proc_open|pcntl_exec|exec)[[:space:]]*\([[:space:]]*(\$_(GET|POST|REQUEST|COOKIE)|\$[a-zA-Z_]+[[:space:]]*\.)
\$_(GET|POST|REQUEST|COOKIE)[[:space:]]*\[[^]]*\][[:space:]]*\(
preg_replace[[:space:]]*\([[:space:]]*['"](/[^'"]*/|#[^'"]*#)[imsxuADSUXJ]*e[imsxuADSUXJ]*['"]
base64_decode[[:space:]]*\([[:space:]]*['"][A-Za-z0-9+/=]{120,}
(gzinflate|gzuncompress|str_rot13)[[:space:]]*\([[:space:]]*base64_decode[[:space:]]*\([[:space:]]*['"][A-Za-z0-9+/=]{40,}
\$\{[[:space:]]*['"]_(GET|POST|REQUEST|COOKIE)
\$GLOBALS[[:space:]]*\[[[:space:]]*['"][^'"]{1,20}['"][[:space:]]*\][[:space:]]*\(
(chr[[:space:]]*\([[:space:]]*(6[5-9]|[7-9][0-9]|1[01][0-9]|12[0-2])[[:space:]]*\)[[:space:]]*\.[[:space:]]*){4,}
FilesMan|WSOsetcookie|wso_|b374k|r57shell|c99shell|c100shell|IndoXploit|alfashell|ALFA_DATA|AnonymousFox|priv8|Marijuana|MiniShell|Zone-H([^a-zA-Z]|$)|zone-h\.org|Sh3ll|by\.?Orb|xIndoShell|GhostShell
(^|[^a-zA-Z0-9_>:$])(passthru|shell_exec|system)[[:space:]]*\([[:space:]]*['"](wget|curl|python|perl|chmod|nc)[[:space:]]
move_uploaded_file[[:space:]]*\([[:space:]]*\$_FILES[^;]*\$_(GET|POST|REQUEST)
php://input.*eval|eval.*php://input
(fsockopen|pfsockopen)[[:space:]]*\(.*(4444|1337|31337|9001)
(^|[^a-zA-Z0-9_>:$])mail[[:space:]]*\(.*\$_(GET|POST|REQUEST).*\$_(GET|POST|REQUEST)
str_replace[[:space:]]*\([^()]*\)[[:space:]]*\([[:space:]]*['"]?\$
@?(ini_set|error_reporting)[[:space:]]*\([[:space:]]*['"]?(display_errors|0)['"]?[[:space:]]*,?[[:space:]]*(0|false|off)?[[:space:]]*\)[[:space:]]*;[[:space:]]*@?set_time_limit
(=|echo|print|return|\()[[:space:]]*`[^`]*\$_(GET|POST|REQUEST|COOKIE)
move_uploaded_file[[:space:]]*\([^;]*\$_FILES[^;]*\[[[:space:]]*['"]name['"][[:space:]]*\][[:space:]]*\)
PATTERNS

SCAN_INC=(--include='*.php' --include='*.php[0-9]' --include='*.phtml' --include='*.pht'
          --include='*.phar' --include='*.phps' --include='*.inc' --include='*.module'
          --include='*.suspected' --include='*.cgi' --include='*.pl' --include='*.py'
          --include='*.htaccess' --include='*.txt')

CAND="$WORK/cand"
: > "$CAND"
if [ "${#ROOTS[@]}" -gt 0 ]; then
  grep -rlEf "$SIG" "${SCAN_INC[@]}" "${ROOTS[@]}" 2>/dev/null | sort -u > "$CAND"
fi
# --exclude-dir on the basename of $WORK keeps the run from matching its own
# pattern file; $OUT is filtered too in case the report was written under /tmp.
[ "${#TMPDIRS[@]}" -gt 0 ] && grep -rlEf "$SIG" "${TMPDIRS[@]}"   --exclude-dir="$(basename "$WORK")" 2>/dev/null   | grep -vF -e "$WORK" -e "$OUT" | sort -u >> "$CAND"
sort -u -o "$CAND" "$CAND"

NC=$(wc -l < "$CAND" | tr -d ' ')
log "files matching webshell signatures: $NC"
log ""
n=0
while IFS= read -r f; do
  [ -f "$f" ] || continue
  n=$((n+1)); [ "$n" -gt 150 ] && { log "... (truncated, see $CAND for full list)"; break; }
  log "### $f"
  log "    size=$(stat -c %s "$f" 2>/dev/null)  mtime=$(stat -c %y "$f" 2>/dev/null)  owner=$(stat -c %U:%G "$f" 2>/dev/null)  perm=$(stat -c %a "$f" 2>/dev/null)"
  grep -nEof "$SIG" "$f" 2>/dev/null | head -4 | sed 's/^/    hit: /' | cut -c1-200 | tee -a "$OUT"
done < "$CAND"
log ""
log "(full candidate list kept at: $CAND)"

# -----------------------------------------------------------------------------
sec "7. OBFUSCATION HEURISTICS"
sub "PHP files containing a single very long line (>1500 chars) -- packed shells"
if [ "${#ROOTS[@]}" -gt 0 ]; then
  find "${ROOTS[@]}" -type f -name '*.php' -size +1k 2>/dev/null \
    | while IFS= read -r f; do
        awk 'length($0)>1500 {print FILENAME; exit}' "$f" 2>/dev/null
      done | sort -u | cap
fi
sub "two-step variable functions: \$v = \$_POST[..] then \$v(..)  -- split-up shells"
# Neither half is suspicious alone, so require BOTH in the same file.
# This catches  $f=$_POST['a']; $f($_POST['b']);  which single-line patterns miss.
if [ "${#ROOTS[@]}" -gt 0 ]; then
  grep -rlE '\$[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*=[[:space:]]*(\$_(GET|POST|REQUEST|COOKIE)\[|base64_decode|gzinflate|str_rot13)' \
    --include='*.php' "${ROOTS[@]}" 2>/dev/null \
    | while IFS= read -r f; do
        grep -qE '\$[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\([[:space:]]*\$' "$f" 2>/dev/null && echo "$f"
      done | sort -u | cap
fi

sub "two-step command execution: \$v = ..\$_POST.. then system(\$v) or \`\$v\`  -- split-up shells"
# The largest group the signatures missed on a public corpus of 710 webshells
# and backdoors: the command arrives in one statement and runs in another --
#   $c = isset($_POST['c']) ? $_POST['c'] : '';   echo shell_exec($c);   `$c`
# Same principle as the check above: neither half alone, both in one file.
# Measured on that corpus and on ~33,700 clean PHP files (WordPress core with
# 12 popular plugins, Joomla 6, Drupal 11): 70 shells matched; of the 622 clean
# files that assign from a superglobal, 0. An earlier version also counted
# backticks anywhere and flagged 33 WordPress core files, whose docblocks
# write `$action` in markdown style -- hence the expression-position rule.
# One awk process per batch of files, never one per file.
if [ "${#ROOTS[@]}" -gt 0 ]; then
  grep -rlE '\$[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*=[^=;][^;]*\$_(GET|POST|REQUEST|COOKIE)' \
    --include='*.php' "${ROOTS[@]}" 2>/dev/null \
    | LC_ALL=C xargs -d '\n' -r awk '
        function flush(  u) {
          if (cur != "") for (u in use) if (u in src) { print cur; break }
          split("", src); split("", use); cur = FILENAME
        }
        FNR == 1 { flush() }
        {
          line = $0
          while (match(line, /\$[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[^=;][^;]*\$_(GET|POST|REQUEST|COOKIE)/)) {
            v = substr(line, RSTART, RLENGTH); sub(/[[:space:]]*=.*/, "", v); src[v] = 1
            line = substr(line, RSTART + RLENGTH)
          }
          line = $0
          while (match(line, /(system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)[[:space:]]*\([[:space:]]*\$[A-Za-z_][A-Za-z0-9_]*/)) {
            pre = (RSTART > 1) ? substr(line, RSTART - 1, 1) : ""
            if (pre !~ /[A-Za-z0-9_>:$]/) { u = substr(line, RSTART, RLENGTH); sub(/^[^$]*/, "", u); use[u] = 1 }
            line = substr(line, RSTART + RLENGTH)
          }
          line = $0
          # a backtick only where an expression can start: WordPress docblocks
          # write `$action` in markdown style, and those are not commands
          while (match(line, /(=|echo|print|return|\()[[:space:]]*`[[:space:]]*\$[A-Za-z_][A-Za-z0-9_]*/)) {
            u = substr(line, RSTART, RLENGTH); sub(/^[^$]*/, "", u); use[u] = 1
            line = substr(line, RSTART + RLENGTH)
          }
        }
        END { flush() }' 2>/dev/null | sort -u | art | cap
fi

sub "PHP files with almost no whitespace / high symbol density"
if [ "${#ROOTS[@]}" -gt 0 ]; then
  find "${ROOTS[@]}" -type f -name '*.php' -size +2k 2>/dev/null \
    | while IFS= read -r f; do
        tot=$(wc -c < "$f"); sp=$(tr -cd ' \n\t' < "$f" | wc -c)
        [ "$tot" -gt 0 ] || continue
        pct=$(( sp * 100 / tot ))
        [ "$pct" -lt 4 ] && echo "$f  (whitespace ${pct}%)"
      done | cap
fi

# -----------------------------------------------------------------------------
sec "8. PHP CODE HIDDEN IN NON-PHP FILES"
if [ "${#ROOTS[@]}" -gt 0 ]; then
  grep -rlE '<\?php|<\?=' \
    --include='*.jpg' --include='*.jpeg' --include='*.png' --include='*.gif' \
    --include='*.ico' --include='*.svg' --include='*.css' --include='*.log' \
    --include='*.zip' --include='*.bak' --include='*.old' --include='*.json' \
    --include='*.woff' --include='*.ttf' \
    "${ROOTS[@]}" 2>/dev/null | cap
fi

# -----------------------------------------------------------------------------
sec "9. MALICIOUS .htaccess / php.ini"
if [ "${#ROOTS[@]}" -gt 0 ]; then
  sub ".htaccess mapping images to the PHP handler, or auto_prepend backdoors"
  grep -rnsE '(AddHandler|AddType|SetHandler)[^\n]*(php|x-httpd)|auto_prepend_file|auto_append_file|php_value[[:space:]]+auto_|RewriteRule.*\.(jpg|png|gif|ico).*\.php' \
    --include='.htaccess' "${ROOTS[@]}" 2>/dev/null | cap
  sub ".htaccess with redirects/cloaking (SEO spam / mobile redirect)"
  grep -rnsE 'HTTP_USER_AGENT.*(googlebot|bingbot|android|iphone)|HTTP_REFERER.*(google|yandex|bing)' \
    --include='.htaccess' "${ROOTS[@]}" 2>/dev/null | cap
  sub "stray php.ini / .user.ini in webroots (auto_prepend abuse)"
  find "${ROOTS[@]}" -maxdepth 4 \( -name '.user.ini' -o -name 'php.ini' \) 2>/dev/null \
    | while IFS= read -r f; do log ">>> $f"; grep -vE '^[[:space:]]*(;|$)' "$f" | cap; done
fi

# -----------------------------------------------------------------------------
sec "10. RECENTLY MODIFIED FILES IN WEBROOTS (last ${DAYS}d)"
if [ "${#ROOTS[@]}" -gt 0 ]; then
  sub "executable-by-web extensions changed recently"
  find "${ROOTS[@]}" -type f \( -name '*.php' -o -name '*.php[0-9]' -o -name '*.phtml' \
       -o -name '*.pht' -o -name '*.phar' -o -name '*.cgi' -o -name '*.pl' \) \
       -mtime -"$DAYS" -printf '%TY-%Tm-%Td %TH:%TM  %u:%g %m  %p\n' 2>/dev/null \
       | sort -r | cap
  sub "newest 40 files of ANY type"
  find "${ROOTS[@]}" -type f -printf '%TY-%Tm-%Td %TH:%TM  %p\n' 2>/dev/null | sort -r | head -40 | cap
  sub "files where ctime > mtime (timestomping -- mtime was faked)"
  find "${ROOTS[@]}" -type f -name '*.php' -newerct "-${DAYS} days" \
       ! -newermt "-${DAYS} days" -printf '%p  mtime=%TF ctime=%CF\n' 2>/dev/null | cap
fi

# -----------------------------------------------------------------------------
sec "11. PERMISSION / OWNERSHIP ANOMALIES"
if [ "${#ROOTS[@]}" -gt 0 ]; then
  sub "world-writable files (777/666)"
  find "${ROOTS[@]}" -type f -perm -0002 -printf '%m %u:%g %p\n' 2>/dev/null | cap
  sub "PHP files owned by the web server user (should be owned by the site user)"
  find "${ROOTS[@]}" -type f -name '*.php' \
       \( -user apache -o -user nginx -o -user www-data -o -user nobody -o -user psacln \) \
       -printf '%u:%g %p\n' 2>/dev/null | cap
  sub "files/dirs with odd names (dot-prefixed, space-suffixed, unicode)"
  find "${ROOTS[@]}" -maxdepth 6 \( -name '.*.php' -o -name '* ' -o -name '*..*' \) 2>/dev/null | cap
fi

# -----------------------------------------------------------------------------
sec "12. EXECUTABLES IN UPLOAD / CACHE DIRS (should never contain PHP)"
if [ "${#ROOTS[@]}" -gt 0 ]; then
  find "${ROOTS[@]}" -type d \( -name 'uploads' -o -name 'upload' -o -name 'files' \
       -o -name 'images' -o -name 'img' -o -name 'media' -o -name 'cache' -o -name 'tmp' \
       -o -name 'backup' -o -name 'assets' \) 2>/dev/null \
    | while IFS= read -r d; do
        find "$d" -type f \( -name '*.php' -o -name '*.php[0-9]' -o -name '*.phtml' \
             -o -name '*.pht' -o -name '*.phar' -o -name '*.suspected' \) 2>/dev/null
      done | sort -u | cap
fi
sub "double-extension files anywhere in webroots"
if [ "${#ROOTS[@]}" -gt 0 ]; then
  find "${ROOTS[@]}" -type f -regextype posix-extended \
    -regex '.*\.(php|phtml|phar|pht)\.(jpg|jpeg|png|gif|txt|bak|old|zip|html)$' 2>/dev/null | cap
  find "${ROOTS[@]}" -type f -regextype posix-extended \
    -regex '.*\.(jpg|jpeg|png|gif|ico|txt)\.(php|phtml|phar|pht)$' 2>/dev/null | cap
fi

# -----------------------------------------------------------------------------
sec "13. MAIL ABUSE (spam sent through the shell)"
if have exim; then
  log "exim queue size: $(exim -bpc 2>/dev/null)"
  sub "top sending scripts (exim mainlog)"
  grep -hoE 'cwd=[^ ]+' /var/log/exim/mainlog* /var/log/exim_mainlog* 2>/dev/null \
    | sort | uniq -c | sort -rn | head -20 | cap
fi
if have postqueue; then
  log "postfix queue size: $(postqueue -p 2>/dev/null | tail -1)"
fi
sub "PHP mail() senders recorded by mail.log (Plesk)"
grep -hoE 'X-PHP-Originating-Script: [^ ]+' /var/log/maillog /var/log/mail.log 2>/dev/null \
  | sort | uniq -c | sort -rn | head -20 | cap
sub ".forward / pipe-to-command backdoors"
find /home /var/qmail/mailnames /var/qmail/control -maxdepth 4 -name '.forward' 2>/dev/null \
  | while IFS= read -r f; do log ">>> $f"; cat "$f" | cap; done

# -----------------------------------------------------------------------------
sec "14. ENTRY-POINT HINTS FROM ACCESS LOGS"
LOGS=()
SEENLOGS=""
for g in /var/log/httpd/domains/*.log \
         /var/log/apache2/*access*log /var/log/apache2/domlogs/* \
         /var/log/nginx/*access*log \
         /var/www/vhosts/system/*/logs/*access*log \
         /usr/local/apache/domlogs/* \
         /usr/local/lsws/logs/*access*log /usr/local/lsws/logs/*/*access*log \
         /home/*/logs/*access*log /home/*/logs/*/*access*log \
         /var/log/virtualmin/*access_log; do
  [ -f "$g" ] || continue
  # cPanel keeps byte counters and FTP transfer offsets beside the access logs.
  case "$g" in *-bytes_log|*ftpxferlog*) continue ;; esac
  # The same directory is often reachable by several of the paths above -- on
  # cPanel all three domlogs paths are one directory behind symlinks -- and a
  # log read three times prints every request three times.
  rp=$(readlink -f "$g" 2>/dev/null); rp=${rp:-$g}
  case "$SEENLOGS" in *"|$rp|"*) continue ;; esac
  SEENLOGS="$SEENLOGS|$rp|"
  LOGS+=("$g")
done
# Compressed history. cPanel's log processor empties the live domlog and files
# the requests away as /home/<user>/logs/<domain>-<Mon>-<Year>.gz -- observed
# within a minute of the request on cPanel 138 -- so on that panel the live logs
# hold almost nothing and the evidence is all in the archives. Rotated nginx
# and Apache logs are the same story one logrotate cycle later.
ZLOGS=()
for g in /home/*/logs/*.gz /var/log/nginx/*access*log*.gz \
         /var/log/apache2/*access*log*.gz /var/log/httpd/*access*log*.gz; do
  [ -f "$g" ] || continue
  case "$g" in *.tar.gz|*-bytes_log*) continue ;; esac
  ZLOGS+=("$g")
done
# One grep over all plain logs and one zgrep over all archives: two processes
# per question, however many logs there are.
lgrep() {
  [ "${#LOGS[@]}" -gt 0 ] && grep "$@" "${LOGS[@]}" 2>/dev/null
  [ "${#ZLOGS[@]}" -gt 0 ] && have zgrep && zgrep "$@" "${ZLOGS[@]}" 2>/dev/null
  return 0
}
NLOGS=$(( ${#LOGS[@]} + ${#ZLOGS[@]} ))
log "access logs found: ${#LOGS[@]} live, ${#ZLOGS[@]} compressed"
[ "${#ZLOGS[@]}" -gt 0 ] && ! have zgrep && \
  log "!! zgrep is not installed -- the compressed logs were NOT searched"
if [ "$NLOGS" -eq 0 ]; then
  log "!! none found -- locate them manually, then re-run with the path:"
  log "     ss -ltnp | grep -E ':(80|443)'   then check that server's config"
  log "   LiteSpeed/OpenLiteSpeed default: /usr/local/lsws/logs/"
  log "   CyberPanel: /home/<domain>/logs/    Virtualmin: /var/log/virtualmin/"
fi
if [ "$NLOGS" -gt 0 ]; then
  sub "POST requests to PHP inside upload/cache dirs (shell being driven)"
  lgrep -hE '"POST [^"]*(upload|uploads|images|cache|tmp|assets|media)/[^"]*\.php' \
    | tail -60 | cap
  sub "requests to any file flagged in section 6"
  if [ -s "$CAND" ]; then
    while IFS= read -r f; do
      b=$(basename "$f")
      case "$b" in *.php|*.phtml|*.phar) ;; *) continue ;; esac
      hits=$(lgrep -hF "/$b" | tail -5)
      [ -n "$hits" ] && { log ">>> $b"; printf '%s\n' "$hits" | cut -c1-220 | tee -a "$OUT"; }
    done < <(head -40 "$CAND")
  fi
  sub "common exploit probes (LFI/RCE/upload)"
  lgrep -hoiE '(\.\./\.\./|/wp-content/plugins/[a-z0-9_-]+/[^ "]*\.php\?|xmlrpc\.php|/wp-json/wp/v2/users|eval\(|base64_|union[+ ]select|/vendor/phpunit|think\\\\app|/cgi-bin/)' \
    | sort | uniq -c | sort -rn | head -25 | cap

  sub "CMS component/plugin task endpoints in the query string"
  # Joomla and WordPress route exploits through option=/task=/action= parameters.
  # Anything here with a 500 usually means the component EXISTS and is reachable
  # -- a 404 means it is not installed on that vhost.
  lgrep -hoiE 'option=com_[a-z0-9_]+&[a-z]*task=[a-z0-9_.]+|action=[a-z0-9_]*upload[a-z0-9_]*' \
    | sort | uniq -c | sort -rn | head -25 | cap

  sub "status codes returned to those endpoint probes"
  lgrep -hoiE '"(GET|POST) [^"]*(option=com_[a-z0-9_]+|task=[a-z0-9_.]*upload[a-z0-9_.]*)[^"]*" [0-9]{3}' \
    | grep -oE '[0-9]{3}$' | sort | uniq -c | sort -rn | head | cap

  log ""
  log "  !! IMPORTANT -- a quiet result here does NOT mean no exploitation."
  log "  !! Real exploitation is usually POST, with the parameters in the request"
  log "  !! BODY, which access logs do not record. Only the GET-style probes are"
  log "  !! visible above. Correlate POST requests by timestamp against the mtime"
  log "  !! of the files found in section 6/10 instead:"
  log "  !!    grep -h 'POST /index.php' <log> | grep '<DD/Mon/YYYY>'"
fi
sub "panel + FTP + SSH login activity"
grep -hiE 'fail|invalid|error' /var/log/directadmin/*.log 2>/dev/null | tail -20 | cap
grep -hiE 'authentication|login' /var/log/plesk/panel.log 2>/dev/null | tail -20 | cap
grep -hE 'FAILED LOGIN' /usr/local/cpanel/logs/login_log 2>/dev/null | tail -20 | cap
grep -hE 'Accepted (password|publickey)' /var/log/secure /var/log/auth.log 2>/dev/null | tail -25 | cap
# Match both FTP daemons. pure-ftpd writes "OK LOGIN", proftpd writes
# "Login successful", and they log to different files -- so a check written for
# one of them reports nothing on a host running the other, which reads exactly
# like a host with no FTP activity. Report which daemon is actually running so
# an empty result can be told apart from an unsupported log format.
#
# Detected by running process, not by unit name. Debian and Ubuntu ship Pure-FTPd
# as pure-ftpd-mysql / -postgresql / -ldap, whose unit and process names do not
# match "pure-ftpd" -- so a CyberPanel host with FTP running reported "none".
# The unit is no better a witness: on that host pure-ftpd-mysql.service read
# "active (exited)" while the daemon had died at startup. Pure-FTPd's process
# title is "pure-ftpd (SERVER)" whatever the package is called.
FTPD="none detected"
if   pgrep -x proftpd >/dev/null 2>&1;     then FTPD="proftpd"
elif pgrep -f '^pure-ftpd' >/dev/null 2>&1; then FTPD="pure-ftpd"
elif pgrep -x vsftpd >/dev/null 2>&1;      then FTPD="vsftpd"
fi
log "  FTP daemon: $FTPD"
# FTP daemons log to their own file on some systems and to the general system
# log on others: /var/log/messages or /var/log/secure on RHEL, /var/log/syslog
# on Debian and Ubuntu, which was not read at all. General logs are filtered to
# FTP daemon lines first, so an SMTP "SASL authentication failed" is not
# counted as an FTP brute force.
ftplines() {
  grep -rhs '' /var/log/pureftpd.log /var/log/xferlog /var/log/proftpd/ 2>/dev/null
  grep -hsE 'pure-ftpd|proftpd|vsftpd' /var/log/messages /var/log/secure /var/log/syslog 2>/dev/null
  return 0
}
# Formats observed on real hosts, not assumed: Pure-FTPd writes "is now logged
# in" (Ubuntu 24.04). ProFTPD authenticating through PAM on RHEL writes only
# pam_unix lines -- "session opened for user" and "authentication failure" --
# and with neither pattern present, both checks were silent on a Virtualmin
# host with ProFTPD (AlmaLinux 9). "Login successful" is ProFTPD's own wording.
ftplines | grep -iE 'OK LOGIN|Login successful|is now logged in|session opened for user' | tail -25 | cap
sub "FTP login FAILURES -- brute force against panel FTP accounts"
# One source per line: Pure-FTPd writes the client as "(user@host)", proftpd as
# "host (1.2.3.4[1.2.3.4])". Taking every IP on the line counted proftpd twice,
# and a client shown by hostname was not counted at all.
ftplines | grep -iE 'authentication failed|authentication failure|Login failed|no such user' \
  | awk '{ if (match($0, /@[^) ]+\)/)) { print substr($0, RSTART + 1, RLENGTH - 2); next }
           if (match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) print substr($0, RSTART, RLENGTH) }' \
  | sort | uniq -c | sort -rn | head -15 | cap
sub "log files that were truncated or deleted (anti-forensics)"
find /var/log -maxdepth 2 -type f -size 0 -mtime -"$DAYS" 2>/dev/null | cap

# -----------------------------------------------------------------------------
sec "15. SYSTEM BINARY INTEGRITY"
if [ -f /etc/redhat-release ] && grep -qE 'release 7' /etc/redhat-release 2>/dev/null; then
  log "!! CentOS/RHEL 7 detected -- upstream EOL was 2024-06-30."
  log "!! Kernel/glibc/openssl get no security patches unless you have CloudLinux ELS"
  log "!! or a similar extended-support subscription. Check: yum list installed | grep els"
  yum list installed 2>/dev/null | grep -iE 'els|extended' | cap
  log "   last yum transaction: $(yum history 2>/dev/null | sed -n '4p')"
fi
if have rpm; then
  log "rpm -Va on core packages (5=md5 differs, T=mtime, S=size):"
  rpm -Va coreutils util-linux openssh-server bash procps-ng 2>/dev/null | cap
elif have debsums; then
  debsums -c 2>/dev/null | cap
else
  log "no rpm/debsums available -- install debsums (apt) to verify binaries"
fi
sub "CMS core integrity, if WP-CLI is available"
# Never with --allow-root: wp-cli loads the target site's wp-config.php, so on a
# compromised site running it as root executes attacker PHP as root. Drop to the
# directory owner, which grants only the privilege that code already had.
if have wp; then
  for r in "${ROOTS[@]:-}"; do
    [ -f "$r/wp-config.php" ] || continue
    owner=$(stat -c '%U' "$r" 2>/dev/null)
    log ">>> $r   (as ${owner:-?})"
    if [ -n "${owner:-}" ] && [ "$owner" != "root" ] && have sudo; then
      sudo -u "$owner" -- wp --path="$r" core verify-checksums 2>&1 | head -20 | cap
    else
      log "    SKIPPED -- refusing to run wp-cli as root against a suspect site."
      log "    Run manually:  sudo -u <siteuser> wp --path=$r core verify-checksums"
    fi
  done
else
  log "wp-cli not installed -- 'wp core verify-checksums' is the fastest WordPress check"
fi

# -----------------------------------------------------------------------------
sec "16. ANTI-CLEANUP, AUTOLOADERS AND CLIENT-SIDE INJECTION"
# This section exists because sections 6-10 miss a whole class of compromise:
# code that is not a PHP shell. It looks for files that resist automated cleanup,
# directories that load without ever appearing in a CMS admin screen, and
# JavaScript injected to attack the site's visitors rather than the server.
if [ "${#ROOTS[@]}" -gt 0 ]; then

  sub "PHP files the OWNER cannot write -- resists scanner cleanup"
  # A read-only PHP file survives scanners that neutralise malware by emptying it
  # rather than deleting it. Some backdoors re-apply chmod 0444 to themselves on
  # every request, so a manual chmod is reverted; only removal works.
  # Excluded below: CMS config files that are meant to be read-only.
  find "${ROOTS[@]}" -type f -name '*.php' ! -perm -u+w \
    ! -name 'wp-config.php' ! -name 'configuration.php' ! -name 'settings.php' \
    -printf '%m %u:%g %TY-%Tm-%Td %p\n' 2>/dev/null | art | cap

  sub "PHP files writable by ANY user on the system"
  find "${ROOTS[@]}" -type f -name '*.php' -perm -o+w \
    -printf '%m %u:%g %p\n' 2>/dev/null | art | cap

  sub "zero-byte PHP -- trace of a scanner that trimmed instead of deleting"
  # An empty .php file with a random name is not junk: it marks a file that was
  # malicious and got emptied. Their timestamps reconstruct the reinfection
  # timeline, including for sites that look clean today.
  find "${ROOTS[@]}" -type f -size 0 \( -name '*.php' -o -name '*.phtml' \) \
    -printf '%TY-%Tm-%Td %TH:%TM  %p\n' 2>/dev/null | sort | art | cap

  sub "random-name .txt beside PHP -- encrypted payload / proxy list pattern"
  find "${ROOTS[@]}" -type f -regextype posix-extended \
    -regex '.*/[a-z]{8,12}\.txt$' -printf '%TY-%Tm-%Td %8s %p\n' 2>/dev/null | art | cap

  sub "WordPress auto-loaders -- run on every request, absent from the plugin list"
  # mu-plugins and drop-ins load with no activation step and are invisible in
  # wp-admin, which makes them a preferred place to hide a persistent injector.
  for r in "${ROOTS[@]}"; do
    [ -d "$r/wp-content" ] || continue
    if [ -d "$r/wp-content/mu-plugins" ]; then
      ls -la "$r/wp-content/mu-plugins/" 2>/dev/null | sed "s|^|  [$r] |" | cap
    fi
    for dropin in object-cache.php db.php advanced-cache.php sunrise.php maintenance.php; do
      [ -f "$r/wp-content/$dropin" ] && \
        log "  DROP-IN  $(stat -c '%m %TY-%Tm-%Td %s' "$r/wp-content/$dropin" 2>/dev/null)  $r/wp-content/$dropin"
    done
  done

  sub "plugin directories with no valid plugin header -- fake plugins"
  for r in "${ROOTS[@]}"; do
    [ -d "$r/wp-content/plugins" ] || continue
    for d in "$r/wp-content/plugins"/*/; do
      [ -d "$d" ] || continue
      if ! grep -rlqs --include='*.php' --max-count=1 'Plugin Name:' "$d" 2>/dev/null; then
        log "  NO HEADER  $(stat -c '%TY-%Tm-%Td' "$d" 2>/dev/null)  $d"
      fi
    done
  done

  sub "unexpected directories inside wp-includes / wp-admin"
  # Injecting a subdirectory into a core tree hides files among thousands of
  # legitimate ones and survives plugin and theme reinstalls.
  for r in "${ROOTS[@]}"; do
    for core in wp-includes wp-admin; do
      [ -d "$r/$core" ] || continue
      find "$r/$core" -type d -name 'wp' -o -type d -name 'wp-*' 2>/dev/null \
        | grep -vE '/(wp-includes|wp-admin)$' | sed "s|^|  |" | cap
    done
  done

  sub "client-side JS injection: repeating-key XOR decoder"
  # Pattern: base64 -> XOR with a repeating key -> inject as a <script> element.
  # No literal payload appears in the file, so PHP shell signatures never match it.
  grep -rlE 'charCodeAt\([^)]*\)[[:space:]]*\^[[:space:]]*[_a-zA-Z0-9$]+\.charCodeAt' \
    "${ROOTS[@]}" --include='*.php' --include='*.js' --include='*.html' 2>/dev/null | art | cap

  sub "script element appended to documentElement (not head/body)"
  # Legitimate loaders append to head or body. Appending to documentElement is
  # rare outside injected code, which makes it a low-noise discriminator --
  # verified not to match jQuery's DOMEval, present on every WordPress site.
  # Note: do NOT try to match createElement and the code assignment in one
  # expression. A ';' separates the two statements in real samples, so any
  # single-line pattern misses them.
  grep -rlE 'documentElement\.appendChild' \
    "${ROOTS[@]}" --include='*.php' --include='*.js' 2>/dev/null | art | cap

  sub "obfuscation via built-in .name properties (defeats string signatures)"
  # Strings such as "eval" are assembled from Array.name, RegExp.name and similar,
  # so the file contains no searchable keyword at all.
  # The character class here must be written (\[|\.) -- a bracket expression
  # containing '[.' opens a POSIX collating symbol and makes grep error out,
  # which with stderr suppressed looks exactly like "nothing found".
  grep -rlE '(RegExp|Array|Boolean|CustomEvent|Path2D|NodeList|Function)\.name[[:space:]]*(\[|\.)' \
    "${ROOTS[@]}" --include='*.php' --include='*.js' 2>/dev/null | cap

  sub "blockchain payload hosting (EtherHiding) -- literal indicators only"
  # A 40-hex EVM contract address plus JSON-RPC method names means the second
  # stage is fetched from a smart contract. There is no C2 domain to block and
  # the operator rewrites the payload with one transaction, so domain
  # blocklists do not help; the contract address is the indicator to record.
  #
  # LIMITATION, measured against a live sample: when the loader is XOR-encoded,
  # neither the address nor the RPC method names exist on disk -- both are
  # assembled at runtime from built-in .name properties. Those variants are
  # caught by the XOR decoder check above, not here. A quiet result in this
  # subsection therefore proves nothing on its own.
  grep -rlE '0x[a-fA-F0-9]{40}' "${ROOTS[@]}" \
    --include='*.php' --include='*.js' 2>/dev/null | cap
  grep -rhoE 'eth_call|eth_getBlockByNumber|jsonrpc|bsc-dataseed|binance\.org|infura|alchemy\.com' \
    "${ROOTS[@]}" --include='*.php' --include='*.js' 2>/dev/null | sort | uniq -c | sort -rn | head -10 | cap

  sub "cloaking: content served conditionally to hide from the site owner"
  grep -rlE 'HTTP_REFERER[^;]{0,80}(google|bing|yandex)|is_user_logged_in\(\)[[:space:]]*\)?[[:space:]]*(\?|\|\|)|HTTP_USER_AGENT[^;]{0,60}(iPhone|Android|Mobile)' \
    "${ROOTS[@]}" --include='*.php' 2>/dev/null | cap
  log ""
  log "  Cloaked injections commonly show only to search-engine referrers, only on"
  log "  mobile, only once per visitor IP, and never to a logged-in administrator."
  log "  Verify from outside with a spoofed request, not by opening the site:"
  log "    curl -sL -A '<mobile UA>' -e 'https://www.google.com/' https://site/ \\"
  log "      | grep -oE '<script[^>]*>' | sort -u"
  log "  Compare against a plain request -- the difference is what was injected."
fi

# -----------------------------------------------------------------------------
sec "17. GENERIC DETECTION -- for families no signature knows about"
# Every signature-based section above shares one weakness: it only finds what
# somebody already described. Sections 6 and 16 were both written against real
# samples and both still started out missing the sample that prompted them.
#
# The checks here do not model malware. They model what NORMAL looks like, and
# report the outliers -- which is what catches a family nobody has seen yet.
if [ "${#ROOTS[@]}" -gt 0 ]; then

  sub "PHP files containing a long unbroken base64 run"
  # Measured on a live sample: the malicious payload carried a 56,030-character
  # run. A legitimately embedded PNG icon measured 1,467. The 4000 threshold sits
  # between them. Base64-embedded fonts can legitimately exceed it, so treat a
  # hit as "read this file", not as a verdict.
  #
  # Candidates are found in ONE grep pass per webroot, then measured only for the
  # few files that matched. Never loop per file here: a per-file pipeline on a
  # shared host with ~100 accounts means hundreds of thousands of process spawns,
  # which turns a read-only report into a self-inflicted outage.
  grep -rlE '[A-Za-z0-9+/]{4000,}' "${ROOTS[@]}" --include='*.php' 2>/dev/null \
    | head -n "$MAXHITS" | while IFS= read -r f; do
        L=$(grep -oE '[A-Za-z0-9+/]{4000,}' "$f" 2>/dev/null | awk '{ if (length($0)>m) m=length($0) } END{print m+0}')
        log "  base64 run ${L}c  $(stat -c '%TY-%Tm-%Td %8s' "$f" 2>/dev/null)  $f"
      done

  sub "PHP files with an extremely long single line"
  # Same sample: longest line 56,101 characters against 71 for ordinary PHP.
  # Obfuscators emit one enormous line because newlines cost them nothing and
  # cost a reader everything.
  grep -rlE '.{5000,}' "${ROOTS[@]}" --include='*.php' 2>/dev/null \
    | head -n "$MAXHITS" | while IFS= read -r f; do
        M=$(awk '{ if (length($0)>m) m=length($0) } END{print m+0}' "$f" 2>/dev/null)
        log "  maxline ${M}c  $(stat -c '%TY-%Tm-%Td %8s' "$f" 2>/dev/null)  $f"
      done

  sub "WordPress package integrity -- the strongest check available"
  # This is the one check that finds an UNKNOWN family. It does not ask what the
  # code does; it asks whether the file matches what wordpress.org shipped.
  # Any modified core file, and any file present in a plugin directory that is
  # not part of that plugin's official package, is reported regardless of
  # content, obfuscation or novelty.
  if have wp && [ "$DO_SUMS" = "1" ]; then
    WPCOUNT=0
    for r in "${ROOTS[@]}"; do
      [ -f "$r/wp-includes/version.php" ] && WPCOUNT=$((WPCOUNT+1))
    done
    log "  verifying $WPCOUNT WordPress install(s) -- this fetches checksums from"
    log "  wordpress.org and hashes every core file, so allow roughly 10-30s each."
    for r in "${ROOTS[@]}"; do
      [ -f "$r/wp-includes/version.php" ] || continue
      # Run as the site's own user, never as root.
      #
      # wp-cli always loads the target site's wp-config.php -- that is how it
      # finds the database, and --skip-plugins/--skip-themes does not change it.
      # On a site that is already compromised, wp-config.php is attacker-writable
      # in practice, so `wp --allow-root` executes their PHP with root privileges.
      # That turns an integrity check into privilege escalation, in exactly the
      # situation the check exists for.
      #
      # Dropping to the directory owner grants the code only the privilege it
      # already had, so there is nothing to escalate.
      # echo, not log, inside this loop: it is piped through cap, which already
      # writes to the report, so log recorded each of these lines twice.
      owner=$(stat -c '%U' "$r" 2>/dev/null)
      echo "  --- $r   (as ${owner:-root})"
      if [ -n "${owner:-}" ] && [ "$owner" != "root" ] && have sudo; then
        sudo -u "$owner" -- wp --path="$r" --skip-plugins --skip-themes \
          core verify-checksums 2>&1 | head -25 | sed 's/^/    /'
        sudo -u "$owner" -- wp --path="$r" --skip-plugins --skip-themes \
          plugin verify-checksums --all 2>&1 | head -40 | sed 's/^/    /'
      else
        echo "    !! cannot drop privileges (owner='${owner:-?}', sudo present=$(have sudo && echo yes || echo no))."
        echo "    !! SKIPPED rather than run wp-cli as root against a suspect site."
        echo "    !! Run it manually as that user:  sudo -u <user> wp --path=$r core verify-checksums"
      fi
    done | cap
  elif have wp; then
    log "  [SKIPPED -- pass --checksums to enable]"
    log ""
    log "  !! This is the STRONGEST check in the whole script and it is off by"
    log "  !! default only because it is slow and needs network: it downloads"
    log "  !! checksums from wordpress.org and hashes every core file, roughly"
    log "  !! 10-30 seconds per install. On a host with many sites that is minutes."
    log "  !! Run it. Nothing else here finds a malware family nobody has described."
    log "  !! Or run it per site, outside this script -- as the SITE'S user, not root,"
    log "  !! because wp-cli loads that site's wp-config.php and on a compromised"
    log "  !! site that file runs attacker code with whatever privilege you gave it:"
    log "  !!   sudo -u <siteuser> wp --path=<webroot> core verify-checksums"
    log "  !!   sudo -u <siteuser> wp --path=<webroot> plugin verify-checksums --all"
  else
    log "  !! wp-cli is NOT installed, and for WordPress hosts this is the single"
    log "  !! most valuable check you are missing. It finds families no pattern knows."
    log "  !!   curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar"
    log "  !!   install -m0755 wp-cli.phar /usr/local/bin/wp"
    log "  !! Then, AS THE SITE USER (not root -- wp-cli loads their wp-config.php):"
    log "  !!   sudo -u <siteuser> wp --path=<webroot> core verify-checksums"
  fi
  sub "Joomla package integrity -- every core file against the official release"
  # Joomla ships no verify-checksums command, so this does what one would: read
  # the site's version, fetch the official Full Package of exactly that version
  # from the project's GitHub releases into $WORK, and compare file by file.
  #   MODIFIED  a file that ships with Joomla and differs from the release --
  #             PHP or the JS under media/, where client-side injection lives
  #   ADDED     a PHP file that is not in the release but sits in a directory
  #             that is. Extensions install into their own directories, which
  #             the release does not have, so they are not reported; backdoors
  #             dropped into core component directories are (the shape seen
  #             in administrator/components/com_* on a compromised host).
  # Nothing is executed and nothing in the webroot is touched. A site whose
  # release cannot be fetched is reported as NOT verified, never skipped.
  # Counted before the loop: the loop runs in a pipeline, i.e. a subshell, and
  # a counter incremented inside it would read 0 out here.
  JCOUNT=0
  for r in "${ROOTS[@]}"; do
    [ -f "$r/administrator/manifests/files/joomla.xml" ] && JCOUNT=$((JCOUNT+1))
  done
  if [ "$DO_SUMS" = "1" ]; then
    for r in "${ROOTS[@]}"; do
      jx="$r/administrator/manifests/files/joomla.xml"
      [ -f "$jx" ] || continue
      jver=$(sed -n 's:.*<version>\([0-9][0-9.]*\)</version>.*:\1:p' "$jx" 2>/dev/null | head -n 1)
      echo "  --- $r   (Joomla ${jver:-version unreadable})"
      case "$jver" in
        [0-9]*.[0-9]*.[0-9]*) ;;
        *) echo "    !! version not readable from $jx -- NOT verified"; continue ;;
      esac
      pkg="$WORK/joomla-$jver"
      if [ ! -f "$pkg.sums" ]; then
        mkdir -p "$pkg"
        url="https://github.com/joomla/joomla-cms/releases/download/$jver/Joomla_$jver-Stable-Full_Package.tar.gz"
        if ! curl -fsSL --max-time 300 "$url" 2>/dev/null | tar -xz -C "$pkg" 2>/dev/null \
           || [ ! -f "$pkg/administrator/manifests/files/joomla.xml" ]; then
          echo "    !! could not fetch the official $jver release -- this site was NOT verified"
          echo "    !!   $url"
          rm -rf "$pkg"; continue
        fi
        ( cd "$pkg" && find . -type f -print0 | xargs -0 sha256sum ) > "$pkg.sums" 2>/dev/null
        ( cd "$pkg" && find . -type d ) > "$pkg.dirs" 2>/dev/null
        rm -rf "$pkg"
      fi
      # Hash only what the release contains, in one process per batch.
      ( cd "$r" && sed 's/^[0-9a-f]*  //' "$pkg.sums" \
          | while IFS= read -r p; do [ -f "$p" ] && printf '%s\n' "$p"; done \
          | xargs -d '\n' -r sha256sum ) > "$WORK/jsite.sums" 2>/dev/null
      # Runtime directories are left out of ADDED: Joomla 4+ writes
      # administrator/cache/autoload_psr4.php itself, into a directory the
      # release ships, and would be reported on every live site. PHP in cache,
      # tmp, images and logs is section 12's job, which reports it regardless.
      ( cd "$r" && find . \( -path ./cache -o -path ./administrator/cache -o -path ./tmp \
          -o -path ./images -o -path ./logs -o -path ./administrator/logs \) -prune \
          -o -type f \( -name '*.php' -o -name '*.php[0-9]' -o -name '*.phtml' \
          -o -name '*.phar' -o -name '*.inc' \) ! -path './configuration.php' -print ) > "$WORK/jsite.php" 2>/dev/null
      awk -v root="$r" '
        FILENAME == ARGV[1] { h = $1; sub(/^[0-9a-f]*  /, ""); pkgsum[$0] = h; next }
        FILENAME == ARGV[2] { pkgdir[$0] = 1; next }
        FILENAME == ARGV[3] { h = $1; sub(/^[0-9a-f]*  /, "")
                              if ($0 in pkgsum && pkgsum[$0] != h) { print "    MODIFIED " root substr($0, 2); nm++ }
                              next }
        { if (!($0 in pkgsum)) { d = $0; sub(/\/[^\/]*$/, "", d)
                                 if (d in pkgdir) { print "    ADDED    " root substr($0, 2); na++ } } }
        END { printf "    %d modified core file(s), %d PHP file(s) added inside core directories\n", nm, na }
      ' "$pkg.sums" "$pkg.dirs" "$WORK/jsite.sums" "$WORK/jsite.php" 2>/dev/null
    done | art | cap
    [ "$JCOUNT" = "0" ] && log "  no Joomla installation among the scanned roots"
  elif [ "$JCOUNT" -gt 0 ]; then
    log "  [SKIPPED -- $JCOUNT Joomla site(s) found; pass --checksums to verify them against"
    log "   the official release of their version. This is the check that finds a family"
    log "   no signature knows.]"
  fi

  sub "files whose extension does not match their content"
  # An extension is a claim, not a fact. One grep pass, not one per file.
  grep -rlaE '<\?php|<\?=' "${ROOTS[@]}" \
    --include='*.txt' --include='*.log' --include='*.css' --include='*.json' \
    --include='*.ini' --include='*.md' 2>/dev/null \
    | sed 's/^/  PHP inside  /' | cap

  if [ "$DO_HTTP" = "1" ]; then
    sub "black-box fetch: injection served to visitors but absent from files"
    # File scanning cannot see an injection stored in the database or in web
    # server config. Fetching the site as a visitor can. Cloaked injections
    # commonly appear only for a search-engine referrer or a mobile agent, and
    # never for a logged-in administrator -- so two requests are compared.
    UA_M='Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15'
    # Which domain a webroot answers to. Only DirectAdmin puts the domain in the
    # path; cPanel and Plesk record it, so ask them. This used to derive the
    # domain from the path alone, which meant that on every panel except
    # DirectAdmin the loop skipped each root and the section printed nothing --
    # indistinguishable from "fetched every site and found them clean".
    DOMMAP="$WORK/dommap"          # lines of: <document root><TAB><domain>
    : > "$DOMMAP"
    for f in /var/cpanel/userdata/*/*; do
      [ -f "$f" ] || continue
      case "$f" in *.cache|*.json|*.yaml|*_SSL|*/main) continue ;; esac
      dr=$(sed -n 's/^documentroot:[[:space:]]*//p' "$f" 2>/dev/null | head -n 1)
      sn=$(sed -n 's/^servername:[[:space:]]*//p' "$f" 2>/dev/null | head -n 1)
      [ -n "$dr" ] && [ -n "$sn" ] && printf '%s\t%s\n' "$dr" "$sn" >> "$DOMMAP"
    done
    if have plesk; then
      plesk db -Ne "SELECT h.www_root, d.name FROM hosting h JOIN domains d ON d.id = h.dom_id" \
        2>/dev/null >> "$DOMMAP"
    fi
    # Apache virtual hosts: ServerName and DocumentRoot inside each
    # <VirtualHost> block. This covers any Apache host, panel or not --
    # Virtualmin writes its vhosts straight into httpd.conf, and before this a
    # Virtualmin site whose root carries no domain name was never fetched.
    # Checked on Virtualmin 8.3 / AlmaLinux 9. A ServerName with a port has it
    # stripped; quoted roots are unquoted. Missing config files are skipped.
    awk 'tolower($1) == "<virtualhost" { inv = 1; sn = ""; dr = ""; next }
         inv && tolower($1) == "servername"   { sn = $2 }
         inv && tolower($1) == "documentroot" { dr = $2 }
         tolower($1) == "</virtualhost>" {
           if (sn != "" && dr != "") { gsub(/"/, "", dr); sub(/\/$/, "", dr); sub(/:[0-9]+$/, "", sn)
                                       print dr "\t" sn }
           inv = 0 }' \
      /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf \
      /etc/apache2/apache2.conf /etc/apache2/sites-enabled/* \
      /etc/apache2/conf/httpd.conf /usr/local/apache/conf/httpd.conf 2>/dev/null >> "$DOMMAP"

    # OpenLiteSpeed -- CyberPanel, or OLS on its own -- declares each virtual
    # host in httpd_config.conf (name, vhRoot) and its docRoot in a per-vhost
    # file, both written in terms of $VH_NAME / $VH_ROOT. Checked on CyberPanel
    # 3.0, including a child domain whose docRoot sits inside its parent's.
    OLSCONF=/usr/local/lsws/conf/httpd_config.conf
    if [ -f "$OLSCONF" ]; then
      for vc in /usr/local/lsws/conf/vhosts/*/vhost.conf; do
        [ -f "$vc" ] || continue
        vn=$(basename "$(dirname "$vc")")
        vr=$(awk -v n="$vn" 'tolower($1) == "virtualhost" { f = ($2 == n) }
                             f && $1 == "vhRoot" { print $2; exit }' "$OLSCONF")
        vr=${vr//\$VH_NAME/$vn}
        [ -z "$vr" ] && vr="/home/$vn"
        case "$vr" in /*) ;; *) vr="/usr/local/lsws/$vr" ;; esac
        dr=$(awk '$1 == "docRoot" { print $2; exit }' "$vc")
        dr=${dr//\$VH_ROOT/$vr}; dr=${dr//\$VH_NAME/$vn}
        dr=$(printf '%s' "$dr" | tr -s '/' | sed 's:/$::')
        dm=$(awk '$1 == "vhDomain" { print $2; exit }' "$vc")
        dm=${dm//\$VH_NAME/$vn}; dm=${dm%%,*}
        [ -z "$dm" ] && dm=$vn
        [ -n "$dr" ] && printf '%s\t%s\n' "$dr" "$dm" >> "$DOMMAP"
      done
    fi
    for r in "${ROOTS[@]}"; do
      dom=$(printf '%s\n' "$r" | sed -n 's|^/home/[^/]*/domains/\([^/]*\)/.*|\1|p')
      [ -n "$dom" ] && printf '%s\t%s\n' "$r" "$dom" >> "$DOMMAP"
    done

    # Inside this loop use echo, not log: the whole loop is piped through cap,
    # which already writes to the report, so log would record every line twice.
    # Every domain whose document root lies at or under a scanned root is
    # fetched. Matching the root exactly missed subdomains and child domains:
    # their roots sit inside the parent's, so they are not scanned roots of
    # their own, yet each is a separate site that can serve its own injection.
    for r in "${ROOTS[@]}"; do
      doms=$(awk -F'\t' -v r="$r" '$1 == r || index($1, r "/") == 1 { print $2 }' "$DOMMAP" | sort -u)
      if [ -z "$doms" ]; then
        echo "  no domain known for $r -- NOT fetched"
        continue
      fi
      for dom in $doms; do
        A="$WORK/fetch_a" ; B="$WORK/fetch_b"
        : > "$A"; : > "$B"
        # -k: a compromised site with an expired or self-signed certificate is
        # still serving its visitors, and what it serves is the question here.
        # Plain HTTP is tried when HTTPS gets no answer: a site without a
        # certificate has no 443 listener at all on OpenLiteSpeed, and HTTPS
        # only meant such a site was never checked.
        for sch in https http; do
          curl -skL --max-time 20 "$sch://$dom/" -o "$A" 2>/dev/null; rc_a=$?
          curl -skL --max-time 20 -A "$UA_M" -e 'https://www.google.com/' "$sch://$dom/" -o "$B" 2>/dev/null
          { [ -s "$A" ] || [ -s "$B" ]; } && break
        done
        if [ -s "$A" ] || [ -s "$B" ]; then
          echo "  fetched $sch://$dom/  (plain: $(wc -c < "$A" | tr -d ' ') bytes, mobile+referrer: $(wc -c < "$B" | tr -d ' ') bytes)"
          d=$(diff <(grep -oE '<script[^>]*>' "$A" 2>/dev/null | sort -u) \
                   <(grep -oE '<script[^>]*>' "$B" 2>/dev/null | sort -u) 2>/dev/null)
          [ -n "$d" ] && { echo "  CLOAKING DIFFERENCE  $dom"; printf '%s\n' "$d" | sed 's/^/    /'; }
          for pat in 'atob(' 'fromCharCode' 'documentElement.appendChild' 'navigator.clipboard'; do
            grep -qF "$pat" "$A" 2>/dev/null && echo "  $dom  serves: $pat"
            grep -qF "$pat" "$B" 2>/dev/null && echo "  $dom  serves (mobile/referrer): $pat"
          done
        else
          echo "  $dom  could NOT be fetched (curl exit $rc_a) -- nothing was checked for this site"
        fi
      done
    done | cap
  else
    sub "black-box fetch  [SKIPPED -- pass --http to enable]"
    log "  Off by default: it makes outbound requests, which during an incident may"
    log "  be blocked by your own containment or may signal that you are looking."
    log "  Enable when you need to catch injection stored outside the filesystem --"
    log "  in the database, or in web server config -- which no file scan can see."
  fi

  log ""
  log "  The only detection that does not depend on recognising the malware is a"
  log "  baseline taken while clean, compared daily. See PLAYBOOK Phase 8. It will"
  log "  not find what is already present, so take it AFTER remediation, not before."
fi

# -----------------------------------------------------------------------------
sec "18. SUMMARY"
log "panel:                      $PANEL"
log "web server:                 $WEBSRV   (.htaccess honored: $HTACCESS)"
log "webroots scanned:           ${#ROOTS[@]}"
log "signature-matched files:    $NC"
log "candidate list file:        $CAND"
log "full report:                $OUT"

# --- aggregate the artifacts collected during the run -------------------------
# Two questions get asked before any others: how many sites, and since when.
# Both were previously left for the reader to derive by scrolling a few thousand
# lines and correlating timestamps by eye, which is slow and easy to get wrong.
ALL="$WORK/all"
: > "$ALL"
sort -u "$ARTIFACTS" 2>/dev/null | grep -E '^/'   | grep -vF -e "$WORK" -e "$OUT" > "$ALL"
# Signature hits belong in the same picture.
[ -s "$CAND" ] && cat "$CAND" >> "$ALL"
sort -u "$ALL" -o "$ALL" 2>/dev/null
# grep -c prints 0 AND exits 1 on no match, so `|| echo 0` yields two lines
NART=$(grep -c . "$ALL" 2>/dev/null); NART=${NART:-0}

log ""
log "== AFFECTED ACCOUNTS =========================================="
log "artifacts collected: $NART"
if [ "${NART:-0}" -gt 0 ]; then
  # Derive the account from the path -- far cheaper than a stat per file.
  # The patterns are deliberately unanchored at the front: a webroot reached via
  # a symlink or a non-standard prefix still yields its account. Anchoring on
  # ^/home dropped every such path silently, which is the wrong failure -- an
  # artifact that cannot be attributed must still be counted somewhere.
  # Last expression is the catch-all: anything unmatched collapses to its
  # top-level directory (/tmp, /var/tmp, /dev/shm) rather than vanishing.
  sed -E -e 's|.*/home/([^/]+)/domains/.*|\1|' \
         -e 's|.*/home/([^/]+)/public_html.*|\1|' \
         -e 's|^/var/www/vhosts/([^/]+)/.*|\1|' \
         -e 's|^/home/([^/]+)/.*|\1|' \
         -e 's|^/([^/]+)/.*|/\1|' "$ALL" \
    | sort | uniq -c | sort -rn \
    | awk '{printf "  %-5s %s\n", $1, $2}' | cap
  log ""
  log "  Ranking is by artifact count, which is a proxy for how long an account has"
  log "  been worked on rather than for severity. One live backdoor outranks twenty"
  log "  emptied files -- read the accounts at the top first, but read all of them."
else
  log "  none -- see the caveat below before concluding the host is clean"
fi

log ""
log "== INTRUSION TIMELINE ========================================="
if [ "${NART:-0}" -gt 0 ]; then
  TL="$WORK/timeline"
  : > "$TL"
  # One stat invocation per batch rather than per file.
  xargs -a "$ALL" -d '\n' -r stat -c '%Y|%y|%n' 2>/dev/null | sort -n > "$TL"
  if [ -s "$TL" ]; then
    FIRST=$(head -1 "$TL" | cut -d'|' -f2 | cut -c1-19)
    LAST=$(tail -1 "$TL" | cut -d'|' -f2 | cut -c1-19)
    FEPOCH=$(head -1 "$TL" | cut -d'|' -f1)
    case "${FEPOCH:-}" in
      ''|*[!0-9]*) DAYSAGO="?" ;;      # empty or non-numeric would abort the arithmetic
      *) DAYSAGO=$(( ( $(date +%s) - FEPOCH ) / 86400 )) ;;
    esac
    log "  EARLIEST artifact:  $FIRST   (~$DAYSAGO days ago)"
    log "  LATEST artifact:    $LAST"
    log ""
    log "  The earliest timestamp is the floor on how long this has been going on,"
    log "  not the date of entry. Emptied files keep the mtime they were emptied at,"
    log "  and anything the attacker removed leaves no timestamp at all."
    log ""
    NTL=$(grep -c . "$TL" 2>/dev/null); NTL=${NTL:-0}
    if [ "${NTL:-0}" -le 24 ]; then
      # head -12 and tail -12 overlap below 24 entries, which reprints the oldest
      # rows under a "newest" heading and makes the timeline read as nonsense.
      log "  all $NTL, chronological:"
      awk -F'|' '{printf "    %s  %s\n", substr($2,1,19), $3}' "$TL" | cap
    else
      log "  oldest 12:"
      head -12 "$TL" | awk -F'|' '{printf "    %s  %s\n", substr($2,1,19), $3}' | cap
      log "  newest 12:"
      tail -12 "$TL" | awk -F'|' '{printf "    %s  %s\n", substr($2,1,19), $3}' | cap
    fi
    log ""
    log "  A cluster of timestamps within minutes of each other is one intrusion"
    log "  session. Clusters spread over months mean repeated re-entry, which means"
    log "  the way in is still open -- cleaning without closing it repeats the cycle."
  fi
else
  log "  no artifacts to date"
fi

log ""
log "== WHAT A QUIET REPORT DOES AND DOES NOT MEAN ================="
log "  Finding nothing here is not proof of a clean host. In this session's field"
log "  use, three separate defects each made a real compromise look like a clean"
log "  result: a panel misdetected from a leftover directory silently skipped the"
log "  per-user crontab check; an FTP login check written for one daemon reported"
log "  nothing on a host running the other; and 19 signature patterns all missed a"
log "  live injector because it was PHP that merely echoed obfuscated JavaScript."
log "  Corroborate with section 17's package verification (--checksums), which does"
log "  not depend on anyone having described the malware first."
log ""
log "NEXT STEPS"
log "  1. Do NOT delete yet. Archive evidence first:"
log "       tar czf /root/evidence-$STAMP.tar.gz -T $CAND"
log "  2. Review every file in the list by hand -- signatures produce false positives"
log "     (minifiers, caches, and some plugins legitimately use base64/eval)."
log "  3. Find the entry point in section 14 before cleaning, or it comes back."
log "  4. Rotate ALL credentials: panel, FTP, MySQL, SSH keys, CMS admins, API keys."
log "  5. If section 5 shows ld.so.preload, a UID-0 account, or modified system binaries,"
log "     assume root compromise -> rebuild the server, migrate only data."
rm -rf "$WORK"
echo ""
echo "Done. Report: $OUT"
