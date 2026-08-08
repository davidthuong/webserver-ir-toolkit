# Webshell / malware response playbook

The order of these phases matters. The most common and most costly mistake is **deleting
shells before finding how they got in** — the attacker re-uploads within hours, and you have
destroyed the evidence that would have told you where the hole is.

---

## Phase 0 — Before touching anything

| Do | Don't |
|---|---|
| Preserve evidence before deleting | `rm -rf` the moment you see a strange file |
| Assume every credential on the box is compromised | Change the panel password and call it done |
| Find the entry point, then clean | Clean the shells without patching the hole |
| Actively check for root compromise | Assume "it's just a web-layer thing" |

### When cleanup is pointless and you must rebuild

```bash
cat /etc/ld.so.preload 2>/dev/null && echo "!!! ROOTKIT"   # must be empty or absent
awk -F: '$3==0' /etc/passwd                                 # only root may appear
rpm -Va coreutils util-linux openssh-server bash procps-ng  # must return nothing
ls -la /root/.ssh/authorized_keys 2>/dev/null
for p in /proc/[0-9]*; do readlink $p/exe; done | grep -E 'deleted|^/tmp|^/dev/shm'
lsmod | tail -20                                            # unexpected kernel modules
```

Any of these means the host is untrustworthy: `/etc/ld.so.preload` has contents, a UID 0
account other than `root` exists, `rpm -Va` reports modified system binaries, a process runs
from a deleted binary and cannot be killed, or `ps`/`netstat` disagree with `/proc`.

At that point no amount of file deletion is reliable. Build a fresh server and migrate **data
only** — verified static files and a database dump. Never migrate code from a compromised host.

---

## Phase 1 — Contain (do this first, before scanning)

The goal is to cut the attacker's control while keeping the machine running. **Do not reboot** —
you lose volatile evidence, and on many hosts you lose logs that were never flushed.

```bash
# cut common mining pool ports and stop the web user from initiating outbound connections
iptables -I OUTPUT -p tcp --dport 3333:5555 -j DROP
iptables -I OUTPUT -m owner --uid-owner apache -p tcp --syn -j DROP   # adjust user: apache, nobody, nginx, lsadm

# stop outbound mail if the box is spamming -- keep the queue as evidence, do not flush it
systemctl stop exim      # DirectAdmin
systemctl stop postfix   # Plesk, cPanel, generic
```

To block web access while still collecting logs:

| Stack | How |
|---|---|
| DirectAdmin | Point the document root at a static maintenance page |
| Plesk | Domains → Hosting Settings → disable PHP support (kills PHP shells, HTTP logging continues) |
| cPanel | Suspend the account, or `.htaccess` with `Require ip <your-ip>` |
| Any | Firewall to allow only your own IP to port 80/443 |

**Do not rotate credentials yet.** Doing it now tells the attacker you have noticed, before you
have closed the way in. Credentials come in Phase 6.

---

## Phase 2 — Collect evidence

```bash
mkdir -p /root/ir-$(date +%F) && cd /root/ir-$(date +%F)

# volatile state -- gone after a reboot
ps auxfww                > ps.txt
ss -antup                > sockets.txt
lsof -nP                 > lsof.txt 2>/dev/null
for p in /proc/[0-9]*; do echo "$p -> $(readlink $p/exe)"; done > proc_exe.txt
crontab -l               > cron_root.txt 2>/dev/null
cp -a /var/spool/cron    ./spool_cron
last -F                  > last.txt
ip route                 > routes.txt

# copy logs before rotation eats them
tar czf logs.tar.gz /var/log/httpd /var/log/nginx /var/log/apache2 /var/log/secure \
                    /var/log/auth.log /var/log/exim /var/log/maillog \
                    /var/log/directadmin /var/log/plesk /usr/local/lsws/logs \
                    /var/www/vhosts/system/*/logs /usr/local/apache/domlogs 2>/dev/null
```

**Record the mtime of every suspicious file.** That timestamp is what you will correlate
against access logs in Phase 4, and it is the first thing lost if anyone touches the file.

```bash
stat -c '%n | size=%s | mtime=%y | ctime=%z | owner=%U:%G | perm=%a' /path/to/shell.php
sha256sum /path/to/shell.php
```

If a commercial scanner already quarantined files, its retention window is a deadline. Imunify360
keeps originals for `keep_original_files_days` (default 14) — after that the evidence is gone
permanently. Collect it now, not later.

---

## Phase 3 — Scan

```bash
sed -i 's/\r$//' webshell-triage.sh          # only if copied from Windows
sudo bash webshell-triage.sh --days 60
```

Read-only. Output goes to `/root/triage-<host>-<time>.txt`.

Read in this order: **section 2B** (which web server actually serves requests — this determines
every containment option you have) → **section 5** (persistence, the most serious) →
**section 6** (shells) → **section 14** (entry point).

### If a scanner is already installed

A server that got shelled *with* Imunify360 or maldet running is telling you something. Check
which of the two situations you are in before spending time on configuration:

```bash
imunify360-agent malware malicious list --limit 200
```

**A long list, mostly `SCAN_TYPE = realtime`** — the scanner is working. Files keep appearing
because the vulnerability is still open. This is a reinfection loop; skip to Phase 4 and patch.
Tuning the scanner will not help.

**An empty list against a disk full of shells** — the scanner is blind. See
[IMUNIFY360.md](IMUNIFY360.md) for the six causes and how to check each.

```bash
imunify360-agent malware on-demand start --path /home              # DirectAdmin, cPanel
imunify360-agent malware on-demand start --path /var/www/vhosts    # Plesk
```

### Free alternatives

```bash
wget -q http://www.rfxn.com/downloads/maldetect-current.tar.gz
tar xf maldetect-current.tar.gz && cd maldetect-* && ./install.sh
maldet -u
maldet -a /home/?/domains/?/public_html      # DirectAdmin
maldet -a /var/www/vhosts/?/httpdocs         # Plesk
maldet -a /home/?/public_html                # cPanel
maldet --report list                          # results only, nothing deleted
```

**Every automated scanner shares the same blind spot.** They look at files in the webroot. They
do not look at user crontabs, systemd units, added SSH keys, `.forward` backdoors, or
`/etc/ld.so.preload`. A cleanup that misses the cron entry is undone in ten minutes. Section 5
of `webshell-triage.sh` covers that surface.

---

## Phase 4 — Find the entry point

Skip this and roughly nine out of ten servers get reinfected. Four sources account for almost
every case.

### 1. Vulnerable CMS plugin, theme or component — by far the most common

```bash
# get the shell's mtime, then read the access log around it
stat -c '%y %n' /path/to/shell.php          # e.g. 2026-08-05 14:23

# then pull the window either side of that moment
grep '05/Aug/2026:1[2-6]' /var/log/httpd/domains/site.com.log | grep -E '"(GET|POST) '
```

Look for a POST to a plugin or component file **immediately before** the shell appears. That is
the vulnerability.

CMS exploits route through predictable parameters, so these are worth grepping directly:

```bash
grep -hoiE 'option=com_[a-z0-9_]+&[a-z]*task=[a-z0-9_.]+' <logs> | sort | uniq -c | sort -rn
grep -hoiE '/wp-content/plugins/[a-z0-9_-]+/[^ "]*\.php' <logs> | sort | uniq -c | sort -rn
```

**Status codes are informative.** A `500` on such a request usually means the component exists
and the endpoint is reachable — the site is very likely still vulnerable. A `404` means it is
not installed on that vhost.

**A critical caveat.** Real exploitation is usually a `POST` with parameters in the request
**body**, which access logs do not record. Only GET-style probes are visible to the greps above.
A quiet result is not evidence of no exploitation — correlate POST requests by timestamp against
file mtimes instead:

```bash
grep -h 'POST /index.php' <log> | grep '05/Aug/2026'
```

Then check the installed version against the vendor advisory. For Joomla components the version
is in the component XML; for WordPress use `wp plugin list` and [wpscan.com/plugins](https://wpscan.com/plugins).

```bash
for x in /home/*/domains/*/public_html/administrator/components/com_*/[a-z]*.xml; do
  [ -f "$x" ] && printf '%-10s %s\n' "$(sed -n 's:.*<version>\(.*\)</version>.*:\1:p' "$x" | head -1)" "$x"
done
```

### 2. Stolen FTP or panel credentials — usually an infostealer on a developer's machine

```bash
grep 'OK LOGIN' /var/log/pureftpd.log | awk '{print $NF}' | sort | uniq -c | sort -rn
grep 'Accepted' /var/log/secure | awk '{print $9, $11}' | sort | uniq -c
```

A successful login from an unexpected country means credential theft, not a code
vulnerability — and patching the site will not help. Every machine holding those credentials
needs to be scanned.

### 3. Cross-user contamination on a shared host

If several users have the same shell but run entirely different applications, the PHP
configuration is letting one account read another. See [HARDENING.md](HARDENING.md) on
`open_basedir` and per-user PHP-FPM pools.

### 4. Unpatched panel or service

```bash
/usr/local/directadmin/directadmin v
plesk version
/usr/local/cpanel/cpanel -V
```

---

## Phase 5 — Clean

In order of preference:

**A. Restore from a known-good backup.** Fastest and most trustworthy, if you can date the
infection and have a backup from before it. Restore **code**; keep the current database after
checking it.

**B. Reinstall core, plugins and themes; keep only uploads.**

```bash
wp core download --force --allow-root
wp plugin install $(wp plugin list --field=name) --force --allow-root
wp core verify-checksums --allow-root
```

Then check by hand: `wp-config.php`, every `.htaccess`, and `uploads/` (images only).

**C. Delete file by file** — only when A and B are impossible, and only after archiving
evidence.

```bash
tar czf /root/evidence.tar.gz -T /tmp/candidate-list.txt
xargs -a /tmp/candidate-list.txt rm -v -f
```

### Commonly missed hiding places

- **Database**: `wp_options` (`siteurl`, `home`), `<script>` in `wp_posts`, unexpected admins in `wp_users`
- `wp-config.php` / `configuration.php` with an `include` of an unfamiliar file at the top
- `.htaccess` in **every** directory, not just the root
- User crontabs: `crontab -l -u <user>`
- `.ico`, `.png`, `.jpg` files containing `<?php`
- A single appended `eval` line at the end of `index.php`
- Files whose only change is an added `auto_prepend_file` in `.user.ini`

---

## Phase 6 — Rotate every credential

After cleaning, before reopening. Assume everything readable in config files and the database
has been read.

- [ ] Panel passwords — **all** users, not only the infected one
- [ ] FTP passwords, and delete unfamiliar FTP accounts
- [ ] MySQL password per site, then update the application config
- [ ] SSH: remove unknown `authorized_keys`, rotate keys, set `PasswordAuthentication no`
- [ ] CMS admin passwords; delete unknown accounts (`wp user list`)
- [ ] WordPress salts: `wp config shuffle-salts` — invalidates every logged-in session
- [ ] API, SMTP and payment keys stored in config files
- [ ] Root password
- [ ] Mailbox passwords for every account on the server

---

## Phase 7 — Harden

See [HARDENING.md](HARDENING.md). Minimum: block PHP execution in upload directories (using the
recipe for **your** web server — see [MITIGATION.md](MITIGATION.md)), `disable_functions`,
ModSecurity with a real ruleset, firewall plus fail2ban, and 2FA on the panel.

---

## Phase 8 — Watch for reinfection

Take a baseline once clean, then compare daily for two to four weeks.

```bash
find /home/*/domains/*/public_html -type f \( -name '*.php' -o -name '.htaccess' \) \
  -exec sha256sum {} \; | sort > /root/baseline.sha256

cat > /root/check-drift.sh <<'EOF'
#!/bin/bash
find /home/*/domains/*/public_html -type f \( -name '*.php' -o -name '.htaccess' \) \
  -exec sha256sum {} \; | sort > /tmp/now.sha256
diff /root/baseline.sha256 /tmp/now.sha256 > /tmp/drift.txt
[ -s /tmp/drift.txt ] && mail -s "FILE DRIFT on $(hostname)" you@example.com < /tmp/drift.txt
EOF
chmod +x /root/check-drift.sh
(crontab -l 2>/dev/null; echo '0 3 * * * /root/check-drift.sh') | crontab -
```

> Note the `crontab -l` prefix — `echo ... | crontab -` on its own **replaces** the existing
> crontab rather than adding to it.

Re-run `webshell-triage.sh` at 48 hours and at one week. If shells come back, the entry point
found in Phase 4 was not the real one.

---

## Path quick reference

| | DirectAdmin | Plesk | cPanel |
|---|---|---|---|
| Webroot | `/home/<user>/domains/<domain>/public_html` | `/var/www/vhosts/<domain>/httpdocs` | `/home/<user>/public_html` |
| Access log | `/var/log/httpd/domains/<domain>.log` | `/var/www/vhosts/system/<domain>/logs/access_log` | `/usr/local/apache/domlogs/<domain>` |
| Error log | `/var/log/httpd/domains/<domain>.error.log` | `…/logs/error_log` | `/usr/local/apache/logs/error_log` |
| Panel log | `/var/log/directadmin/` | `/var/log/plesk/panel.log` | `/usr/local/cpanel/logs/` |
| User crontab | `/usr/local/directadmin/data/users/<u>/crontab.conf` | `plesk db "SELECT * FROM ScheduledTasks"` | `/var/spool/cron/<user>` |
| User list | `/usr/local/directadmin/data/users/` | `plesk bin subscription --list` | `/etc/trueuserdomains` |
| PHP config | `/usr/local/php*/lib/php.ini` | `/opt/plesk/php/<ver>/etc/php.ini` | `/opt/cpanel/ea-php<ver>/root/etc/php.ini` |
| Mail | exim, `/var/log/exim/mainlog` | postfix, `/var/log/maillog` | exim, `/var/log/exim_mainlog` |
| Reload web | `systemctl restart httpd` | `plesk sbin httpdmng --reconfigure-all` | `/scripts/restartsrv_httpd` |

**LiteSpeed / OpenLiteSpeed** keep their own logs in `/usr/local/lsws/logs/`, though DirectAdmin
continues to write per-domain logs to `/var/log/httpd/domains/` regardless of which web server
serves the request. **CyberPanel** uses `/home/<domain>/logs/`.
