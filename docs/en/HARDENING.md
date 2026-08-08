# Hardening a shared-hosting server after a compromise

Ordered by effect over effort. The first five items stop the great majority of reinfections.

---

## 0. Is the OS still receiving security patches?

This is background risk that no configuration change fixes, and it is worth checking before
anything else, because the answer can change your whole plan.

```bash
cat /etc/redhat-release 2>/dev/null; cat /etc/os-release | grep PRETTY
uname -r
rpm -q kernel 2>/dev/null | tail -3          # how recent is the newest kernel?
yum list installed 2>/dev/null | grep -iE 'els|extended'
yum history 2>/dev/null | head -6            # or: apt list --upgradable
```

**CentOS 7 reached end of life on 2024-06-30.** CentOS 8 ended earlier still, in 2021.
On an EOL release the kernel, glibc and OpenSSL receive no upstream patches, and the knock-on
effects widen the attack surface further: Plesk, DirectAdmin and cPanel have all dropped
support for CentOS 7, which pins the panel to an old version, which in turn pins the PHP
versions you can build.

Three options, in the order usually worth taking:

| | Approach | Upside | Downside |
|---|---|---|---|
| **A** | Extended support subscription (e.g. CloudLinux ELS for CentOS 7) | Security patches resume within hours; nothing to migrate | Per-server cost. A bridge, not a fix — the panel and PHP stay pinned |
| **B** | Fresh server on a supported OS (AlmaLinux, Rocky, Debian, Ubuntu LTS) then migrate | Genuinely current. After a compromise it has a second benefit: the new host carries no backdoor | Planned downtime and real work |
| **C** | ~~In-place major upgrade (ELevate and similar)~~ | — | **Not with a control panel.** Unsupported by Plesk and DirectAdmin; a failure takes the whole server |

A now, B within one to three months, is a reasonable path.

Migration tooling: Plesk has the **Plesk Migrator** extension; DirectAdmin has Admin
Backup/Transfer; cPanel has the Transfer Tool.

> **When migrating after a security incident, move data only — never code.** A faithful
> migration carries the shells across with it. Reinstall the CMS, plugins and themes from
> official sources, and bring over only `uploads/` and the database.

Also raise the inotify watch limit. The default of 8192 is far too low for a server with many
sites, and it makes real-time scanners fail silently once exceeded:

```bash
cat /proc/sys/fs/inotify/max_user_watches
echo 'fs.inotify.max_user_watches=524288' >> /etc/sysctl.conf && sysctl -p
```

---

## 1. Block PHP execution in upload directories

The single most effective measure. Shells land in `uploads/`, `images/`, `cache/`, `tmp/` and
`media/` far more often than anywhere else.

**The correct recipe depends on your web server, and the wrong one fails silently.** Full
detail with a verification step is in **[MITIGATION.md](MITIGATION.md)** — read that before
deploying. In short:

| Web server | Reads `.htaccess`? |
|---|---|
| Apache, LiteSpeed Enterprise | Yes (Apache additionally depends on `AllowOverride`) |
| **OpenLiteSpeed, nginx** | **No** — `.htaccess` is ignored entirely |

Apache and LiteSpeed Enterprise:

```apache
<FilesMatch "(?i)\.(php|php[0-9]|phtml|phtm|pht|phar|phps|cgi|pl|py|shtml)$">
    Require all denied
</FilesMatch>
```

The `(?i)` prefix is **mandatory**. `<FilesMatch>` is case-sensitive by default, and uploading
`shell.PHP` with an uppercase extension to defeat `\.php$` is standard practice, not a
hypothetical.

Do not add `php_flag engine off` — that is a mod_php directive and returns **500** under
PHP-FPM or a LiteSpeed SAPI.

nginx:

```nginx
location ~* ^/(uploads|files|images|cache|tmp|media|logs)/.*\.(php[0-9]?|phtml?|phar|phps)$ {
    deny all;
}
```

OpenLiteSpeed — vhost Rewrite Rules, since `.htaccess` will not work:

```apache
RewriteRule ^(tmp|cache|logs|uploads|images)/.*\.(php|php[0-9]|phtml|phtm|phar|phps)$ - [F,L,NC]
```

Then **verify it**, with an uppercase extension:

```bash
printf '<?php echo "EXECUTED"; ?>' > /path/to/public_html/tmp/zz-ir-probe.PHP
curl -sS https://site.com/tmp/zz-ir-probe.PHP    # must be 403/404, never "EXECUTED"
rm -f /path/to/public_html/tmp/zz-ir-probe.PHP
```

---

## 2. `disable_functions` and `open_basedir`

A shell loses most of its usefulness when it cannot execute commands.

```ini
; php.ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,proc_close,proc_get_status,proc_nice,proc_terminate,pcntl_exec,pcntl_fork,dl,curl_multi_exec,posix_kill,posix_setuid,posix_setpgid,posix_setsid,show_source,symlink,link,escapeshellcmd,escapeshellarg
allow_url_include = Off
allow_url_fopen  = Off      ; check first -- some plugins need it
expose_php       = Off
```

> `mail()` usually has to stay. If a site does not send mail, disable it there and the spam
> path closes completely. Some plugins use `curl_multi_exec` legitimately — test before rolling
> this out.

**`open_basedir`** stops a shell reading across into other users' home directories, which is
what matters most on shared hosting.

- DirectAdmin: Admin Settings → php-fpm/open_basedir, or per-user in the pool config
- Plesk: Domains → PHP Settings → `open_basedir` = `{WEBSPACEROOT}{/}{:}{TMP}{/}`
- cPanel: MultiPHP INI Editor, or per-account in the FPM pool

Confirm it actually applied — **FPM values differ from CLI**, and checking only CLI is a common
way to believe a setting is live when it is not:

```bash
php -i | grep -E 'disable_functions|open_basedir'      # CLI only
# then request a phpinfo() page through the web server and compare
```

---

## 3. A separate PHP-FPM pool per user

If every site runs in one pool as `apache` or `nginx`, a single shell means every site on the
server is reachable. This is the cause of nearly every "cross-contamination" case.

- **DirectAdmin**: CustomBuild `php1_mode=php-fpm`; each user gets a pool under
  `/usr/local/php*/etc/php-fpm.d/`. Verify with `ps aux | grep php-fpm` — you should see many
  different users.
- **Plesk**: Domains → Hosting Settings → PHP → **FPM application served by nginx/Apache**,
  not the shared "FastCGI application served by Apache".
- **cPanel**: MultiPHP Manager → PHP-FPM per account.

Alongside this: application files must be owned by the **site user**, never by the web server
user. A `.php` file whose `stat -c %U` returns `apache` or `www-data` means the web server can
write to your code, which is exactly what makes shell upload trivial.

```bash
chown -R user:user /home/user/domains/site.com/public_html
find /home/user/domains/site.com/public_html -type d -exec chmod 755 {} \;
find /home/user/domains/site.com/public_html -type f -exec chmod 644 {} \;
```

---

## 4. ModSecurity with a real ruleset

Blocks exploits at the HTTP layer, including against plugins you have not patched yet. This
matters most on OpenLiteSpeed and nginx, where per-directory `.htaccess` mitigation is not
available — there it is your main web-layer defense rather than a supplement.

```bash
# DirectAdmin (CustomBuild)
cd /usr/local/directadmin/custombuild
./build set modsecurity yes
./build set modsecurity_ruleset comodo      # or owasp
./build modsecurity && ./build modsecurity_rules
./build restart_apache
```

Plesk: Tools & Settings → **Web Application Firewall (ModSecurity)** → enable, ruleset
**Comodo** or **OWASP CRS**, mode **On**. "Detection only" is for a one- to two-week tuning
period, not a destination.

**Check which ruleset is actually loaded, not just that the module is on.** A minimal ruleset
passes CMS component exploits straight through while the dashboard reports ModSecurity as
enabled. If you use Imunify360:

```bash
imunify360-agent config show | grep -o '"MOD_SEC":[^}]*}'
imunify360-agent config update '{"MOD_SEC": {"ruleset": "FULL"}}'
```

After enabling, watch `/var/log/httpd/modsec_audit.log` for a few days and tune false
positives rather than switching the whole thing off when one site breaks.

---

## 5. Firewall, fail2ban, rate limiting

```bash
cd /usr/src && wget https://download.configserver.com/csf.tgz
tar -xzf csf.tgz && cd csf && sh install.sh
csf -e
```

In `/etc/csf/csf.conf`:

```ini
TESTING = "0"
LF_SSHD = "3"
LF_FTPD = "5"
PT_LIMIT = "200"       # alert on CPU-heavy processes -- catches miners
PT_USERPROC = "15"
LF_DIRWATCH = "300"    # watch /tmp
SMTP_BLOCK = "1"       # stop PHP opening port 25 directly -- cuts spam at the source
```

`SMTP_BLOCK = 1` is unusually effective: spam shells typically connect straight out to port 25,
bypassing the local mail server entirely.

> It also breaks any application legitimately using an external SMTP relay (SendGrid, Mailgun,
> Amazon SES). Inventory those first, then whitelist them.

Restrict panel access by IP (DirectAdmin 2222, Plesk 8443, cPanel 2087):

```bash
csf -a <your-ip>
# then remove 2222 / 8443 / 2087 from TCP_IN and allow only the allow-list
```

---

## 6. Panel security

- **2FA** for every admin and reseller account: DirectAdmin → User Level → Two-Step Auth;
  Plesk → My Profile → 2FA; cPanel → WHM → Two-Factor Authentication
- Move the panel off its default port — this reduces automated scanning noise, and is not
  security in itself
- DirectAdmin: Admin Settings → Enable IP whitelist for admin logins
- Plesk: Tools & Settings → Security Policy → forbid weak passwords, enable
  **Restrict administrative access** by IP
- **Turn off services nobody uses.** If no one needs FTP, disable pure-ftpd/proftpd and use
  SFTP. FTP transmits credentials in plaintext and is the largest single source of credential
  leaks in shared hosting.

---

## 7. Automatic updates

Most compromises come from an outdated plugin, not a zero-day.

```bash
wp plugin auto-updates enable --all --allow-root
wp theme auto-updates enable --all --allow-root
```

- DirectAdmin: CustomBuild `./build set autover yes`, plus a cron running
  `./build update && ./build all d`
- Plesk: Tools & Settings → Update and Upgrade Settings → auto-install security patches
- Plesk **WP Toolkit**: enable *Smart Updates* and *Security measures* across all sites — for
  this problem it is the most valuable feature Plesk ships
- cPanel: WHM → Update Preferences → security updates automatic
- OS: `dnf-automatic`, or `unattended-upgrades` on Debian/Ubuntu

**Remove nulled themes and plugins.** Pirated commercial themes are the leading source of
pre-installed backdoors, and no patch fixes them because the backdoor is the product. Either
buy a licence or replace the theme.

---

## 8. Backups you can actually rely on

A backup stored on the same server is encrypted or deleted along with it.

- Keep **14 days or more**, offsite, with at least one **immutable** or pull-based copy — the
  backup host reaches in and pulls, and the web server has no credentials to write or delete
- **Test a real restore at least once.** An untested backup is not a backup
- DirectAdmin: Admin Backup/Transfer → remote FTP/SFTP
- Plesk: Tools & Settings → Backup Manager → remote storage
- cPanel: WHM → Backup Configuration → remote destination

---

## 9. Monitoring

```bash
yum install -y inotify-tools      # or: apt install inotify-tools
cat > /usr/local/bin/watch-php.sh <<'EOF'
#!/bin/bash
inotifywait -m -r -e create,moved_to --format '%w%f' \
  /home/*/domains/*/public_html 2>/dev/null \
  | while read f; do
      case "$f" in *.php|*.PHP|*.phtml|*.phar|*.pht)
        echo "$(date) NEW: $f" >> /var/log/new-php.log
        mail -s "New PHP file on $(hostname)" you@example.com <<< "$f" ;;
      esac
    done
EOF
chmod +x /usr/local/bin/watch-php.sh
```

Note the `*.PHP` case in that pattern — uppercase extensions are the norm in real uploads, and
a lowercase-only match misses them.

Alongside: periodic rootkit checks (`rkhunter --check`, `chkrootkit`), and a weekly cron running
`webshell-triage.sh` with the report mailed out.

---

## Short checklist

```
[ ] OS still receiving security patches, or extended support purchased, or migration planned
[ ] fs.inotify.max_user_watches raised to 524288
[ ] Scanner config verified, not assumed -- see IMUNIFY360.md; do this before anything below
[ ] ModSecurity ruleset is a real one (FULL/OWASP/Comodo), mode On, not detection-only
[ ] PHP execution blocked in uploads/ cache/ images/ tmp/ media/ on every vhost
[ ] That block VERIFIED by curl, using an uppercase .PHP probe file
[ ] Block written where a panel rebuild will not erase it
[ ] disable_functions + open_basedir applied to FPM, not just CLI
[ ] Separate PHP-FPM pool per user
[ ] Code owned by the site user, NOT apache/nginx/www-data
[ ] CSF with SMTP_BLOCK=1 and LF_SSHD, external SMTP relays whitelisted first
[ ] Panel: 2FA, IP restriction, non-default port
[ ] FTP disabled in favour of SFTP, or FTPS enforced at minimum
[ ] CMS/plugin/theme auto-updates enabled
[ ] All nulled themes and plugins removed
[ ] Offsite backups, 14+ days, restore tested
```
