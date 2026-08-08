# Imunify360 was installed and the server still got shelled

This is the most useful question to answer when a scanner was already running. Imunify360
catches webshells well **when configured correctly**. When shells get through anyway, it is
almost always one of the causes below, ordered by how often they turn out to be responsible.

---

## 0. First: is this a blind scanner or a reinfection loop?

These two situations look identical from the outside and call for opposite responses.

| | Genuinely blind | Reinfection loop |
|---|---|---|
| Symptom | `malware malicious list` is **empty** or nearly so, while the disk is full of shells | List is **long**, `SCAN_TYPE = realtime`, `STATUS = cleanup_done/removed` |
| Meaning | The scanner is not seeing the files — misconfiguration | The scanner is working; **the vulnerability is still open** |
| Response | Fix the configuration, sections 1–6 below | **Patch the hole.** Configuration tuning is secondary |

Run this first:

```bash
imunify360-agent malware malicious list --limit 200
```

A long list of `realtime` detections means Imunify is catching uploads as fast as the attacker
makes them. No amount of configuration will stop that until the entry point is closed — go to
[PLAYBOOK.md](PLAYBOOK.md) Phase 4.

---

## 1. Proactive Defence is in `LOG` or `DISABLED` mode

> **Spelling matters.** The key is `PROACTIVE_DEFENCE` — British spelling. `PROACTIVE_DEFENSE`
> is rejected with `{'PROACTIVE_DEFENSE': ['unknown field']}`, and because that message is
> easy to skim past, people believe they changed a setting they did not. Mode values are
> uppercase: `KILL`, `LOG`, `DISABLED`.

```bash
imunify360-agent config show | grep -o '"PROACTIVE_DEFENCE":[^}]*}'
```

```bash
imunify360-agent config update '{"PROACTIVE_DEFENCE": {"mode": "KILL"}}'
```

`php_immunity` in the same group should be `true`.

> Run `KILL` for a while and check `/var/log/imunify360/console.log` for legitimate plugins
> being blocked. Do not revert to `LOG` over a single false positive — in `LOG` mode you have
> monitoring, not protection.

---

## 2. The Imunify PHP extension is not loaded for every PHP version

**The quietest failure of the six.** Proactive Defence works through a PHP extension. If the
server offers PHP 7.4, 8.0, 8.1 and 8.2 but the extension is loaded for only some of them,
every site on an uncovered version is **completely unprotected** — while the dashboard
continues to report Imunify as enabled.

Check every PHP binary on the box. The paths differ by panel and by SAPI:

```bash
for p in /usr/local/lsws/lsphp*/bin/php \
         /opt/plesk/php/*/bin/php \
         /usr/local/php*/bin/php \
         /opt/cpanel/ea-php*/root/usr/bin/php \
         /opt/alt/php*/usr/bin/php \
         /usr/bin/php; do
  [ -x "$p" ] || continue
  printf '%-52s php %-8s %s\n' "$p" "$("$p" -r 'echo PHP_VERSION;' 2>/dev/null)" \
    "$("$p" -m 2>/dev/null | grep -i imunify || echo '!! NO EXTENSION')"
done
```

Then find which version each site actually runs:

```bash
grep -h php_ver /usr/local/directadmin/data/users/*/user.conf | sort | uniq -c    # DirectAdmin
plesk bin site --list                                                             # Plesk
```

For any version missing the extension: install the hardened PHP build for it, or move those
sites onto a version that is covered.

---

## 3. Expired licence — the agent runs but signatures stop updating

The agent stays up and the dashboard renders, but the signature database froze on the day the
licence lapsed.

```bash
imunify360-agent register --status
imunify360-agent version
ls -la /var/imunify360/            # when were signature files last written?
```

If the last signature update is months old, either the licence or outbound connectivity is the
problem. Note that if you blocked outbound traffic during containment (PLAYBOOK Phase 1), you
may have blocked the vendor's update endpoints — check before concluding it is a licence issue.

---

## 4. Site directories out of scope, or on the ignore list

```bash
imunify360-agent malware ignore list
imunify360-agent config show | grep -o '"MALWARE_SCANNING":[^}]*}'
```

The ignore list is easy to forget. A previous administrator adds `/home` or `/var/www/vhosts`
to silence a false positive, and the scanner is blind from then on.

```bash
imunify360-agent malware ignore delete --path /wrong/path
```

Sites in non-standard locations (not `/home/*/domains` or `/var/www/vhosts`) may also not be
recognised as webroots at all.

---

## 5. Real-time scanning off — only scheduled scans run

Without inotify, a shell uploaded at 2am survives until the next scheduled scan.

```bash
imunify360-agent config show | grep -i inotify
imunify360-agent config update '{"MALWARE_SCANNING": {"enable_scan_inotify": true}}'
```

Also raise the kernel watch limit. The default is far too low for a busy shared host, and
inotify fails silently once exceeded — real-time scanning appears enabled and simply stops
seeing new files:

```bash
cat /proc/sys/fs/inotify/max_user_watches      # 8192 by default: not enough
echo 'fs.inotify.max_user_watches=524288' >> /etc/sysctl.conf && sysctl -p
```

---

## 6. WebShield disabled

```bash
imunify360-agent config show | grep -o '"WEBSHIELD":[^}]*}'
imunify360-agent config update '{"WEBSHIELD": {"enable": true}}'
```

> WebShield inserts a reverse proxy in front of the web server and changes how ports are
> handled. It is the highest-risk Imunify setting to change on a production box. Do it as a
> planned change with a rollback, not in the middle of an incident.

---

## 7. ModSecurity ruleset left at `MINIMAL` — the most overlooked cause

Imunify ships its own ModSecurity, but the ruleset may be `MINIMAL`: a handful of basic rules
that **do not block CMS plugin or component exploits**. This is why an exploit request reaches
the application untouched while the dashboard shows ModSecurity as active.

```bash
imunify360-agent config show | grep -o '"MOD_SEC":[^}]*}'
imunify360-agent config update '{"MOD_SEC": {"ruleset": "FULL"}}'
imunify360-agent config update '{"MOD_SEC": {"cms_account_compromise_prevention": true}}'
```

This matters even more on **OpenLiteSpeed and nginx**, where `.htaccess` mitigation does not
exist — there ModSecurity is your only web-layer control. See [MITIGATION.md](MITIGATION.md).

Watch for false positives for a few days after enabling:

```bash
tail -f /var/log/imunify360/console.log
imunify360-agent incidents list --limit 50
```

---

## 8. Other settings commonly left at unhelpful defaults

```bash
# scan FTP uploads -- off by default, and DirectAdmin serves FTP through pure-ftpd
imunify360-agent config update '{"MALWARE_SCANNING": {"enable_scan_pure_ftpd": true}}'

# brute-force protection for FTP
imunify360-agent config update '{"PAM": {"ftp_protection": true}}'

# background scan daily instead of weekly
imunify360-agent config update '{"MALWARE_SCAN_SCHEDULE": {"interval": "day"}}'

# alert on detection
imunify360-agent config update '{"MALWARE_SCANNING": {"notify_on_detect": true}}'

# block shells connecting straight out to port 25
imunify360-agent config update '{"SMTP_BLOCKING": {"enable": true}}'
```

Two cautions for a production server mid-incident:

**`SMTP_BLOCKING`** breaks any application using an external SMTP relay — SendGrid, Mailgun,
SES. Customers lose order confirmations and password resets. Inventory those first, or add the
accounts to `allow_users`.

**`notify_on_detect`** during an active infection with hundreds of detections produces an email
flood that can get your mail server's reputation damaged. Enable it *after* the cleanup, not
during.

---

## 9. Cleanup mode: `trim` or `remove`?

```bash
imunify360-agent config show | grep -o '"MALWARE_CLEANUP":[^}]*}'
```

With `trim_file_instead_of_removal: true` a cleaned file is **emptied but left on disk**. In
`malware malicious list`:

- `STATUS = cleanup_done` → the file is still there, contents stripped
- `STATUS = cleanup_removed` → the file was deleted

`keep_original_files_days` controls how long the quarantined original survives — **this is your
sample source for analysis.** Once past that window the evidence is gone permanently, so if you
intend to analyse anything, collect it before the retention period expires.

---

## Do not rely on Imunify alone

Imunify360 does not check most of what section 5 of `webshell-triage.sh` covers: user crontabs,
unfamiliar systemd units, added SSH keys, `.forward` backdoors, `/etc/ld.so.preload`. It focuses
on malicious files inside the webroot.

On a server that has been shelled, persistence tends to live in exactly those places. Imunify
cleans the webroot, the cron entry pulls the shell back ten minutes later, and the loop looks
like a detection failure when it is a coverage gap. **Run both.**

---

## Checklist

```
[ ] Established which situation this is: blind scanner vs reinfection loop
[ ] PROACTIVE_DEFENCE mode = KILL   (note the spelling, and the uppercase value)
[ ] php_immunity = true
[ ] Imunify PHP extension loaded for EVERY installed PHP version
[ ] Licence valid, signatures updated recently
[ ] Ignore list does not contain a webroot
[ ] enable_scan_inotify = true, and max_user_watches raised
[ ] MOD_SEC ruleset = FULL, not MINIMAL
[ ] enable_scan_pure_ftpd = true
[ ] Understood what cleanup_done vs cleanup_removed means before reading the report
[ ] Quarantined originals collected before keep_original_files_days expires
[ ] Ran webshell-triage.sh for the persistence surface Imunify does not cover
```
