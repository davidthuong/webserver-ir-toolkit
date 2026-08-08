# Collecting samples for analysis

## Your antivirus will delete the samples

Windows Defender deleted three webshell test files the moment they were written to disk during
development of this toolkit, and locked two others with `Permission denied`. Copying a real
shell to a workstation with a `.php` extension will very likely destroy it before you can read
it — and the deletion is sometimes silent.

**Rename on the server, before transferring:**

```bash
mkdir -p /root/for-analysis
cp /path/to/shell.php /root/for-analysis/shell1.php.txt
cp /path/to/another.PHP /root/for-analysis/shell2.php.txt
```

If files still disappear, add the destination folder to your AV exclusions, or paste the file
contents into a text editor rather than transferring the file at all.

---

## Metadata matters as much as content

For attribution, the timestamps are often more useful than the payload — they are what you
correlate against access logs to find the entry point. Capture them **before** anything touches
the files:

```bash
cd /root/for-analysis
for f in /path/to/shell.php /path/to/another.PHP; do
  stat -c '%n | size=%s | mtime=%y | ctime=%z | owner=%U:%G | perm=%a' "$f"
  sha256sum "$f"
done > metadata.txt
```

`mtime` is when the content was last written — the upload time. `ctime` is when the inode last
changed. If `ctime` is much later than `mtime`, something touched the file after upload, which
often means an attempt to backdate it.

Identical hashes across many files tell you the same payload was written under multiple names or
extensions — usually an automated probe testing which extension the server will execute.

---

## Pull the access log window around the shell's mtime

This is the single most valuable artifact and the easiest one to lose to log rotation:

```bash
stat -c '%y' /path/to/shell.php      # e.g. 2026-08-05 14:23

# DirectAdmin
grep '05/Aug/2026:1[2-6]' /var/log/httpd/domains/site.com.log > /root/for-analysis/access-window.log
# Plesk
grep '05/Aug/2026:1[2-6]' /var/www/vhosts/system/site.com/logs/access_log > /root/for-analysis/access-window.log
# cPanel
grep '05/Aug/2026:1[2-6]' /usr/local/apache/domlogs/site.com > /root/for-analysis/access-window.log
# LiteSpeed / OpenLiteSpeed standalone
grep '05/Aug/2026:1[2-6]' /usr/local/lsws/logs/access.log > /root/for-analysis/access-window.log
```

Include POST requests even when they look unremarkable. Exploit parameters travel in the request
body, which the access log does not record — so the giveaway is often just a `POST` to
`index.php` at the right second, with nothing else to distinguish it.

---

## If a scanner already quarantined the files

Commercial scanners keep originals for a limited window, and that window is a deadline.

```bash
imunify360-agent config show | grep -o '"MALWARE_CLEANUP":[^}]*}'   # keep_original_files_days
imunify360-agent malware malicious list --limit 5000 > /root/for-analysis/imunify-full.txt
du -sh /var/imunify360/* 2>/dev/null
```

With `trim_file_instead_of_removal: true`, files marked `cleanup_done` are still on disk with
their contents stripped — the filename and metadata survive even though the payload is gone.

---

## What to record alongside the files

An analysis is only as good as the context. Note down:

1. **Server**: OS and version, panel, **which web server actually serves requests**
   (`ss -ltnp | grep -E ':(80|443)'` — do not assume from installed binaries)
2. **Application**: WordPress, Joomla, Laravel, custom? Which version? Which plugins,
   components or themes, and at what versions?
3. **Discovery**: how did you find out? Google Search Console warning, host complaint about
   spam, site defacement, disk filling up? Each points at a different attacker goal.
4. **Timeline**: when did the site last work normally? That bounds the search window.

---

## Handling

Treat collected samples as live malware for as long as you have them.

- Keep them outside any webroot — `/root/for-analysis` is fine, `public_html` is not
- Never commit them to a repository. `samples/` in this repo is gitignored; pushing malware to a
  public host distributes it and gets accounts suspended
- Do not attach them to issues or email. If a signature gap needs demonstrating, write a
  minimal synthetic reproduction instead — see [SECURITY.md](../../SECURITY.md)
- Delete them when the analysis is finished
