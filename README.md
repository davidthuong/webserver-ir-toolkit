# Web Server Incident Response Toolkit

Read-only triage tooling and field procedures for shared-hosting servers compromised by
webshells — DirectAdmin, Plesk, cPanel, or no panel at all, across Apache, nginx,
OpenLiteSpeed and LiteSpeed Enterprise.

**Nothing in this repository deletes, moves, chmods or edits a single file on the server
being examined.** The scanner reads and writes one report. Every destructive step is left to
a human who has read the report.

🇻🇳 **[Tài liệu tiếng Việt](docs/vi/README.md)**

---

## Why another one of these

Most webshell guides stop at "run a scanner and delete what it finds". That advice loses to
the two things that actually determine whether a server stays clean:

**Persistence outside the webroot.** Imunify360, maldet and ClamAV look at files in the
webroot. They do not look at user crontabs, systemd units, `authorized_keys`, `.forward`
files, or `/etc/ld.so.preload`. A cleanup that misses the cron entry is undone in ten
minutes.

**The entry point.** Deleting shells without finding the upload path is a loop, not a fix.
The toolkit correlates access logs against file mtimes to locate the vulnerability that let
the files in.

And one trap that wastes more responder time than any other: writing `.htaccess` rules on a
web server that never reads `.htaccess`. See [MITIGATION.md](docs/en/MITIGATION.md).

---

## Contents

| Document | Purpose |
|---|---|
| [webshell-triage.sh](webshell-triage.sh) | Read-only scanner, 20 sections |
| [PLAYBOOK.md](docs/en/PLAYBOOK.md) | 8-phase response procedure, in order |
| [MITIGATION.md](docs/en/MITIGATION.md) | Blocking PHP execution — the correct recipe per web server |
| [HARDENING.md](docs/en/HARDENING.md) | Prevention, ranked by effect over effort |
| [IMUNIFY360.md](docs/en/IMUNIFY360.md) | Why a server with Imunify360 still got shelled |
| [INTAKE.md](docs/en/INTAKE.md) | Collecting samples for analysis without your AV eating them |

---

## Quick start

```bash
git clone https://github.com/davidthuong/webserver-ir-toolkit.git
sudo bash webserver-ir-toolkit/webshell-triage.sh --days 60
```

Options:

```
--days N        window for the "recently modified" checks (default 30)
--root PATH     add a webroot the script did not auto-detect
--out FILE      report destination (default /root/triage-<host>-<time>.txt)
--http          also fetch each site over the network (section 17, off by default)
```

Read section **2B** first — it tells you which web server is actually serving requests, which
determines every mitigation available to you. Then section **5** (persistence), **16**
(anti-cleanup and client-side injection) and **14** (entry point).

---

## What the scanner checks

**Web-layer intrusion**
19 webshell signature patterns, obfuscation, PHP embedded in image files, malicious
`.htaccess` / `.user.ini`, executables in upload directories, double extensions, recently
modified files, permission and ownership anomalies, timestomping.

**Persistence** — the surface commercial scanners skip
User crontabs (including DirectAdmin `crontab.conf` and Plesk ScheduledTasks), systemd units,
`rc.local`, shell startup files, `/etc/ld.so.preload`, `LD_PRELOAD`, unexpected SUID binaries,
SSH `authorized_keys`, sudoers, UID 0 accounts, `.forward` backdoors, mail queue abuse.

**Environment**
Web server and edition, whether `.htaccess` is honored, PHP binaries per version and whether a
hardening extension covers each one, installed scanner state.

**Anti-cleanup and client-side injection**
PHP files their own owner cannot write — a backdoor that re-applies `chmod 0444` to itself on
every request survives any scanner that neutralises malware by emptying it. Zero-byte PHP files,
which are not junk but the trace such a scanner leaves, and whose timestamps reconstruct a
reinfection timeline. WordPress `mu-plugins` and drop-ins, which load on every request and never
appear in the admin plugin list. Plugin directories with no plugin header. Injected
subdirectories inside core trees. JavaScript that decodes itself with a repeating-key XOR and
injects a script element, assembles strings from built-in `.name` properties to defeat keyword
search, or fetches its payload from a blockchain contract instead of a domain.

**Generic detection — for families no signature knows about**
Every signature section shares one weakness: it only finds what somebody already described.
These checks model what normal looks like instead. Long unbroken base64 runs and extremely
long single lines in PHP, with thresholds set from measurement rather than taste — a live
malicious payload carried a 56,030-character base64 run and a 56,101-character line, against
1,467 and 1,499 for a legitimately embedded icon. Content that contradicts its own extension.
And `wp core verify-checksums` plus `wp plugin verify-checksums`, which ask only whether a file
matches what wordpress.org shipped — reporting any modified core file and any extra file in a
plugin directory regardless of content, obfuscation or novelty. That is the one check here that
reliably finds a family nobody has seen yet.

With `--http`, the scanner also fetches each site twice — plainly, and as a mobile visitor
arriving from Google — and diffs the script tags. That catches injection stored in the database
or in web server config, which no file scan can see, and exposes cloaking that hides the payload
from the site owner.

**Attribution**
Access log correlation against shell mtimes, CMS component task endpoints and the status codes
they returned, panel/FTP/SSH login activity, system binary integrity via `rpm -Va`, WordPress
core checksums.

---

## Signature reliability

The 19 patterns were validated against 16 real webshell forms and 12 clean-code samples:

| | |
|---|---|
| Detected | 16/16 |
| False positives | 0/12 |

The clean-code controls are the constructs naive patterns trip on: `eval($template)`,
`call_user_func($this->handler, $_POST['data'])`, short base64 icon payloads,
`$wpdb->prepare(..., $_GET['id'])`, and `array_map` with a closure.

Two-step shells that split a variable function across statements
(`$f = $_POST['a']; $f($_POST['b']);`) are caught by requiring both halves in the same file
rather than by a single-line pattern — which is what keeps the false positive count at zero.

**If you change `$SIG`, re-run that check.** A pattern set that flags legitimate code gets
ignored, and an ignored scanner is worse than none.

---

## Limitations, stated plainly

**Signatures are not a substitute for a dedicated scanner.** This toolkit's strength is
persistence and entry-point attribution. Run it *alongside* Imunify360, maldet or ClamAV, not
instead of them.

**A clean report is not proof of a clean server.** Kernel-level rootkits, in-memory-only
implants and a competent attacker who cleaned up after themselves will not appear here.

**Root compromise makes cleanup meaningless.** If `/etc/ld.so.preload` has contents, an
unexpected UID 0 account exists, or `rpm -Va` reports modified system binaries, the correct
response is a rebuild on fresh infrastructure. See PLAYBOOK Phase 0.

**Tested on** CentOS 7 / RHEL-family with DirectAdmin and Plesk, Apache and OpenLiteSpeed.
cPanel, nginx, LiteSpeed Enterprise, CyberPanel and Debian/Ubuntu paths are implemented from
documentation rather than verified in the field — corrections welcome, see
[CONTRIBUTING.md](CONTRIBUTING.md).

---

## Do not commit incident data

`samples/` and `reports/` are gitignored for a reason. The former holds live malware —
pushing it to a public repository distributes malicious code and gets accounts suspended. The
latter holds hostnames, IP addresses and internal paths.

Check `git status` before every commit.

---

## Order of work

1. **PLAYBOOK** Phase 0–1 — isolate, preserve evidence, delete nothing yet
2. **IMUNIFY360** — if a scanner is already installed, find out why it did not stop this
3. **webshell-triage.sh** — scan, read the report
4. **MITIGATION** — contain, using the recipe for your actual web server, then verify it works
5. **PLAYBOOK** Phase 4 — find the entry point *before* cleaning
6. **PLAYBOOK** Phase 5–6 — clean, rotate every credential
7. **HARDENING** — close the surface
8. **PLAYBOOK** Phase 8 — monitor 2–4 weeks; re-scan at 48 hours and at one week

---

## License

MIT — see [LICENSE](LICENSE).

Contributions welcome, particularly field corrections for stacks marked untested above.
