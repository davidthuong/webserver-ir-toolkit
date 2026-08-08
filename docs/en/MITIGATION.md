# Blocking PHP execution in upload directories

The single most effective containment step after a webshell compromise is to stop the web
server from executing PHP inside directories that only ever hold assets — `tmp/`, `cache/`,
`uploads/`, `media/`, `images/`, `logs/`. A shell that lands there becomes an inert file.

**The recipe is different for every web server, and the wrong recipe fails silently.** This
document exists because that failure mode is so common: an `.htaccess` file written on a
server that never reads `.htaccess` looks exactly like a successful mitigation.

---

## Step 1 — identify the web server. Do not assume.

The presence of an `httpd` binary does not mean Apache serves requests. Panels install and
leave behind binaries they no longer use.

```bash
# authoritative: what is actually bound to the ports
ss -ltnp | grep -E ':(80|443)\b'

# which service is running
systemctl is-active httpd apache2 nginx lsws litespeed openlitespeed 2>/dev/null

# DirectAdmin records its choice explicitly
grep -E '^(webserver|php[0-9]_mode)=' /usr/local/directadmin/custombuild/options.conf

# LiteSpeed edition -- Enterprise and OpenLiteSpeed behave differently
/usr/local/lsws/bin/lshttpd -v
```

For LiteSpeed the **edition matters more than the version**. A version string containing
`Open` means OpenLiteSpeed. Anything containing `Enterprise` means LSWS Enterprise.

---

## Step 2 — pick the matching recipe

| Web server | Reads `.htaccess`? | Where mitigation goes |
|---|---|---|
| Apache | Yes, if `AllowOverride` permits | `.htaccess`, or vhost config |
| LiteSpeed Enterprise | Yes, natively | `.htaccess`, or vhost config |
| **OpenLiteSpeed** | **No** | vhost rewrite rules, or WAF |
| **nginx** | **No** | `location` block in vhost config |
| nginx + Apache proxy | Yes, at the Apache layer | `.htaccess` works for PHP, but nginx may serve static files directly — test both |

---

## Apache / LiteSpeed Enterprise

```apache
<FilesMatch "(?i)\.(php|php[0-9]|phtml|phtm|pht|phar|phps|shtml|cgi|pl|py)$">
    Require all denied
</FilesMatch>
```

Two things that break this:

**Case sensitivity.** `<FilesMatch>` is case-sensitive by default. Attackers routinely upload
`shell.PHP` with an uppercase extension precisely to slip past `\.php$`. The `(?i)` prefix is
not optional.

**AllowOverride.** `Require` comes from `mod_authz_core` and needs `AllowOverride` to include
`AuthConfig` or `Limit`. If it does not, Apache returns **500 for the entire directory** —
your mitigation becomes an outage. Check first:

```bash
grep -rhs 'AllowOverride' /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf \
  /usr/local/directadmin/data/users/*/httpd.conf 2>/dev/null | sort -u
```

If `AllowOverride None`, the file is ignored entirely — no error, no effect. Put the block in
the vhost config instead.

> Do **not** use `php_admin_flag engine off`. That is a mod_php directive; under PHP-FPM or
> LiteSpeed SAPI it produces a 500 error.

---

## nginx

nginx has no per-directory override file. The block goes in the server block, and `~*` makes
the match case-insensitive for free:

```nginx
location ~* ^/(tmp|cache|logs|uploads|images|media)/.*\.(php[0-9]?|phtml?|phar|phps)$ {
    deny all;
    access_log off;
    log_not_found off;
}
```

Place this **before** the general `location ~ \.php$ { fastcgi_pass ... }` block — nginx
picks the longest matching regex in order of appearance, and the first regex match wins.

Then reload:

```bash
nginx -t && systemctl reload nginx
```

---

## OpenLiteSpeed

OpenLiteSpeed does not read `.htaccess` the way Apache does. `<FilesMatch>` and
`Require all denied` are ignored. Two working approaches:

**A. Rewrite rule in the vhost config** (recommended)

WebAdmin console → Virtual Hosts → *your vhost* → Rewrite → Rewrite Rules:

```apache
RewriteRule ^(tmp|cache|logs|uploads|images)/.*\.(php|php[0-9]|phtml|phtm|phar|phps)$ - [F,L,NC]
```

`[NC]` handles the uppercase-extension bypass. `[F]` returns 403. Then Graceful Restart.

**B. Enable `.htaccess` rewrite loading**

Virtual Hosts → Rewrite → **Auto Load from .htaccess** → Yes. OpenLiteSpeed will then read
**rewrite directives only** from `.htaccess` — still not `<FilesMatch>` or `Require`. So the
rule has to be written as a `RewriteRule`, exactly as in option A.

This is convenient on shared hosting where per-user files are easier to deploy than vhost
edits, but it comes with a cost: every request checks for `.htaccess` files, and site owners
regain the ability to change rewrite behavior.

---

## Step 3 — verify empirically. Every time.

A mitigation you have not tested is an assumption. Drop a harmless probe file and request it:

```bash
d=/path/to/site/public_html/tmp
printf '<?php echo "EXECUTED-".PHP_VERSION; ?>' > "$d/zz-ir-probe.PHP"
chown --reference="$d" "$d/zz-ir-probe.PHP"

curl -sS "https://example.com/tmp/zz-ir-probe.PHP"
```

| Response | Meaning |
|---|---|
| `403` / `404` | Blocked. Working as intended. |
| `EXECUTED-8.1.2` | **Not blocked.** PHP still runs there. |
| Raw source shown | Not executed, but readable — acceptable containment, weaker than a deny |

Note the **uppercase `.PHP`** in the probe filename. Testing with lowercase `.php` and
declaring success is how the case-sensitivity gap survives.

Remove the probe when done:

```bash
rm -f "$d/zz-ir-probe.PHP"
```

---

## Step 4 — make it survive a panel rebuild

Control panels regenerate vhost configuration from templates. Manual edits to generated files
are silently reverted on the next domain change, panel update, or config rebuild — and the
mitigation disappears without any notice.

| Panel | Where custom config belongs |
|---|---|
| DirectAdmin | Copy the stock template from `/usr/local/directadmin/data/templates/` into `.../templates/custom/`, edit the copy, then `cd /usr/local/directadmin/custombuild && ./build rewrite_confs` |
| Plesk | Domain → Apache & nginx Settings → *Additional directives*, or drop a file in `/etc/nginx/plesk.conf.d/vhosts/` |
| cPanel | `/usr/local/apache/conf/userdata/std/2_4/<user>/<domain>/*.conf`, then `/scripts/ensure_vhost_includes --all-users` |
| OpenLiteSpeed standalone | `/usr/local/lsws/conf/vhosts/<vhost>/vhconf.conf` |

Discover which template your panel actually uses rather than guessing at filenames:

```bash
ls /usr/local/directadmin/data/templates/ | grep -iE 'litespeed|nginx|httpd'
ls /usr/local/directadmin/data/templates/custom/ 2>/dev/null
```

After any panel upgrade, re-run the Step 3 probe. That is the only reliable way to know the
rule is still in force.

---

## What this does and does not fix

Blocking PHP execution is **containment, not a fix**. The upload path is still open; the
attacker can still write files, still fill the disk, still place content used for phishing or
SEO spam served as static HTML.

The fix is patching whatever allowed the upload. Containment buys time to do that safely —
it does not replace it.

See [PLAYBOOK.md](PLAYBOOK.md) for finding the entry point and
[HARDENING.md](HARDENING.md) for the rest of the prevention surface.
