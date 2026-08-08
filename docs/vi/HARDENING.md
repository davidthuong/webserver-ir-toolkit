# Hardening server shared hosting sau khi bị shell

Xếp theo tỉ lệ **hiệu quả / công sức**. Làm từ trên xuống; 5 mục đầu chặn được phần lớn
các ca tái nhiễm thực tế.

---

## 0. OS còn nhận bản vá bảo mật không?

Đây là rủi ro nền, không sửa được bằng cấu hình, và nên kiểm tra trước mọi thứ khác vì câu
trả lời có thể thay đổi cả kế hoạch.

```bash
cat /etc/redhat-release 2>/dev/null; cat /etc/os-release | grep PRETTY
uname -r
rpm -q kernel 2>/dev/null | tail -3            # kernel mới nhất từ bao giờ?
yum list installed 2>/dev/null | grep -iE 'els|extended'
yum history 2>/dev/null | head -6              # hoặc: apt list --upgradable
```

**CentOS 7 hết hạn hỗ trợ từ 30/06/2024.** CentOS 8 còn sớm hơn — 2021. Trên bản EOL thì
kernel, glibc và OpenSSL không nhận bản vá nào từ upstream, và hệ quả kéo theo còn mở rộng bề
mặt tấn công thêm nữa: Plesk, DirectAdmin và cPanel đều đã ngừng hỗ trợ CentOS 7, nên panel bị
kẹt ở bản cũ, và điều đó lại làm kẹt luôn các version PHP build được.

Ba lựa chọn, theo thứ tự thường nên chọn:

| | Cách | Ưu | Nhược |
|---|---|---|---|
| **A** | Mua extended support (ví dụ CloudLinux ELS cho CentOS 7) | Có vá bảo mật trở lại trong vài giờ, không phải migrate gì | Trả phí theo server. Chỉ là cầu nối — panel và PHP vẫn kẹt version |
| **B** | Server mới trên OS còn hỗ trợ (AlmaLinux, Rocky, Debian, Ubuntu LTS) rồi migrate sang | Sạch thật sự. Sau sự cố còn lợi ích thứ hai: server mới **không mang theo backdoor** | Tốn công, cần downtime có kế hoạch |
| **C** | ~~In-place upgrade (ELevate và tương tự)~~ | — | **Không nên khi có control panel.** Plesk và DirectAdmin không hỗ trợ; hỏng là mất cả server |

Cách A ngay, cách B trong 1–3 tháng tới, là lộ trình hợp lý.

Công cụ migrate: Plesk có extension **Plesk Migrator**; DirectAdmin có Admin Backup/Transfer;
cPanel có Transfer Tool.

> **Khi migrate sau sự cố bảo mật, chỉ mang dữ liệu — không mang code.** Migrate nguyên si là
> bê luôn shell sang server mới. Cài lại CMS, plugin và theme từ nguồn chính thức, chỉ mang
> `uploads/` và database.

Nâng luôn giới hạn inotify. Mặc định 8192 là quá thấp cho server nhiều site, và nó làm
scanner real-time chết trong im lặng khi vượt ngưỡng:

```bash
cat /proc/sys/fs/inotify/max_user_watches
echo 'fs.inotify.max_user_watches=524288' >> /etc/sysctl.conf && sysctl -p
```

Công cụ migrate sang server mới:
- Plesk: extension **Plesk Migrator** (Tools & Settings → Migration & Transfer Manager)
- DirectAdmin: Admin Backup/Transfer, hoặc `/usr/local/directadmin/scripts/da_migrate`

> Lưu ý khi migrate sau sự cố bảo mật: **chỉ mang dữ liệu, không mang code**.
> Migrate nguyên si thì bê luôn shell sang server mới. Restore code từ backup sạch hoặc
> cài lại CMS + plugin từ nguồn chính thức, chỉ giữ `uploads/` và database.

Riêng CentOS 7, nâng giới hạn inotify (mặc định 8192 là quá thấp, làm real-time scan của
Imunify chết âm thầm):
```bash
echo 'fs.inotify.max_user_watches=524288' >> /etc/sysctl.conf && sysctl -p
```

---

## 1. Chặn thực thi PHP trong thư mục upload

Đây là biện pháp đơn lẻ hiệu quả nhất. Shell gần như luôn được upload vào `uploads/`,
`images/`, `cache/`, `tmp/`, `media/`.

**Cách làm khác nhau theo từng web server, và làm sai thì thất bại trong im lặng.**
Chi tiết đầy đủ, kèm cách kiểm chứng, ở **[MITIGATION.md](MITIGATION.md)** — đọc file đó
trước khi triển khai. Tóm tắt:

| Web server | Đọc `.htaccess`? |
|---|---|
| Apache, LiteSpeed Enterprise | Có (Apache còn phụ thuộc `AllowOverride`) |
| **OpenLiteSpeed, nginx** | **Không** — `.htaccess` bị bỏ qua hoàn toàn |

Xác định web server thật:
```bash
ss -ltnp | grep -E ':(80|443)\b'
grep -E '^webserver=' /usr/local/directadmin/custombuild/options.conf 2>/dev/null
/usr/local/lsws/bin/lshttpd -v 2>/dev/null      # có chữ "Open" = OpenLiteSpeed
```

**Apache / LiteSpeed Enterprise:**

```apache
<FilesMatch "(?i)\.(php|php[0-9]|phtml|phtm|pht|phar|phps|cgi|pl|py|shtml)$">
    Require all denied
</FilesMatch>
```

Tiền tố `(?i)` là **bắt buộc**. `<FilesMatch>` mặc định phân biệt hoa thường, và attacker
upload `shell.PHP` viết hoa chính là để lách rule viết `\.php$`. Đây không phải giả thuyết —
đó là cách các shell trong sự cố thực tế đã đặt tên.

Đừng thêm `php_flag engine off` hay `php_admin_flag engine off`: đó là directive của mod_php,
dưới PHP-FPM hoặc LiteSpeed SAPI nó gây **lỗi 500**.

Cũng kiểm tra `AllowOverride` có gồm `AuthConfig` hoặc `Limit` — nếu không, `Require` làm
Apache trả 500 cho cả thư mục:
```bash
grep -rhs 'AllowOverride' /usr/local/directadmin/data/users/*/httpd.conf 2>/dev/null | sort -u
```

**nginx:**

```nginx
location ~* ^/(uploads|files|images|cache|tmp|media|logs)/.*\.(php[0-9]?|phtml?|phar|phps)$ {
    deny all;
}
location ~* /\.(git|env|svn) { deny all; }
location ~* \.(sql|bak|old|log|ini|conf)$ { deny all; }
```

`~*` đã là không phân biệt hoa thường nên không cần thêm gì. Đặt **trước** khối
`location ~ \.php$` vì nginx lấy regex khớp đầu tiên theo thứ tự xuất hiện.

**OpenLiteSpeed:** không dùng được `.htaccess`. Vào WebAdmin → Virtual Hosts → Rewrite →
Rewrite Rules:

```apache
RewriteRule ^(tmp|cache|logs|uploads|images)/.*\.(php|php[0-9]|phtml|phtm|phar|phps)$ - [F,L,NC]
```

**Kiểm chứng — bắt buộc, đừng bỏ qua:**

```bash
d=/path/to/public_html/tmp
printf '<?php echo "EXECUTED"; ?>' > "$d/zz-ir-probe.PHP"
curl -sS https://site.com/tmp/zz-ir-probe.PHP     # phải ra 403/404, KHÔNG ra "EXECUTED"
rm -f "$d/zz-ir-probe.PHP"
```

Chú ý đuôi `.PHP` viết hoa trong file thăm dò. Test bằng chữ thường rồi kết luận đã ổn chính
là cách lỗ hổng hoa-thường sống sót.

**Làm cho rule sống sót qua panel rebuild:** panel sinh lại vhost config từ template, sửa tay
vào file được sinh ra sẽ bị ghi đè trong im lặng. DirectAdmin dùng
`/usr/local/directadmin/data/templates/custom/` rồi `./build rewrite_confs`; Plesk dùng
Additional directives hoặc template chung rồi `plesk sbin httpdmng --reconfigure-all`.
Bảng đầy đủ cho từng panel ở [MITIGATION.md](MITIGATION.md).

---

## 2. `disable_functions` + `open_basedir`

Shell mất phần lớn khả năng nếu không gọi được exec.

```ini
; php.ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,proc_close,proc_get_status,proc_nice,proc_terminate,pcntl_exec,pcntl_fork,dl,curl_multi_exec,posix_kill,posix_setuid,posix_setpgid,posix_setsid,show_source,symlink,link,escapeshellcmd,escapeshellarg
allow_url_include = Off
allow_url_fopen  = Off      ; kiểm tra trước -- một số plugin cần
expose_php       = Off
```

> `mail()` thường phải giữ lại. Nếu site không cần gửi mail thì disable luôn — cắt hẳn
> đường spam. Một số plugin dùng `curl_multi_exec` hợp pháp, test trước khi áp production.

**`open_basedir`** chặn shell đọc chéo sang home user khác — quan trọng nhất trên shared hosting:

- DirectAdmin: `Admin Settings → php-fpm/open_basedir`, hoặc per-user trong pool config
- Plesk: Domains → PHP Settings → `open_basedir` = `{WEBSPACEROOT}{/}{:}{TMP}{/}`

Kiểm tra đã ăn chưa:
```bash
php -i | grep -E 'disable_functions|open_basedir'   # CLI
# và tạo file test.php gọi phpinfo() -- giá trị của FPM có thể khác CLI
```

---

## 3. PHP-FPM riêng cho từng user

Nếu tất cả site chạy chung 1 pool user (`apache`/`nginx`), một shell = mọi site trên server
bị nhiễm. Đây là nguyên nhân của gần như mọi ca "lây chéo".

- **DirectAdmin**: CustomBuild → `php1_mode=php-fpm`, mỗi user có pool riêng trong
  `/usr/local/php*/etc/php-fpm.d/`. Kiểm tra: `ps aux | grep php-fpm` — phải thấy nhiều user khác nhau.
- **Plesk**: Domains → Hosting Settings → PHP → **FPM application served by nginx/Apache**
  (không dùng "FastCGI application served by Apache" chung).

Kèm theo: đảm bảo file PHP thuộc sở hữu của user site, **không** phải của web server user.
File `.php` mà `stat -c %U` trả về `apache` / `www-data` = web server ghi được vào code =
shell upload được tự do.

```bash
# DirectAdmin -- sửa quyền cho 1 user
chown -R user:user /home/user/domains/site.com/public_html
find /home/user/domains/site.com/public_html -type d -exec chmod 755 {} \;
find /home/user/domains/site.com/public_html -type f -exec chmod 644 {} \;
```

---

## 4. ModSecurity + OWASP CRS

Chặn được exploit ở tầng HTTP, kể cả khi plugin chưa kịp patch.

```bash
# DirectAdmin (CustomBuild)
cd /usr/local/directadmin/custombuild
./build set modsecurity yes
./build set modsecurity_ruleset comodo    # hoặc owasp
./build modsecurity && ./build modsecurity_rules
./build restart_apache
```

Plesk: Tools & Settings → **Web Application Firewall (ModSecurity)** → bật, ruleset
**Comodo** hoặc **OWASP CRS**, mode = **On** (không phải "Detection only" — detection chỉ
để test 1–2 tuần rồi phải chuyển sang On).

Sau khi bật, theo dõi `/var/log/httpd/modsec_audit.log` vài ngày để tune false positive
thay vì tắt hẳn khi có site lỗi.

---

## 5. Firewall + fail2ban + rate limit

```bash
# CSF -- chạy tốt trên cả DA và Plesk
cd /usr/src && wget https://download.configserver.com/csf.tgz
tar -xzf csf.tgz && cd csf && sh install.sh
csf -e
```

Trong `/etc/csf/csf.conf`:
```ini
TESTING = "0"
LF_SSHD = "3"          # 3 lần fail SSH -> block
LF_FTPD = "5"
PT_LIMIT = "200"       # cảnh báo process dùng nhiều CPU (phát hiện miner)
PT_USERPROC = "15"
LF_DIRWATCH = "300"    # theo dõi /tmp
SMTP_BLOCK = "1"       # chặn PHP gửi mail trực tiếp ra port 25 -> cắt spam
```

`SMTP_BLOCK = 1` rất hiệu quả: shell spam thường mở socket tới port 25 bên ngoài, bỏ qua
mail server local. Bật cái này là chặn.

Giới hạn truy cập panel theo IP (port 2222 cho DA, 8443 cho Plesk):
```bash
csf -a <IP-của-bạn>
# rồi bỏ 2222 / 8443 khỏi TCP_IN, chỉ cho IP trong allow list
```

---

## 6. Panel security

- **2FA** cho mọi user admin/reseller: DA → User Level → Two-Step Auth; Plesk → My Profile → 2FA
- Đổi port panel khỏi mặc định (giảm scan tự động, không phải bảo mật thật)
- DirectAdmin: `Admin Settings → Enable IP whitelist for admin logins`
- Plesk: Tools & Settings → Security Policy → cấm mật khẩu yếu, bật
  **Restrict administrative access** theo IP
- Tắt các service không dùng: nếu không ai dùng FTP thì tắt hẳn pure-ftpd/proftpd và
  dùng SFTP. FTP là nguồn credential leak lớn nhất vì mật khẩu truyền plaintext.

---

## 7. Auto-update

Phần lớn ca bị shell là do plugin cũ, không phải 0-day.

```bash
# WordPress: bật auto-update cho core + plugin
wp plugin auto-updates enable --all --allow-root
wp theme auto-updates enable --all --allow-root
```

- DirectAdmin: CustomBuild → `./build set autover yes`, cron `./build update && ./build all d`
- Plesk: Tools & Settings → Update and Upgrade Settings → auto-install security patches
- Plesk **WP Toolkit**: bật *Smart Updates* + *Security measures* cho toàn bộ site — đây là
  tính năng đáng giá nhất của Plesk cho trường hợp này
- OS: `dnf install dnf-automatic` / `unattended-upgrades`

**Xoá nulled theme/plugin.** Theme crack là nguồn backdoor số 1 và không có bản patch nào
cứu được. Nếu client dùng theme nulled thì hoặc mua bản thật hoặc đổi theme.

---

## 8. Backup đáng tin

Backup nằm trên cùng server thì bị mã hoá/xoá cùng lúc với server.

- Giữ **≥ 14 ngày**, offsite (S3/B2/rsync sang máy khác), có ít nhất 1 bản **immutable**
  hoặc pull-based (máy backup kéo về, server không có quyền ghi)
- Test restore thật ít nhất 1 lần — backup chưa test = chưa có backup
- DirectAdmin: Admin Backup/Transfer → FTP/SFTP remote
- Plesk: Tools & Settings → Backup Manager → remote storage (S3/Dropbox/FTP)

---

## 9. Giám sát

```bash
# alert khi có file .php mới trong webroot -- rẻ và hiệu quả
yum install -y inotify-tools   # hoặc apt install inotify-tools
cat > /usr/local/bin/watch-php.sh <<'EOF'
#!/bin/bash
inotifywait -m -r -e create,moved_to --format '%w%f' \
  /home/*/domains/*/public_html 2>/dev/null \
  | while read f; do
      case "$f" in *.php|*.phtml|*.phar|*.pht)
        echo "$(date) NEW: $f" >> /var/log/new-php.log
        mail -s "New PHP file on $(hostname)" you@example.com <<< "$f" ;;
      esac
    done
EOF
chmod +x /usr/local/bin/watch-php.sh
```

Kèm theo: rootkit check định kỳ (`rkhunter --check`, `chkrootkit`), và cron chạy
`webshell-triage.sh` hằng tuần gửi report qua mail.

---

## Checklist rút gọn

```
[ ] OS còn nhận bản vá bảo mật, HOẶC đã mua extended support, HOẶC đã có kế hoạch migrate
[ ] fs.inotify.max_user_watches đã nâng lên 524288
[ ] Đã kiểm tra config scanner thật (không phải giả định) -- xem IMUNIFY360.md,
    làm trước tất cả các mục dưới
[ ] ModSecurity dùng ruleset thật (FULL/OWASP/Comodo), mode On, không phải detection-only
[ ] PHP tắt trong uploads/ cache/ images/ tmp/ media/  (mọi vhost)
[ ] Đã KIỂM CHỨNG bằng curl, dùng file thăm dò đuôi .PHP viết hoa
[ ] Rule đặt ở chỗ panel rebuild không ghi đè
[ ] disable_functions + open_basedir đã áp cho FPM (không chỉ CLI)
[ ] PHP-FPM pool riêng từng user
[ ] File code thuộc user site, KHÔNG thuộc apache/nginx/www-data
[ ] ModSecurity mode = On (không phải detection only)
[ ] CSF + SMTP_BLOCK=1 + LF_SSHD
[ ] Panel: 2FA + giới hạn IP + đổi port
[ ] FTP tắt (dùng SFTP), hoặc ít nhất bắt buộc FTPS
[ ] Auto-update CMS/plugin/theme bật
[ ] Nulled theme/plugin đã xoá hết
[ ] Backup offsite ≥14 ngày, đã test restore
[ ] Baseline sha256 + cron kiểm drift hằng ngày
[ ] Máy tính của dev/client đã quét malware (credential stealer)
```
