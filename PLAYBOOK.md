# Playbook xử lý server bị shell / malware (DirectAdmin & Plesk)

Thứ tự các bước dưới đây quan trọng. Sai thứ tự phổ biến nhất là **xoá shell trước khi tìm
đường vào** — hacker sẽ upload lại trong vài giờ.

---

## Phase 0 — Nguyên tắc trước khi làm gì

| Nên | Không nên |
|---|---|
| Chụp lại bằng chứng trước khi xoá | `rm -rf` ngay khi thấy file lạ |
| Giả định mọi mật khẩu trên server đã bị lộ | Chỉ đổi mật khẩu panel rồi coi là xong |
| Tìm entry point rồi mới dọn | Dọn shell mà không patch lỗ hổng |
| Kiểm tra dấu hiệu chiếm quyền root | Mặc định là "chỉ bị shell ở web thôi" |

**Khi nào bắt buộc rebuild server, không cứu:**
- `/etc/ld.so.preload` tồn tại và có nội dung
- Có user UID 0 ngoài `root`, hoặc `/etc/passwd` bị sửa gần đây
- `rpm -Va` báo binary hệ thống (`ls`, `ps`, `ssh`, `bash`) bị đổi
- Có process chạy từ binary đã bị xoá và không kill được
- Kernel module lạ (`lsmod`), hoặc `ps` / `netstat` cho kết quả khác nhau so với `/proc`

Root compromise thì mọi thao tác dọn dẹp đều không đáng tin. Dựng server mới, chỉ mang
**dữ liệu** (file tĩnh đã kiểm tra + dump DB) sang.

---

## Phase 1 — Cô lập (làm ngay, trước cả khi scan)

Mục tiêu: chặn shell tiếp tục được điều khiển, nhưng **không tắt máy** (mất RAM forensics
và mất log).

```bash
# 1. Chặn outbound trừ cái cần thiết -> cắt liên lạc C2 và mining pool
iptables -I OUTPUT -p tcp --dport 3333:5555 -j DROP     # port mining pool phổ biến
iptables -I OUTPUT -m owner --uid-owner apache -p tcp --syn -j DROP  # web user không được tự gọi ra ngoài

# 2. Ngừng gửi mail nếu đang bị dùng để spam (giữ queue lại làm bằng chứng)
systemctl stop exim     # DirectAdmin
systemctl stop postfix  # Plesk

# 3. Nếu site không critical: cho vào maintenance thay vì tắt hẳn
```

Nếu cần **chặn truy cập web ngay** mà vẫn muốn xem log tiếp:
- DirectAdmin: đổi document root sang trang tĩnh, hoặc thêm `Require ip <IP-của-bạn>`
- Plesk: **Domains → Hosting Settings → tắt PHP support** cho vhost đó (shell PHP chết ngay,
  log HTTP vẫn ghi)

Đừng đổi mật khẩu ở bước này. Đổi bây giờ chỉ làm hacker biết b đã phát hiện; để sau khi dọn.

---

## Phase 2 — Thu thập bằng chứng

```bash
mkdir -p /root/ir-$(date +%F) && cd /root/ir-$(date +%F)

# snapshot trạng thái sống (mất khi reboot)
ps auxfww                > ps.txt
ss -antup                > sockets.txt
lsof -nP                 > lsof.txt 2>/dev/null
for p in /proc/[0-9]*; do echo "$p -> $(readlink $p/exe)"; done > proc_exe.txt
crontab -l               > cron_root.txt 2>/dev/null
cp -a /var/spool/cron    ./spool_cron
last -F                  > last.txt
netstat -rn              > routes.txt

# copy log TRƯỚC khi rotate ăn mất
tar czf logs.tar.gz /var/log/httpd /var/log/nginx /var/log/secure /var/log/auth.log \
                    /var/log/exim /var/log/maillog /var/log/directadmin /var/log/plesk \
                    /var/www/vhosts/system/*/logs 2>/dev/null
```

Ghi lại mtime của các file nghi ngờ — đó là mốc thời gian để đối chiếu với access log.

---

## Phase 3 — Scan

```bash
sed -i 's/\r$//' webshell-triage.sh          # nếu copy từ Windows
sudo bash webshell-triage.sh --days 60
```

Script chỉ đọc, không sửa gì. Kết quả ở `/root/triage-<host>-<time>.txt`.

Đọc theo thứ tự ưu tiên: **section 5** (persistence — nghiêm trọng nhất) → **section 6**
(shell) → **section 14** (entry point) → phần còn lại.

**Đã có Imunify360 trên server** → dùng nó trước, nhưng phải kiểm tra config trước đã.
Server có Imunify mà vẫn bị shell = Imunify đang bị tắt, hết license, hoặc ở mode log-only.
Xem `IMUNIFY360.md` — 6 nguyên nhân và cách kiểm tra từng cái.

```bash
imunify360-agent malware malicious list --limit 200      # nó đã biết file nào độc
imunify360-agent malware on-demand start --path /home            # DirectAdmin
imunify360-agent malware on-demand start --path /var/www/vhosts  # Plesk
```

**Bổ sung bằng scanner chuyên dụng** (nếu chưa có Imunify, hoặc muốn đối chứng bằng
signature độc lập):

```bash
# maldet + ClamAV -- miễn phí, chạy được trên cả DA và Plesk
wget -q http://www.rfxn.com/downloads/maldetect-current.tar.gz
tar xf maldetect-current.tar.gz && cd maldetect-* && ./install.sh
maldet -u                                    # cập nhật signature
maldet -a /home/?/domains/?/public_html       # DirectAdmin
maldet -a /var/www/vhosts/?/httpdocs          # Plesk
maldet --report list                          # xem kết quả, chưa xoá gì

# Plesk có sẵn nếu đã cài extension:
plesk ext revisium-antivirus --scan -domain example.com
```

**Cảnh báo về mọi scanner tự động:** Imunify/maldet chỉ tìm **file độc trong webroot**.
Chúng không kiểm cron của user, systemd unit lạ, SSH key bị thêm, `.forward` backdoor,
hay `ld.so.preload` — đúng những chỗ backdoor hay nằm. Dọn sạch webroot mà bỏ sót cron
thì 10 phút sau shell về lại. Section 5 của `webshell-triage.sh` lo phần này.

---

## Phase 4 — Tìm entry point

Không tìm được cái này thì 90% sẽ bị lại. 4 nguồn xâm nhập chiếm gần hết số ca:

**1. Plugin/theme CMS lỗi (phổ biến nhất)**

```bash
# lấy mtime của shell rồi soi access log đúng khoảng đó
stat -c '%y %n' /path/to/shell.php
grep -E '"(POST|GET) ' /var/log/httpd/domains/site.com.log | grep '06/Aug/2026:1[0-9]'
```
Tìm request POST tới file plugin ngay **trước** thời điểm shell xuất hiện. Đó là lỗ hổng.
Kiểm tra version plugin đó với [wpscan.com/plugins](https://wpscan.com/plugins) hoặc `wp plugin list`.

**2. Mật khẩu FTP/panel bị lộ (thường do máy dev nhiễm stealer)**

```bash
grep 'OK LOGIN' /var/log/pureftpd.log | awk '{print $NF}' | sort | uniq -c | sort -rn
grep 'Accepted' /var/log/secure | awk '{print $9, $11}' | sort | uniq -c
```
IP đăng nhập thành công từ quốc gia lạ = credential leak, không phải lỗi code.
→ Bắt buộc quét malware trên máy tính của tất cả người có mật khẩu FTP.

**3. Lây chéo giữa các user trên cùng server**
Nếu nhiều user bị cùng loại shell mà mỗi user chạy code khác nhau → cấu hình PHP đang cho
đọc chéo home directory. Xem `HARDENING.md`, phần `open_basedir` và PHP-FPM per-user.

**4. Panel/service chưa patch**
```bash
/usr/local/directadmin/directadmin v      # so với changelog DA mới nhất
plesk version                              # so với release notes Plesk
```

---

## Phase 5 — Dọn sạch

Ưu tiên theo thứ tự:

**A. Restore từ backup sạch** — nhanh và chắc nhất, nếu xác định được thời điểm nhiễm và có
backup trước đó. Restore **code**, giữ DB hiện tại (sau khi kiểm DB không có mã độc).

**B. Reinstall core + plugin/theme, giữ lại uploads**
```bash
wp core download --force --allow-root         # ghi lại core sạch
wp plugin install $(wp plugin list --field=name) --force --allow-root
```
Rồi kiểm tra thủ công: `wp-config.php`, `.htaccess`, thư mục `uploads/` (chỉ được có ảnh),
và mọi file mà `wp core verify-checksums` báo lạ.

**C. Xoá từng file** — chỉ khi A và B không khả thi. Sau khi đã tar bằng chứng:
```bash
tar czf /root/evidence.tar.gz -T /tmp/candidate-list.txt
xargs -a /tmp/candidate-list.txt rm -v -f
```

Đừng quên các chỗ hay bị bỏ sót:
- Mã độc chèn trong **DB**: `wp_options` (`siteurl`, `home`), `wp_posts` có `<script>`,
  user admin lạ trong `wp_users`
- `wp-config.php` / `configuration.php` có dòng `include` file lạ ở đầu file
- `.htaccess` ở **mọi** thư mục, không chỉ root
- Cron của user (`crontab -l -u <user>`)
- File `.ico`, `.png` chứa `<?php`
- `index.php` bị thêm 1 dòng eval ở cuối

---

## Phase 6 — Rotate toàn bộ credentials

Sau khi dọn, trước khi mở lại. Giả định mọi thứ trong DB và config đã bị đọc.

- [ ] Mật khẩu user panel (DA/Plesk) — tất cả user, không chỉ user bị nhiễm
- [ ] Mật khẩu FTP + xoá các FTP account lạ
- [ ] Mật khẩu MySQL của từng site → cập nhật lại `wp-config.php`
- [ ] SSH: xoá `authorized_keys` lạ, đổi key, `PasswordAuthentication no`
- [ ] Admin CMS: đổi pass, xoá user lạ, `wp user list`
- [ ] WordPress salts: `wp config shuffle-salts` (kick mọi session đang đăng nhập)
- [ ] API key / SMTP / payment key nằm trong file config
- [ ] Mật khẩu root server
- [ ] Mật khẩu email của các mailbox trên server

---

## Phase 7 — Hardening

Xem `HARDENING.md`. Tối thiểu phải làm: tắt PHP trong thư mục upload, `disable_functions`,
ModSecurity, firewall + fail2ban, 2FA cho panel.

---

## Phase 8 — Theo dõi tái nhiễm

Đặt baseline rồi so sánh hằng ngày trong 2–4 tuần:

```bash
# tạo baseline sau khi đã dọn sạch
find /home/*/domains/*/public_html -type f \( -name '*.php' -o -name '.htaccess' \) \
  -exec sha256sum {} \; | sort > /root/baseline.sha256

# cron hằng ngày: báo file mới/đổi
cat > /root/check-drift.sh <<'EOF'
#!/bin/bash
find /home/*/domains/*/public_html -type f \( -name '*.php' -o -name '.htaccess' \) \
  -exec sha256sum {} \; | sort > /tmp/now.sha256
diff /root/baseline.sha256 /tmp/now.sha256 > /tmp/drift.txt
[ -s /tmp/drift.txt ] && mail -s "FILE DRIFT on $(hostname)" you@example.com < /tmp/drift.txt
EOF
chmod +x /root/check-drift.sh
echo '0 3 * * * /root/check-drift.sh' | crontab -
```

Chạy lại `webshell-triage.sh` sau 48h và sau 1 tuần. Nếu shell quay lại → entry point ở
Phase 4 chưa đúng.

---

## Bảng đường dẫn nhanh

| | DirectAdmin | Plesk |
|---|---|---|
| Webroot | `/home/<user>/domains/<domain>/public_html` | `/var/www/vhosts/<domain>/httpdocs` |
| Access log | `/var/log/httpd/domains/<domain>.log` | `/var/www/vhosts/system/<domain>/logs/access_log` |
| Error log | `/var/log/httpd/domains/<domain>.error.log` | `/var/www/vhosts/system/<domain>/logs/error_log` |
| Panel log | `/var/log/directadmin/` | `/var/log/plesk/panel.log` |
| Cron user | `/usr/local/directadmin/data/users/<u>/crontab.conf` | `plesk db "SELECT * FROM ScheduledTasks"` |
| Danh sách user | `/usr/local/directadmin/data/users/` | `plesk bin subscription --list` |
| Config PHP | `/usr/local/php*/lib/php.ini` (CustomBuild) | `/opt/plesk/php/<ver>/etc/php.ini` |
| Mail | exim, `/var/log/exim/mainlog` | postfix, `/var/log/maillog` |
| Reload web | `systemctl restart httpd` | `plesk sbin httpdmng --reconfigure-all` |
