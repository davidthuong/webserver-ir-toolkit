# Chặn thực thi PHP trong thư mục upload

Sau khi bị webshell, biện pháp khoanh vùng hiệu quả nhất là làm cho web server **không thực
thi PHP** trong những thư mục chỉ chứa asset — `tmp/`, `cache/`, `uploads/`, `media/`,
`images/`, `logs/`. Shell nào rơi vào đó trở thành file vô hại.

**Mỗi web server có cách làm khác nhau, và làm sai thì thất bại trong im lặng.** Tài liệu này
tồn tại vì đó là lỗi rất hay gặp: một file `.htaccess` viết trên server không đọc `.htaccess`
trông y hệt như đã chặn thành công.

---

## Bước 1 — xác định web server. Đừng đoán.

Có binary `httpd` không có nghĩa là Apache đang phục vụ request. Panel cài rồi để lại binary
mà nó không còn dùng.

```bash
# đáng tin nhất: cái gì đang thực sự bind port
ss -ltnp | grep -E ':(80|443)\b'

# service nào đang chạy
systemctl is-active httpd apache2 nginx lsws litespeed openlitespeed 2>/dev/null

# DirectAdmin ghi lại lựa chọn của nó
grep -E '^(webserver|php[0-9]_mode)=' /usr/local/directadmin/custombuild/options.conf

# phiên bản LiteSpeed -- Enterprise và OpenLiteSpeed hành xử khác nhau
/usr/local/lsws/bin/lshttpd -v
```

Với LiteSpeed, **bản (edition) quan trọng hơn version**. Version string có chữ `Open` là
OpenLiteSpeed. Có chữ `Enterprise` là LSWS Enterprise.

---

## Bước 2 — chọn công thức đúng

| Web server | Đọc `.htaccess`? | Đặt rule ở đâu |
|---|---|---|
| Apache | Có, nếu `AllowOverride` cho phép | `.htaccess`, hoặc vhost config |
| LiteSpeed Enterprise | Có, đọc trực tiếp | `.htaccess`, hoặc vhost config |
| **OpenLiteSpeed** | **Không** | rewrite rule trong vhost, hoặc WAF |
| **nginx** | **Không** | khối `location` trong vhost config |
| nginx + Apache proxy | Có, ở tầng Apache | `.htaccess` chặn được PHP, nhưng nginx có thể phục vụ file tĩnh trực tiếp — phải test cả hai |

---

## Apache / LiteSpeed Enterprise

```apache
<FilesMatch "(?i)\.(php|php[0-9]|phtml|phtm|pht|phar|phps|shtml|cgi|pl|py)$">
    Require all denied
</FilesMatch>
```

Hai thứ làm rule này vô hiệu:

**Phân biệt hoa thường.** `<FilesMatch>` mặc định phân biệt hoa thường. Attacker thường
upload `shell.PHP` viết hoa chính là để lách `\.php$`. Tiền tố `(?i)` là bắt buộc, không phải
tuỳ chọn.

**AllowOverride.** `Require` thuộc `mod_authz_core`, cần `AllowOverride` gồm `AuthConfig` hoặc
`Limit`. Nếu không có, Apache trả **500 cho toàn bộ thư mục** — biện pháp bảo vệ biến thành
sự cố downtime. Kiểm tra trước:

```bash
grep -rhs 'AllowOverride' /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf \
  /usr/local/directadmin/data/users/*/httpd.conf 2>/dev/null | sort -u
```

Nếu là `AllowOverride None` thì file bị bỏ qua hoàn toàn — không lỗi, không tác dụng. Khi đó
phải đặt rule vào vhost config.

> **Đừng** dùng `php_admin_flag engine off`. Đó là directive của mod_php; dưới PHP-FPM hoặc
> LiteSpeed SAPI nó gây lỗi 500.

---

## nginx

nginx không có file override theo thư mục. Rule đặt trong server block, và `~*` cho sẵn khả
năng không phân biệt hoa thường:

```nginx
location ~* ^/(tmp|cache|logs|uploads|images|media)/.*\.(php[0-9]?|phtml?|phar|phps)$ {
    deny all;
    access_log off;
    log_not_found off;
}
```

Đặt khối này **trước** khối `location ~ \.php$ { fastcgi_pass ... }` — nginx chọn regex khớp
theo thứ tự xuất hiện, khối regex khớp đầu tiên thắng.

Rồi reload:

```bash
nginx -t && systemctl reload nginx
```

---

## OpenLiteSpeed

OpenLiteSpeed không đọc `.htaccess` như Apache. `<FilesMatch>` và `Require all denied` bị bỏ
qua. Hai cách dùng được:

**A. Rewrite rule trong vhost config** (khuyên dùng)

WebAdmin console → Virtual Hosts → *vhost của bạn* → Rewrite → Rewrite Rules:

```apache
RewriteRule ^(tmp|cache|logs|uploads|images)/.*\.(php|php[0-9]|phtml|phtm|phar|phps)$ - [F,L,NC]
```

`[NC]` xử lý việc lách bằng đuôi viết hoa. `[F]` trả 403. Xong thì Graceful Restart.

**B. Bật đọc rewrite từ `.htaccess`**

Virtual Hosts → Rewrite → **Auto Load from .htaccess** → Yes. Khi đó OpenLiteSpeed sẽ đọc
**chỉ các directive rewrite** từ `.htaccess` — vẫn không đọc `<FilesMatch>` hay `Require`.
Nên rule phải viết dạng `RewriteRule`, đúng như cách A.

Cách này tiện trên shared hosting vì triển khai file theo user dễ hơn sửa vhost, nhưng có
giá phải trả: mọi request đều phải kiểm tra file `.htaccess`, và chủ site lấy lại được quyền
thay đổi hành vi rewrite.

---

## Bước 3 — kiểm chứng bằng thực nghiệm. Lần nào cũng vậy.

Biện pháp chưa test chỉ là giả định. Đặt một file thăm dò vô hại rồi gọi nó:

```bash
d=/path/to/site/public_html/tmp
printf '<?php echo "EXECUTED-".PHP_VERSION; ?>' > "$d/zz-ir-probe.PHP"
chown --reference="$d" "$d/zz-ir-probe.PHP"

curl -sS "https://example.com/tmp/zz-ir-probe.PHP"
```

| Phản hồi | Nghĩa là |
|---|---|
| `403` / `404` | Đã chặn. Đúng như mong muốn. |
| `EXECUTED-8.1.2` | **Chưa chặn được.** PHP vẫn chạy ở đó. |
| Hiện source code | Không thực thi nhưng đọc được — khoanh vùng tạm ổn, yếu hơn deny |

Chú ý đuôi **`.PHP` viết hoa** trong tên file thăm dò. Test bằng `.php` chữ thường rồi kết
luận đã ổn chính là cách để lỗ hổng hoa-thường sống sót.

Xong thì xoá file thăm dò:

```bash
rm -f "$d/zz-ir-probe.PHP"
```

---

## Bước 4 — làm cho rule sống sót qua lần panel build lại

Control panel sinh lại cấu hình vhost từ template. Sửa tay vào file được sinh ra sẽ bị ghi đè
trong im lặng ở lần đổi domain, cập nhật panel, hoặc rebuild config kế tiếp — và biện pháp
bảo vệ biến mất mà không có thông báo nào.

| Panel | Đặt custom config ở đâu |
|---|---|
| DirectAdmin | Copy template gốc từ `/usr/local/directadmin/data/templates/` sang `.../templates/custom/`, sửa bản copy, rồi `cd /usr/local/directadmin/custombuild && ./build rewrite_confs` |
| Plesk | Domain → Apache & nginx Settings → *Additional directives*, hoặc đặt file vào `/etc/nginx/plesk.conf.d/vhosts/` |
| cPanel | `/usr/local/apache/conf/userdata/std/2_4/<user>/<domain>/*.conf`, rồi `/scripts/ensure_vhost_includes --all-users` |
| OpenLiteSpeed độc lập | `/usr/local/lsws/conf/vhosts/<vhost>/vhconf.conf` |

Tìm xem panel thực sự dùng template nào, đừng đoán tên file:

```bash
ls /usr/local/directadmin/data/templates/ | grep -iE 'litespeed|nginx|httpd'
ls /usr/local/directadmin/data/templates/custom/ 2>/dev/null
```

Sau mỗi lần nâng cấp panel, chạy lại bước 3. Đó là cách duy nhất chắc chắn biết rule còn
hiệu lực.

---

## Cái này giải quyết được gì và không giải quyết được gì

Chặn thực thi PHP là **khoanh vùng, không phải sửa lỗi**. Đường upload vẫn mở; attacker vẫn
ghi được file, vẫn làm đầy disk, vẫn đặt được nội dung dùng cho phishing hoặc SEO spam phục
vụ dưới dạng HTML tĩnh.

Sửa thật là vá cái đã cho phép upload. Khoanh vùng mua thời gian để làm việc đó một cách an
toàn — không thay thế được nó.

Xem [PLAYBOOK.md](PLAYBOOK.md) để tìm đường vào, và [HARDENING.md](HARDENING.md) cho phần
phòng ngừa còn lại.
