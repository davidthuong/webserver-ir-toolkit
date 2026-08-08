# Lấy mẫu về phân tích

## Phần mềm diệt virus sẽ xoá mẫu của bạn

Windows Defender đã **xoá thẳng** 3 file webshell mẫu ngay khi chúng được ghi ra đĩa trong lúc
phát triển bộ công cụ này, và khoá 2 file còn lại với `Permission denied`. Copy một shell thật
về máy làm việc với đuôi `.php` thì rất dễ mất file trước khi kịp đọc — và việc xoá đó có khi
diễn ra âm thầm.

**Đổi tên ngay trên server, trước khi tải về:**

```bash
mkdir -p /root/for-analysis
cp /path/to/shell.php /root/for-analysis/shell1.php.txt
cp /path/to/another.PHP /root/for-analysis/shell2.php.txt
```

Nếu file vẫn biến mất: thêm thư mục đích vào exclusion của AV, hoặc đơn giản là paste nội dung
file vào editor thay vì tải file về.

---

## Metadata quan trọng ngang nội dung

Với việc truy vết, timestamp thường hữu ích hơn payload — đó là thứ dùng để đối chiếu với access
log nhằm tìm đường vào. Lấy metadata **trước khi** có gì đó chạm vào file:

```bash
cd /root/for-analysis
for f in /path/to/shell.php /path/to/another.PHP; do
  stat -c '%n | size=%s | mtime=%y | ctime=%z | owner=%U:%G | perm=%a' "$f"
  sha256sum "$f"
done > metadata.txt
```

`mtime` là lần cuối nội dung được ghi — tức thời điểm upload. `ctime` là lần cuối inode thay
đổi. Nếu `ctime` muộn hơn `mtime` nhiều, có gì đó đã chạm vào file sau khi upload, thường là nỗ
lực lùi ngày.

Nhiều file cùng hash cho biết cùng một payload được ghi ra dưới nhiều tên hoặc nhiều đuôi khác
nhau — thường là script tự động dò xem server chịu thực thi đuôi nào.

---

## Trích access log quanh mtime của shell

Đây là artifact giá trị nhất, và cũng là cái dễ mất nhất vì log rotate:

```bash
stat -c '%y' /path/to/shell.php      # ví dụ ra 2026-08-05 14:23

# DirectAdmin
grep '05/Aug/2026:1[2-6]' /var/log/httpd/domains/site.com.log > /root/for-analysis/access-window.log
# Plesk
grep '05/Aug/2026:1[2-6]' /var/www/vhosts/system/site.com/logs/access_log > /root/for-analysis/access-window.log
# cPanel
grep '05/Aug/2026:1[2-6]' /usr/local/apache/domlogs/site.com > /root/for-analysis/access-window.log
# LiteSpeed / OpenLiteSpeed độc lập
grep '05/Aug/2026:1[2-6]' /usr/local/lsws/logs/access.log > /root/for-analysis/access-window.log
```

Giữ cả các request POST dù trông không có gì đặc biệt. Tham số khai thác nằm trong request body,
mà access log không ghi lại — nên dấu hiệu thường chỉ là một `POST` tới `index.php` đúng vào
giây đó, không có gì khác để phân biệt.

---

## Nếu scanner đã quarantine file rồi

Scanner thương mại giữ bản gốc trong một khoảng thời gian có hạn, và khoảng đó là một deadline.

```bash
imunify360-agent config show | grep -o '"MALWARE_CLEANUP":[^}]*}'   # keep_original_files_days
imunify360-agent malware malicious list --limit 5000 > /root/for-analysis/imunify-full.txt
du -sh /var/imunify360/* 2>/dev/null
```

Với `trim_file_instead_of_removal: true`, file có status `cleanup_done` vẫn còn trên đĩa nhưng
đã bị xoá rỗng nội dung — tên file và metadata còn, payload mất.

---

## Ghi lại gì kèm theo file

Phân tích chỉ tốt bằng ngữ cảnh có được. Ghi lại:

1. **Server**: OS và version, panel, **web server nào đang thực sự phục vụ request**
   (`ss -ltnp | grep -E ':(80|443)'` — đừng suy ra từ binary đã cài)
2. **Ứng dụng**: WordPress, Joomla, Laravel, hay code tay? Version bao nhiêu? Plugin/component/
   theme nào, version nào?
3. **Phát hiện ra sao**: Google Search Console cảnh báo? Nhà cung cấp báo spam? Site bị deface?
   Disk đầy? Mỗi dấu hiệu chỉ ra một mục đích khác của attacker.
4. **Mốc thời gian**: lần cuối site còn hoạt động bình thường là khi nào? Nó giới hạn phạm vi
   cần tìm.

---

## Xử lý mẫu

Coi mẫu đã lấy là mã độc sống trong suốt thời gian còn giữ.

- Để ngoài mọi webroot — `/root/for-analysis` thì được, `public_html` thì không
- Không bao giờ commit vào repository. `samples/` trong repo này đã gitignore; push mã độc lên
  host công khai là phát tán nó và bị khoá account
- Không gửi kèm vào issue hay email. Nếu cần minh hoạ một lỗ hổng signature, viết một bản
  tái hiện tối giản tổng hợp — xem [SECURITY.md](../../SECURITY.md)
- Xoá khi phân tích xong
