# Cách đưa file cho t phân tích

## ⚠ Windows Defender sẽ xoá file shell

Lúc test t đã bị Defender **xoá thẳng** 3 file webshell mẫu ngay khi ghi ra đĩa. Nếu b copy
file shell thật về máy Windows với đuôi `.php`, khả năng cao nó biến mất hoặc bị khoá
(`Permission denied`) trước khi t kịp đọc.

**Cách an toàn — đổi đuôi thành `.txt` ngay trên server trước khi tải về:**

```bash
# trên server
mkdir -p /root/for-analysis
cp /path/to/shell.php /root/for-analysis/shell1.php.txt
cp /path/to/another.php /root/for-analysis/shell2.php.txt

# ghi lại metadata -- quan trọng không kém nội dung file
cd /root/for-analysis
for f in /path/to/shell.php /path/to/another.php; do
  stat -c '%n | size=%s | mtime=%y | ctime=%z | owner=%U:%G | perm=%a' "$f"
  sha256sum "$f"
done > metadata.txt
```

Rồi tải `/root/for-analysis/` về và bỏ vào [samples/](samples/).

Nếu vẫn bị Defender ăn: thêm thư mục `samples/` vào exclusion của Defender
(Settings → Privacy & security → Virus & threat protection → Manage settings →
Exclusions → Add folder), hoặc đơn giản là **paste thẳng nội dung file vào chat**.

---

## Bỏ file vào đâu

| Thư mục | Nội dung |
|---|---|
| [samples/](samples/) | File shell nghi ngờ, đổi đuôi thành `.txt` + `metadata.txt` |
| [reports/](reports/) | Output của `webshell-triage.sh` (`/root/triage-*.txt`) |

---

## Cùng với file, cho t biết:

1. **Server nào, panel gì** (DirectAdmin hay Plesk), OS + version
2. **Site chạy gì** — WordPress / Laravel / code tay? Version bao nhiêu?
3. **Phát hiện lúc nào, bằng cách nào** — Google cảnh báo? Host báo spam? Site chậm?
4. **Access log quanh mtime của shell** — đây là thứ chỉ ra đường vào:

```bash
# lấy mtime của shell
stat -c '%y' /path/to/shell.php     # ví dụ ra 2026-08-05 14:23

# xuất log ±2 tiếng quanh mốc đó
grep '05/Aug/2026:1[2-6]' /var/log/httpd/domains/site.com.log > /root/for-analysis/access-window.log   # DirectAdmin
grep '05/Aug/2026:1[2-6]' /var/www/vhosts/system/site.com/logs/access_log > /root/for-analysis/access-window.log  # Plesk
```

---

## Vì đã xác định chỉ nhiễm ở tầng web

Xác nhận lại cho chắc bằng 30 giây — nếu bất kỳ dòng nào dưới đây ra kết quả bất thường
thì kết luận "chỉ tầng web" sai, và phải chuyển sang phương án rebuild
(xem `PLAYBOOK.md`, Phase 0):

```bash
cat /etc/ld.so.preload 2>/dev/null && echo "!!! ROOTKIT"      # phải rỗng / không tồn tại
awk -F: '$3==0' /etc/passwd                                    # chỉ được có dòng root
rpm -Va coreutils util-linux openssh-server bash procps-ng     # phải không ra gì
ls -la /root/.ssh/authorized_keys 2>/dev/null                  # key lạ?
for p in /proc/[0-9]*; do readlink $p/exe; done | grep -E 'deleted|^/tmp|^/dev/shm'
```
