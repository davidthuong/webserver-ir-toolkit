# Có Imunify360 mà vẫn bị shell — chẩn đoán tại sao

Đây là câu hỏi quan trọng nhất trong tình huống của b. Imunify360 bắt webshell rất tốt **khi
được cấu hình đúng**. Bị lọt gần như luôn rơi vào 6 nguyên nhân dưới đây, xếp theo tần suất
thực tế.

Chạy hết phần "Kiểm tra" trước, rồi mới sửa.

---

## 1. Proactive Defense đang ở mode `log` hoặc `disabled`

Mặc định sau khi cài là **`log`** ở nhiều bản — nghĩa là nó *ghi nhận* shell chạy nhưng
**không chặn**. Đây là lý do số 1.

```bash
imunify360-agent config show | grep -A6 -i proactive
```

Sửa:
```bash
imunify360-agent config update '{"PROACTIVE_DEFENSE": {"mode": "kill"}}'
imunify360-agent config show | grep -A6 -i proactive     # xác nhận lại
```

> Chạy `kill` mode một thời gian rồi soi `/var/log/imunify360/console.log` xem có chặn nhầm
> plugin hợp lệ không. Đừng vì 1 false positive mà chuyển ngược về `log`.

---

## 2. PHP extension của Imunify không load cho version PHP mà site đang chạy

**Đây là nguyên nhân âm thầm nhất.** Proactive Defense hoạt động bằng một extension PHP.
Nếu server có PHP 7.4 / 8.0 / 8.1 / 8.2 mà extension chỉ load cho một vài version, thì
mọi site chạy version còn lại **hoàn toàn không được bảo vệ** — Imunify vẫn báo "đang bật".

Kiểm tra **từng** PHP version có trên máy:

```bash
# Plesk
for p in /opt/plesk/php/*/bin/php; do
  echo "=== $p ==="; $p -m 2>/dev/null | grep -i imunify || echo "  !! KHÔNG CÓ extension"
done

# DirectAdmin (CustomBuild)
for p in /usr/local/php*/bin/php; do
  echo "=== $p ==="; $p -m 2>/dev/null | grep -i imunify || echo "  !! KHÔNG CÓ extension"
done

# xem site nào chạy version nào
plesk bin site --list | while read d; do echo "$d: $(plesk bin site --info "$d" 2>/dev/null | grep -i php)"; done   # Plesk
grep -h php_ver /usr/local/directadmin/data/users/*/user.conf | sort | uniq -c                                       # DirectAdmin
```

Version nào thiếu extension → cài lại hardened PHP cho version đó, hoặc chuyển site sang
version đã có extension.

---

## 3. License hết hạn → agent chạy nhưng không cập nhật signature

Agent vẫn sống, dashboard vẫn hiện, nhưng database signature đứng yên từ ngày hết hạn.

```bash
imunify360-agent register --status
imunify360-agent version
ls -la /var/imunify360/                     # xem file signature update lần cuối lúc nào
```

Nếu ngày update signature cách đây vài tháng → license hoặc kết nối ra ngoài có vấn đề.
Nhớ là ở Phase 1 của Playbook b có thể đã chặn outbound — kiểm tra firewall không chặn
nhầm domain của CloudLinux.

---

## 4. Thư mục site nằm ngoài phạm vi quét, hoặc bị đưa vào ignore list

```bash
imunify360-agent malware ignore list
imunify360-agent config show | grep -A10 -i malware_scanning
```

Ignore list là chỗ hay bị bỏ quên: một admin trước đó thêm `/home` hoặc `/var/www/vhosts`
vào để tránh false positive, và thế là mù luôn. Xoá entry sai:

```bash
imunify360-agent malware ignore delete --path /duong/dan/sai
```

Ngoài ra nếu site đặt ở đường dẫn tự chế (không phải `/home/*/domains` hay
`/var/www/vhosts`), Imunify có thể không tự nhận ra là webroot.

---

## 5. Real-time scan (inotify) chưa bật → chỉ quét theo lịch

Không có inotify thì shell upload lúc 2h sáng sẽ sống tới lần quét kế tiếp.

```bash
imunify360-agent config show | grep -i inotify
imunify360-agent config update '{"MALWARE_SCANNING": {"enable_scan_inotify": true}}'
```

Kiểm tra giới hạn watcher của kernel — CentOS 7 mặc định thấp, nhiều file thì inotify
âm thầm chết:
```bash
cat /proc/sys/fs/inotify/max_user_watches      # mặc định 8192, quá ít
echo 'fs.inotify.max_user_watches=524288' >> /etc/sysctl.conf && sysctl -p
```

---

## 6. WebShield tắt → không chặn được ở tầng HTTP

```bash
imunify360-agent config show | grep -A8 -i webshield
imunify360-agent config update '{"WEBSHIELD": {"enable": true}}'
```

---

## Quét lại toàn bộ ngay bây giờ

```bash
# xem Imunify đã biết những file độc nào
imunify360-agent malware malicious list --limit 200

# quét on-demand toàn bộ webroot
imunify360-agent malware on-demand start --path /var/www/vhosts     # Plesk
imunify360-agent malware on-demand start --path /home               # DirectAdmin
imunify360-agent malware on-demand status

# sức khoẻ agent
imunify360-agent doctor
```

> Cú pháp CLI có thay đổi giữa các version. Nếu lệnh nào báo lỗi:
> `imunify360-agent --help` và `imunify360-agent malware --help`.

---

## Quan trọng: đừng dựa hoàn toàn vào Imunify

Imunify360 **không** kiểm tra phần lớn những thứ ở section 5 của `webshell-triage.sh`:
cron của user, systemd unit lạ, SSH authorized_keys bị thêm, `.forward` backdoor,
`ld.so.preload`. Nó tập trung vào file độc trong webroot.

Server đã bị shell thì backdoor persistence hay nằm ở đúng những chỗ đó — Imunify dọn sạch
webroot xong, cron vẫn tải shell về lại sau 10 phút. **Chạy cả hai.**

---

## Checklist

```
[ ] PROACTIVE_DEFENSE mode = kill (không phải log/disabled)
[ ] Extension imunify load cho TẤT CẢ PHP version đang dùng
[ ] License còn hạn, signature update gần đây
[ ] Ignore list không chứa webroot
[ ] enable_scan_inotify = true + max_user_watches đã nâng
[ ] WebShield enable = true
[ ] Đã chạy on-demand scan toàn bộ sau khi sửa config
[ ] Đã chạy webshell-triage.sh để bắt phần persistence Imunify bỏ qua
```
