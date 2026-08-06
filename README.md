# Web Server Incident Response Toolkit

Bộ công cụ xử lý sự cố cho web server bị webshell / malware, dùng cho môi trường
**DirectAdmin** và **Plesk** trên CentOS 7 có **Imunify360**.

Toàn bộ script trong repo này là **read-only** — chỉ đọc và báo cáo, không xoá, không sửa,
không chmod bất cứ thứ gì trên server.

---

## Nội dung

| File | Dùng để làm gì |
|---|---|
| [webshell-triage.sh](webshell-triage.sh) | Scanner chính. 17 section: shell, persistence, entry point, tình trạng Imunify360 |
| [PLAYBOOK.md](PLAYBOOK.md) | Quy trình xử lý 8 phase, đúng thứ tự. Đọc trước khi động vào server |
| [IMUNIFY360.md](IMUNIFY360.md) | 6 nguyên nhân Imunify360 bỏ lọt shell và cách kiểm tra từng cái |
| [HARDENING.md](HARDENING.md) | Chống tái nhiễm. Mục 0 nói về rủi ro CentOS 7 EOL |
| [INTAKE.md](INTAKE.md) | Cách lấy mẫu shell về máy để phân tích mà không bị AV xoá |

---

## Chạy

```bash
scp webshell-triage.sh root@server:/root/
ssh root@server
sed -i 's/\r$//' /root/webshell-triage.sh      # bắt buộc nếu copy từ Windows
bash /root/webshell-triage.sh --days 60
```

Tuỳ chọn:

```bash
--days N        # cửa sổ thời gian cho phần "file mới sửa" (mặc định 30)
--root PATH     # thêm webroot nếu script không tự tìm ra
--out FILE      # đổi chỗ ghi report (mặc định /root/triage-<host>-<time>.txt)
```

Script tự nhận diện DirectAdmin / Plesk / cPanel và webroot tương ứng.

---

## Script kiểm những gì

**Xâm nhập ở tầng web**
- Signature webshell (19 pattern), obfuscation, PHP nhúng trong file ảnh
- `.htaccess` / `.user.ini` độc, file trong thư mục upload, double extension
- File mới sửa, sai quyền, sai chủ sở hữu, dấu hiệu timestomping

**Persistence** — phần mà Imunify360 và maldet **không** kiểm
- Cron của user (kể cả `crontab.conf` của DirectAdmin, ScheduledTasks của Plesk)
- systemd unit, `rc.local`, file khởi động shell
- `ld.so.preload`, `LD_PRELOAD`, SUID lạ
- SSH `authorized_keys`, sudoers, user UID 0
- `.forward` backdoor, lạm dụng mail queue

**Truy vết**
- Đối chiếu access log với `mtime` của shell để tìm đường vào
- Log đăng nhập panel / FTP / SSH
- Toàn vẹn binary hệ thống (`rpm -Va`), checksum core WordPress

---

## Độ tin cậy của signature

Bộ 19 pattern được kiểm bằng 16 dạng webshell thật và 12 mẫu code sạch:

| | |
|---|---|
| Phát hiện đúng | 16/16 |
| Báo nhầm code sạch | 0/12 |

Code sạch dùng làm đối chứng gồm những thứ hay bị báo nhầm: `eval($template)`,
`call_user_func($this->handler, $_POST['data'])`, `base64_decode` của icon,
`$wpdb->prepare(..., $_GET['id'])`, `array_map` với closure.

**Sửa signature thì phải test lại.** Pattern nằm trong heredoc `$SIG` của script.

---

## Cảnh báo

**Đừng commit dữ liệu sự cố.** `samples/` và `reports/` đã nằm trong `.gitignore`:
`samples/` chứa webshell thật (push lên là phát tán mã độc, GitHub sẽ khoá repo),
`reports/` chứa hostname, IP và đường dẫn nội bộ. Kiểm tra `git status` trước mỗi lần commit.

**Signature không thay được scanner chuyên dụng.** Script này mạnh ở phần persistence và
truy vết entry point. Chạy song song với Imunify360 hoặc maldet, đừng dùng thay.

**Nếu có dấu hiệu chiếm quyền root thì dọn dẹp là vô nghĩa.** `/etc/ld.so.preload` có nội
dung, user UID 0 lạ, hoặc `rpm -Va` báo binary hệ thống bị đổi → phải dựng server mới.
Xem `PLAYBOOK.md` Phase 0.

---

## Thứ tự làm

1. `PLAYBOOK.md` Phase 0–1 — cô lập, đừng xoá gì vội
2. `IMUNIFY360.md` — sửa config Imunify trước, nó đang có sẵn mà không chặn
3. `webshell-triage.sh` — quét, lấy report
4. `PLAYBOOK.md` Phase 4 — tìm entry point **trước khi** dọn
5. `PLAYBOOK.md` Phase 5–6 — dọn, đổi toàn bộ credentials
6. `HARDENING.md` — chống tái nhiễm
7. `PLAYBOOK.md` Phase 8 — theo dõi 2–4 tuần, chạy lại script sau 48h và sau 1 tuần
