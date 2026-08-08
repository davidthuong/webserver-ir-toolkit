# Bộ công cụ xử lý sự cố web server

Công cụ triage **chỉ đọc** và quy trình xử lý cho server shared hosting bị webshell —
DirectAdmin, Plesk, cPanel hoặc không panel, trên Apache, nginx, OpenLiteSpeed và
LiteSpeed Enterprise.

**Không có gì trong repo này xoá, di chuyển, chmod hay sửa bất kỳ file nào trên server được
kiểm tra.** Scanner chỉ đọc và ghi ra một file báo cáo. Mọi bước có tính phá hoại đều để cho
người đọc báo cáo tự quyết định.

🇬🇧 **[English documentation](../../README.md)**

---

## Vì sao cần thêm một bộ nữa

Phần lớn hướng dẫn về webshell dừng ở "chạy scanner rồi xoá cái nó tìm được". Cách đó bỏ qua
hai thứ quyết định server có sạch lâu dài hay không:

**Persistence nằm ngoài webroot.** Imunify360, maldet và ClamAV tìm file trong webroot. Chúng
không kiểm cron của user, systemd unit, `authorized_keys`, file `.forward`, hay
`/etc/ld.so.preload`. Dọn sạch mà sót một dòng cron thì 10 phút sau shell về lại.

**Đường vào.** Xoá shell mà không tìm ra đường upload là một vòng lặp, không phải cách sửa.
Bộ công cụ này đối chiếu access log với mtime của file để định vị lỗ hổng đã cho file vào.

Và một cái bẫy làm mất thời gian hơn mọi cái khác: viết rule `.htaccess` trên web server không
bao giờ đọc `.htaccess`. Xem [MITIGATION.md](MITIGATION.md).

---

## Nội dung

| Tài liệu | Dùng để làm gì |
|---|---|
| [webshell-triage.sh](../../webshell-triage.sh) | Scanner chỉ đọc, 18 section |
| [PLAYBOOK.md](PLAYBOOK.md) | Quy trình 8 phase, đúng thứ tự |
| [MITIGATION.md](MITIGATION.md) | Chặn thực thi PHP — công thức đúng cho từng web server |
| [HARDENING.md](HARDENING.md) | Phòng ngừa, xếp theo hiệu quả trên công sức |
| [IMUNIFY360.md](IMUNIFY360.md) | Vì sao server có Imunify360 mà vẫn bị shell |
| [INTAKE.md](INTAKE.md) | Lấy mẫu về phân tích mà không bị AV xoá |

---

## Chạy

```bash
git clone https://github.com/davidthuong/webserver-ir-toolkit.git
sudo bash webserver-ir-toolkit/webshell-triage.sh --days 60
```

Tuỳ chọn:

```
--days N        cửa sổ thời gian cho phần "file mới sửa" (mặc định 30)
--root PATH     thêm webroot nếu script không tự tìm ra
--out FILE      chỗ ghi báo cáo (mặc định /root/triage-<host>-<time>.txt)
```

Đọc **section 2B** trước — nó cho biết web server nào đang thực sự phục vụ request, và điều đó
quyết định mọi biện pháp giảm thiểu khả dụng. Rồi tới **section 5** (persistence) và
**14** (đường vào).

---

## Script kiểm những gì

**Xâm nhập ở tầng web**
19 pattern signature webshell, obfuscation, PHP nhúng trong file ảnh, `.htaccess` / `.user.ini`
độc, file thực thi trong thư mục upload, double extension, file mới sửa, sai quyền và sai chủ
sở hữu, dấu hiệu timestomping.

**Persistence** — phần mà scanner thương mại bỏ qua
Cron của user (kể cả `crontab.conf` của DirectAdmin và ScheduledTasks của Plesk), systemd unit,
`rc.local`, file khởi động shell, `/etc/ld.so.preload`, `LD_PRELOAD`, SUID lạ, SSH
`authorized_keys`, sudoers, user UID 0, `.forward` backdoor, lạm dụng mail queue.

**Môi trường**
Web server và bản (edition), `.htaccess` có được đọc hay không, các PHP binary theo từng version
và version nào có extension bảo vệ, tình trạng scanner đã cài.

**Truy vết**
Đối chiếu access log với mtime của shell, endpoint task của component CMS và status code chúng
trả về, hoạt động đăng nhập panel/FTP/SSH, toàn vẹn binary hệ thống qua `rpm -Va`, checksum core
WordPress.

---

## Độ tin cậy của signature

Bộ 19 pattern được kiểm bằng 16 dạng webshell thật và 12 mẫu code sạch:

| | |
|---|---|
| Phát hiện đúng | 16/16 |
| Báo nhầm code sạch | 0/12 |

Mẫu đối chứng gồm đúng những cấu trúc mà pattern viết vội hay báo nhầm: `eval($template)`,
`call_user_func($this->handler, $_POST['data'])`, base64 ngắn của icon,
`$wpdb->prepare(..., $_GET['id'])`, và `array_map` với closure.

Shell chia 2 bước, tách variable function ra nhiều câu lệnh
(`$f = $_POST['a']; $f($_POST['b']);`) được bắt bằng cách yêu cầu **cả hai** nửa cùng nằm trong
một file, thay vì bằng pattern một dòng — chính điều đó giữ số false positive ở mức 0.

**Sửa `$SIG` thì phải test lại cả hai chiều.** Bộ pattern báo nhầm code hợp lệ sẽ bị bỏ qua, và
một scanner bị bỏ qua thì tệ hơn là không có.

---

## Giới hạn, nói thẳng

**Signature không thay được scanner chuyên dụng.** Điểm mạnh của bộ này là persistence và truy
vết đường vào. Chạy **song song** với Imunify360, maldet hoặc ClamAV, không phải thay thế.

**Báo cáo sạch không chứng minh server sạch.** Rootkit tầng kernel, implant chỉ nằm trong RAM,
và một attacker khéo đã dọn dấu vết sẽ không hiện ra ở đây.

**Bị chiếm quyền root thì dọn dẹp là vô nghĩa.** Nếu `/etc/ld.so.preload` có nội dung, có user
UID 0 lạ, hoặc `rpm -Va` báo binary hệ thống bị đổi → phải dựng lại trên hạ tầng mới. Xem
PLAYBOOK Phase 0.

**Đã kiểm chứng trên** CentOS 7 / dòng RHEL với DirectAdmin và Plesk, Apache và OpenLiteSpeed.
Phần đường dẫn cho cPanel, nginx, LiteSpeed Enterprise, CyberPanel và Debian/Ubuntu được viết
theo tài liệu nhà cung cấp, **chưa kiểm chứng thực tế** — rất mong được đóng góp sửa, xem
[CONTRIBUTING.md](../../CONTRIBUTING.md).

---

## Đừng commit dữ liệu sự cố

`samples/` và `reports/` nằm trong `.gitignore` có lý do. Thư mục đầu chứa mã độc thật — push
lên repo public là phát tán mã độc và bị khoá account. Thư mục sau chứa hostname, địa chỉ IP và
đường dẫn nội bộ.

Liếc `git status` trước mỗi lần commit.

---

## Thứ tự làm

1. **PLAYBOOK** Phase 0–1 — cô lập, giữ bằng chứng, chưa xoá gì
2. **IMUNIFY360** — nếu đã có scanner, tìm hiểu vì sao nó không chặn được
3. **webshell-triage.sh** — quét, đọc báo cáo
4. **MITIGATION** — khoanh vùng, dùng công thức cho web server thật của mình, rồi kiểm chứng
5. **PLAYBOOK** Phase 4 — tìm đường vào **trước khi** dọn
6. **PLAYBOOK** Phase 5–6 — dọn, đổi toàn bộ credentials
7. **HARDENING** — bịt bề mặt tấn công
8. **PLAYBOOK** Phase 8 — theo dõi 2–4 tuần; quét lại sau 48h và sau 1 tuần

---

## Giấy phép

MIT — xem [LICENSE](../../LICENSE).

Rất hoan nghênh đóng góp, đặc biệt là sửa chữa từ thực tế cho các stack đánh dấu chưa kiểm
chứng ở trên. **Đóng góp bằng tiếng Việt hoàn toàn được**, không cần dịch.
