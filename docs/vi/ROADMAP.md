# Lộ trình

Dự án đang ở đâu, cái gì đã kiểm chứng, và sắp làm gì.

🇬🇧 **[English version](../../ROADMAP.md)**

Toàn bộ bộ công cụ này được viết trong lúc xử lý sự cố thật trên shared hosting. Phân biệt
quan trọng nhất trong tài liệu này là giữa **cái đã chạy thật trên server bị chiếm** và **cái
viết theo tài liệu nhà cung cấp**. Cả hai đều được phát hành; chỉ một cái đã được chứng minh.

---

## Hiện trạng

Scanner có 20 section và **chỉ đọc** theo thiết kế —
[tools/verify-readonly.sh](../../tools/verify-readonly.sh) chứng minh điều đó bằng thực nghiệm
thay vì khẳng định suông. [tools/test-signatures.sh](../../tools/test-signatures.sh) làm điều
tương tự cho bộ pattern. Tài liệu duy trì song song tiếng Anh và tiếng Việt.

### Khả năng phát hiện, và cách đo

| Lớp | Kết quả | Cách đo |
|---|---|---|
| Signature webshell | 16/16 phát hiện, 0/12 báo nhầm | 16 dạng shell thật, đối chứng bằng 12 mẫu code sạch chọn đúng những cấu trúc mà pattern viết vội hay báo nhầm. Là phép đo một lần trên mẫu sống, **không** chạy lại được từ repo này |
| Bộ mẫu hồi quy cho signature | 19/19 phát hiện, 0/16 báo nhầm, 19/19 pattern có mẫu | `tools/test-signatures.sh`, commit kèm và chạy lại được: mỗi pattern một fixture tổng hợp, cộng các mẫu code sạch đối chứng. Đã kiểm là nó **thất bại đúng lúc cần** — pattern hỏng cú pháp, pattern bị xoá, pattern quá tham, và report rỗng |
| Chống dọn + inject client-side | 5/5 phát hiện, 0/7 báo nhầm | Mẫu lấy từ một vụ xâm nhập thật, gồm loader dùng XOR key lặp |
| Ngưỡng phát hiện tổng quát | Phân biệt rõ | Đo thật: payload độc có chuỗi base64 **56.030** ký tự, icon nhúng hợp lệ **1.467** |
| Đảm bảo chỉ đọc | PASS | Chạy trọn 20 section trên cây thử; sha256, quyền và danh sách file giống hệt trước/sau |

Hai dòng về signature **không** nói cùng một điều. Dòng đầu là kết quả mã độc thật đối đầu với
bộ pattern, một lần; dòng sau là thứ bất kỳ ai cũng chạy lại được sau khi sửa pattern. Không
cái nào thay được cái nào, và lý do bộ mẫu là tổng hợp: repo này không chứa mã độc thật.

Cả hai bài tự kiểm chạy trong [CI](../../.github/workflows/tests.yml) ở mỗi lần push và mỗi
pull request: trên runner Ubuntu với quyền root, và trong container CentOS 7, AlmaLinux 8 và 9,
Debian 12, Ubuntu 24.04. Đó là nơi lớp đầu-cuối của bài test signature — lớp chạy scanner rồi
đọc ngược report — lần đầu chạy với chính `webshell-triage.sh` thay vì một scanner giả sinh ra
report. Trên cả sáu môi trường, scanner chạy trọn 20 section và report gọi tên đủ mọi fixture.

Điều một lần chạy xanh **không** chứng minh, nói rõ đúng tinh thần của tài liệu này: bất cứ thứ
gì liên quan tới control panel. Không runner nào cài DirectAdmin, Plesk hay cPanel, nên CI chỉ
kiểm scanner trên hệ điều hành, bash và grep đó với một webroot tổng hợp, và không nói gì về
việc nhận diện panel, crontab theo user hay đường dẫn log của panel. Bảng bên dưới không đổi vì
nó. Phần kiểm chứng thực tế đứng sau bảng đó đến từ một host production mà nhóm duy trì không
còn quyền truy cập, nên các dòng ấy là ghi nhận về thứ đã quan sát được, không phải thứ được
kiểm lại sau mỗi thay đổi.

### Phạm vi nền tảng

| Stack | Trạng thái |
|---|---|
| CentOS 7 / dòng RHEL | **Đã kiểm chứng thực tế** trên CentOS 7; AlmaLinux 8 và 9 mới chỉ trong CI |
| DirectAdmin | **Đã kiểm chứng thực tế** |
| OpenLiteSpeed | **Đã kiểm chứng thực tế** — gồm cả việc `.htaccess` bị bỏ qua trong im lặng |
| ProFTPD | **Đã kiểm chứng thực tế** |
| Imunify360 | **Đã kiểm chứng thực tế** |
| Apache | Một phần — đã xử lý đường dẫn và `AllowOverride`, chưa chạy trên host Apache bị chiếm |
| Plesk | Theo tài liệu |
| cPanel | Theo tài liệu |
| nginx | Theo tài liệu |
| LiteSpeed Enterprise | Theo tài liệu — phân biệt edition rất quan trọng, và script **từ chối đoán** |
| CyberPanel, Virtualmin | Chỉ mới có đường dẫn log |
| Debian / Ubuntu | Scanner và cả hai bài tự kiểm chạy trong CI; đường dẫn package và log viết theo tài liệu, chưa chạy trên host bị chiếm |

Hai tính năng **chưa từng dùng** trên sự cố thật: `--http` (fetch black-box và so sánh
cloaking) và `--checksums` (đối chiếu package WordPress). Cái thứ hai xét về cấu trúc là check
mạnh nhất trong toàn bộ toolkit, vì nó hỏi file có khớp bản upstream phát hành hay không, chứ
không hỏi nó có giống thứ ai đó từng mô tả hay không.

---

## Sắp làm

Xếp theo mức giảm rủi ro report bị sai trong im lặng.

**Kiểm toàn vẹn cho Joomla.** WordPress có `wp core verify-checksums` và
`wp plugin verify-checksums` — đó là check duy nhất tìm được họ mã độc chưa ai mô tả. Joomla
không có tương đương, và hướng dẫn hiện tại (diff với bản giải nén sạch cùng version) là quy
trình thủ công chứ không phải một check. Trong vụ sinh ra bộ công cụ này, **Joomla chiếm đa số
site bị chiếm**.

**Kiểm kê CMS và extension.** Xuất danh sách version trên mọi account của một host là việc máy
móc, và là đầu vào cho mọi câu hỏi "cái này có dính lỗ hổng không". Bản thân dữ liệu lỗ hổng
nằm ngoài phạm vi — xem mục không làm.

**Xuất định dạng máy đọc được.** Chế độ `--json` để đưa phát hiện vào hệ thống ticket hoặc so
sánh giữa các lần chạy. Report hiện chỉ dành cho người đọc.

**Công cụ baseline và drift.** `PLAYBOOK.md` Phase 8 mô tả việc lấy baseline hash sau khi dọn
rồi so sánh hằng ngày — nhưng đó là văn xuôi, không phải script. So sánh baseline là **cách
phát hiện duy nhất không phụ thuộc việc nhận ra mã độc**, nên xứng đáng thành công cụ.

**Bảng thuật ngữ song ngữ.** `containment` và `mitigation` hiện có chỗ đang dịch lẫn nhau. Một
bảng thuật ngữ sẽ giữ hai nhánh ngôn ngữ không trôi xa nhau khi có người đóng góp.

---

## Về sau

**Công cụ dọn dẹp có backup và rollback**, tách hoàn toàn khỏi scanner và không bao giờ được
scanner gọi. Đảm bảo chỉ đọc chính là lý do người xử lý sự cố dám chạy scanner giữa lúc đang
có sự cố, và đảm bảo đó không thương lượng. Công cụ dọn nếu có sẽ nhận **danh sách file do
người duyệt** làm đầu vào.

**Sửa chữa từ thực tế cho các stack chưa kiểm chứng.** Đây là thứ người bảo trì không tự tạo
ra được; cần người đang vận hành đúng stack đó. Một dòng sửa đường dẫn log giá trị hơn một
tính năng mới.

---

## Không làm

**Không khai thác, không quét host mình không quản trị, không có chức năng "kiểm tra xem người
khác có dính không".** Đây là công cụ phòng thủ để soi server của chính mình.

**Không tự động xoá hay quarantine trong scanner.** Như trên — tính chất chỉ đọc là thứ chịu
lực.

**Không duy trì cơ sở dữ liệu lỗ hổng.** Các advisory được trích dẫn như ví dụ minh hoạ cách
truy đường vào, kèm liên kết tới nhà cung cấp để tra phạm vi version hiện hành. Tự nuôi dữ
liệu version ở đây sẽ tạo ra một cơ sở dữ liệu cũ mà người ta lại tin.

**Không thay thế scanner thương mại.** Điểm mạnh của bộ này là bề mặt persistence và truy vết
đường vào — thứ Imunify360, maldet và ClamAV không phủ. Chạy **song song**, không thay thế.

---

## Đóng góp

Xem [CONTRIBUTING.md](../../CONTRIBUTING.md). Đóng góp giá trị nhất, theo thứ tự: sửa chữa cho
các stack đánh dấu chưa kiểm chứng ở trên, code sạch bị scanner báo nhầm, và kỹ thuật né tránh
mà pattern bỏ sót — mô tả bằng **bản tái hiện tối giản tổng hợp**, không bao giờ gửi kèm mẫu thật.

**Đóng góp bằng tiếng Việt hoàn toàn được**, không cần dịch.
