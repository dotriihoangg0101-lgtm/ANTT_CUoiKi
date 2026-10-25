# Xây Dựng Ứng Dụng Web Quản Lý, Cấp Phát Và Kiểm Soát API Key An Toàn
**Học phần:** Lập trình An ninh Thông tin — HUTECH  

---

## 1. Kiến Trúc Bảo Mật Đã Triển Khai

> Chuẩn áp dụng và giải thích chi tiết từng thuật toán: xem [KIEN_THUC_AP_DUNG.md](KIEN_THUC_AP_DUNG.md).

1. **Bảo vệ Mật khẩu Quản trị viên & Người dùng (`PBKDF2-HMAC-SHA256`, NIST SP 800-132 & SP 800-63B-4)**:
   - Băm bằng `hashlib.pbkdf2_hmac("sha256")`, **600.000 vòng**, salt ngẫu nhiên **128 bit**, đầu ra 256 bit; định dạng lưu `$pbkdf2-sha256$<vòng>$<salt>$<hash>`.
   - Chính sách mật khẩu theo **NIST SP 800-63B-4 (08/2025)**: tối thiểu **15 ký tự**, tối đa 128, kiểm tra danh sách mật khẩu phổ biến và từ theo ngữ cảnh, **không** bắt buộc chữ hoa/số/ký tự đặc biệt (`app/services/password_policy.py`).
   - Hash Argon2id cũ vẫn đăng nhập được và tự động băm lại sang PBKDF2 ở lần đăng nhập thành công kế tiếp.
   - Phân quyền chặt chẽ (**RBAC / Chống IDOR**): Tài khoản `developer` chỉ được xem và thao tác trên các API Key của chính mình, không được tự cấp các scope nhạy cảm (`admin:records`, `transfer:funds`). Các trang `/db-inspector`, `/logs`, `/dashboard/reset-demo` yêu cầu quyền `admin` (`@admin_required`).
2. **Cấp phát & Lưu trữ API Key Không lộ Plaintext (`CSPRNG + HMAC-SHA256 + Pepper`)**:
   - Sinh khóa bằng `secrets.token_urlsafe(24)` (**24 byte entropy → 32 ký tự URL-safe**) kết hợp với prefix theo định dạng 4 phần: `ak_<live|test>_<8_ky_tu_id>_<32_chars_secret>`.
   - Chuỗi `key_prefix` lưu trong Database có độ dài **16 ký tự** (ví dụ `ak_live_9f8a1b2c` đối với key sinh ngẫu nhiên bằng `secrets.token_hex(4)`, hoặc các prefix định danh cố định như `ak_live_1001full` trong bộ `DEMO_KEYS_CATALOG`).
   - Chỉ hiển thị API Key gốc **đúng 1 lần duy nhất (Show-Once Pattern)** bằng cách render trực tiếp trong HTTP response của thao tác tạo/rotate (không lưu raw key hay signing secret vào cookie `session`).
   - Trong Database (`api_keys`), chỉ lưu `key_prefix` (16 ký tự) và mã băm một chiều `key_hash = HMAC-SHA256(raw_key, API_KEY_PEPPER)`.
   - Đối chiếu mã băm bằng thuật toán hằng thời gian `hmac.compare_digest()` chống **Timing Side-Channel Attack**.
   - Kiểm tra nghiêm ngặt các biến môi trường bí mật (`SECRET_KEY`, `API_KEY_PEPPER`, `MASTER_ENCRYPTION_KEY`) qua `validate_secrets(app)` ngay khi khởi động: từ chối chạy nếu thiếu, rỗng, ngắn hơn 32 ký tự hoặc dùng lại giá trị mẫu trong `.env.example`.
3. **Mã hóa Dữ liệu Nhạy cảm trên Đĩa (`Fernet AES-128-CBC + HMAC-SHA256`)**:
   - Cột `signing_secret_enc` (trong bảng `api_keys`) và cột `encrypted_secret_note` (trong bảng `vault_records`, đi kèm `account_number_masked`) được mã hóa đối xứng bằng `cryptography.fernet.Fernet`.
   - Khóa Fernet 256 bit được dẫn xuất từ `MASTER_ENCRYPTION_KEY` bằng **HKDF-SHA256** (RFC 5869, NIST SP 800-56C Rev.2). Dùng `MultiFernet` nên dữ liệu mã hóa bằng khóa kiểu cũ vẫn giải mã được.
4. **Middleware Kiểm Soát Truy Cập 6 Lớp (`@require_api_key`)**:
   - **Chốt chặn 0 (CWE-598)**: Cấm truyền API Key trên URL Query String (`?api_key=...`), trả về `400` với `error_code = "API_KEY_IN_URL_FORBIDDEN"`.
   - **Lớp 1**: Xác thực cấu trúc 4 phần & đối chiếu mã băm `HMAC-SHA256` hằng thời gian (`hmac.compare_digest`). Sai secret không được đếm vào `failed_attempts` (nhằm chống tấn công DoS khóa key thông qua prefix công khai); brute-force secret được chặn bởi Rate Limit `120 per minute` theo IP trên toàn bộ `/api/v1`.
   - **Lớp 2**: Kiểm tra Vòng đời Key (Thu hồi `API_KEY_REVOKED`, Đóng băng tự động `API_KEY_AUTO_FROZEN`, Hết hạn `API_KEY_EXPIRED`, Hết ân hạn `ROTATION_GRACE_PERIOD_EXPIRED`). Trạng thái `REVOKED` là trạng thái cuối (không thể unlock hay rotate); thao tác **Rotate chỉ áp dụng cho key `ACTIVE`**. Các giới hạn nhập liệu được kiểm tra chặt chẽ ở tầng Service: `rate_limit_per_minute` trong khoảng `1..1000`, thời hạn TTL `expires_in_days` trong khoảng `1..365` ngày, và thời gian ân hạn `grace_period_hours` trong khoảng `1..168` giờ.
   - **Lớp 3**: Kiểm soát Địa chỉ mạng (`IP Whitelisting` & dải mạng `CIDR` bằng `ipaddress.ip_network(rule, strict=False)`). Giá trị `allowed_ips` bằng `*` hoặc rỗng `""` cho phép mọi IP; nếu chuỗi IP client không hợp lệ (không parse được bằng `ipaddress.ip_address`) thì từ chối ngay (`False`). Phản hồi `403` (`error_code = "IP_NOT_WHITELISTED"`) không làm lộ danh sách `allowed_ips`.
   - **Lớp 4**: Kiểm soát Phân quyền Đặc quyền tối thiểu (`Scope-based Authorization`: `read:records`, `write:records`, `admin:records`, `transfer:funds`). Khi thiếu quyền trả về `403` với `error_code = "INSUFFICIENT_SCOPE"` và `required_scopes` (không lộ `granted_scopes`).
   - **Lớp 5**: Kiểm soát Lưu lượng theo từng Key (`Per-Key Sliding-Window Rate Limiting`, tối đa `1..1000` req/phút) và theo IP (`120 per minute` trên toàn blueprint `/api/v1`), trả về `429 Too Many Requests` (`error_code = "RATE_LIMIT_EXCEEDED"`) kèm `Retry-After`.
   - **Lớp 6**: Xác thực Chữ ký số gói tin `HMAC-SHA256` (`X-Signature`) và `X-Timestamp` (±300s):
     - Chống sửa dữ liệu trên đường truyền (**MITM Tampering** → `401` với `error_code = "INVALID_HMAC_SIGNATURE_TAMPERED"`).
     - Chống phát lại gói tin quá hạn (**Expired Timestamp** → `401` với `error_code = "TIMESTAMP_EXPIRED_REPLAY_DETECTED"`).
     - Chống phát lại cùng một chữ ký trong cửa sổ 300s bằng bộ nhớ đệm `_SEEN_SIGNATURES` (**Anti-Replay Cache** → `401` với `error_code = "REPLAY_DETECTED"`).
5. **Phát hiện Xâm nhập & Tự động Đóng băng (`Auto-Freeze IDS`)**:
   - Ngưỡng cấu hình `AUTO_FREEZE_THRESHOLD = 5`.
   - Các loại vi phạm được đếm vào `failed_attempts` của Key (chỉ sau khi đã chứng minh sở hữu đầy đủ `raw_key` ở Lớp 1):
     1. Gọi từ địa chỉ IP không nằm trong Whitelist (`IP_NOT_WHITELISTED` ở Lớp 3).
     2. Gọi API vượt quá quyền hạn được cấp (`INSUFFICIENT_SCOPE` ở Lớp 4).
     3. Vi phạm chữ ký số HMAC hoặc Replay Attack (`INVALID_HMAC_SIGNATURE_TAMPERED`, `TIMESTAMP_EXPIRED_REPLAY_DETECTED`, `REPLAY_DETECTED`, `MISSING_SIGNATURE_OR_TIMESTAMP`, `INVALID_TIMESTAMP_FORMAT` ở Lớp 6).
   - Khi đạt **5 lần vi phạm liên tiếp**, hệ thống tự động khóa cứng Key (`is_active = False`, `status_label = "AUTO_FROZEN"`) và ghi cảnh báo mức `CRITICAL` vào `security_audit_logs`.

---

## 2. Các Cờ Cấu Hình An Ninh Quan Trọng (`DEMO_MODE`, `TRUST_PROXY`, `REPLAY_DETECTED`)

- **`DEMO_MODE` (Mặc định tắt `DEMO_MODE=0`)**:
  - Khi `DEMO_MODE=0` (môi trường thực tế/production): Hệ thống tự động vô hiệu hóa (trả về `404`) toàn bộ các tính năng phục vụ trình diễn gồm: đăng nhập nhanh `/auth/quick-login/<username>`, trang `/playground`, trang `/db-inspector`, endpoint `/api/v1/demo/compute-hmac`, nút `/dashboard/reset-demo`, bỏ qua header `X-Simulated-IP`, ẩn các liên kết demo trên thanh điều hướng, và không tự động seed dữ liệu mẫu.
  - Khi `DEMO_MODE=1` (cấu hình trong `.env` trên máy thuyết trình): Bật đầy đủ 8 kịch bản trên `/playground` và cho phép `quick-login` (chỉ với `admin`, `dev_hoang`) từ `127.0.0.1` / `::1`. Header `X-Simulated-IP` **chỉ có hiệu lực khi `DEMO_MODE=1` VÀ request thực sự đến từ địa chỉ loopback (`127.0.0.1` / `::1`)** và giá trị gửi lên là một địa chỉ IP hợp lệ.
- **`TRUST_PROXY` (Mặc định tắt `TRUST_PROXY=0`)**:
  - Hệ thống không bao giờ đọc trực tiếp header `X-Forwarded-For` do client tự gửi để tránh giả mạo IP. Chỉ khi chạy sau Reverse Proxy tin cậy và bật `TRUST_PROXY=1`, ứng dụng mới kích hoạt `Werkzeug ProxyFix(x_for=1)`.
- **`REPLAY_DETECTED`**:
  - Mỗi chữ ký `(key_id, signature)` hợp lệ đi qua Lớp 6 được lưu vào `_SEEN_SIGNATURES` với thời hạn `now + 300s`. Mọi nỗ lực gửi lại đúng gói tin đã ký lần thứ 2 trong vòng 300s đều bị từ chối với HTTP `401` và `error_code = "REPLAY_DETECTED"`.

---

## 3. Quản Lý Bí Mật (một file `.env` duy nhất)

Toàn bộ bí mật của dự án nằm trong **một file `.env`** ở thư mục gốc (đã có trong `.gitignore`, không bao giờ bị đẩy lên Git):

| Nhóm | Biến |
|---|---|
| Khóa phía server | `SECRET_KEY`, `API_KEY_PEPPER`, `MASTER_ENCRYPTION_KEY` |
| Mật khẩu tài khoản demo | `DEMO_ADMIN_PASSWORD`, `DEMO_DEV_PASSWORD` |
| 8 API Key demo của Playground | `DEMO_KEY_<TÊN>` và `DEMO_SIGNING_SECRET_<TÊN>` |

- Sinh file `.env` đầy đủ (mọi giá trị ngẫu nhiên bằng CSPRNG): `python scripts/tao_env.py`.
- Mã nguồn **không** chứa key, signing secret hay mật khẩu demo nào. Prefix của key demo (`ak_live_1001full`, …) là cố định để khớp tài liệu; phần bí mật phía sau được sinh ngẫu nhiên trên từng máy.
- Khi bật `DEMO_MODE=1` mà `.env` thiếu key demo, ứng dụng dừng ngay và in ra tên biến còn thiếu.
- Chia sẻ cho thành viên nhóm: gửi riêng file `.env` qua kênh riêng tư. File `.env.example` chỉ là mẫu cấu trúc.
- Test tự động dùng bộ key "TESTONLY" riêng trong `tests/conftest.py`, không cần `.env`.

---

## 4. Hướng Dẫn Chạy

Xem chi tiết từng bước trong **[HUONG_DAN_CHAY.md](HUONG_DAN_CHAY.md)**.

---

## 5. Hạn Chế Đã Biết (chấp nhận trong phạm vi đồ án)

1. **Cache chống Replay (`_SEEN_SIGNATURES`) và Rate Limit per-key lưu in-memory**: chỉ đúng khi chạy 1 process. Triển khai nhiều worker cần chuyển sang Redis (`SET NX EX 300`, `RATELIMIT_STORAGE_URI=redis://...`).
2. **Show-Once render trực tiếp trong response POST**: nếu bấm F5 ở trang kết quả tạo/xoay key, trình duyệt sẽ hỏi gửi lại form; đồng ý sẽ tạo thêm một key mới.
3. **`TRUST_PROXY=1` chỉ bật khi thật sự chạy sau reverse proxy tin cậy.** Nếu bật khi không có proxy, client có thể gửi `X-Forwarded-For: 127.0.0.1` để giả IP loopback (ảnh hưởng quick-login và `X-Simulated-IP` ở chế độ demo).
4. **Key demo hiển thị trên Playground**: ở `DEMO_MODE=1`, trang `/playground` đưa raw key demo xuống trình duyệt để bấm thử. Đây là chủ đích của chế độ demo; khi `DEMO_MODE=0` trang này trả 404.
5. **Giới hạn chung 120 request/phút/IP trên `/api/v1`** (chống dò secret): vượt ngưỡng trả `429` JSON `error_code = "TOO_MANY_REQUESTS"`. Endpoint API cần đăng nhập (`/api/v1/demo/compute-hmac`) trả `401` JSON `LOGIN_REQUIRED` thay vì chuyển hướng sang trang login.
