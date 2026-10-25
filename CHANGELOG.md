# CHANGELOG — Lịch sử review & sửa lỗi bảo mật

File này thay cho các file báo cáo / changelog trung gian của từng vòng (đã gộp vào đây và xóa đi).
Không chứa bất kỳ giá trị bí mật nào.

---

## Tổng quan 4 vòng

| Vòng | Ai sửa | Nội dung chính |
|---|---|---|
| 1 | Gemini | Đóng các lỗ hổng nghiêm trọng: đăng nhập nhanh không cần mật khẩu, không phân quyền dashboard (IDOR), bypass IP whitelist qua header, secret mặc định viết cứng, không chống replay trong 300s, endpoint ký HMAC hộ bằng secret thật, logic chuyển tiền (số tiền âm), tự cấp scope / TTL vô hạn, unlock "hồi sinh" key đã thu hồi. Thêm cờ `DEMO_MODE` để bọc tính năng demo thay vì xóa |
| 2 | Gemini | Sửa phần làm sai/thiếu của vòng 1: sai secret làm đóng băng key người khác (DoS chỉ cần prefix), `X-Simulated-IP` nhận từ mọi IP, rotate key với ân hạn khổng lồ / lỗi 500, lộ audit log cho developer, lỗi 500 do sai kiểu dữ liệu, ẩn nút/link theo quyền & trạng thái, xóa secret bị chép nhầm vào tài liệu |
| 3 | Claude | Lỗi 429/401 của API trả JSON; bỏ API cũ `get_or_404`; **gom mọi bí mật vào một file `.env`** (thêm `scripts/tao_env.py`); hướng dẫn chạy; dọn file thừa |
| 4 | Claude | Chuẩn hóa theo NIST: băm mật khẩu PBKDF2-HMAC-SHA256 600.000 vòng (SP 800-132, có rehash hash Argon2 cũ), chính sách mật khẩu SP 800-63B-4 (tối thiểu 15 ký tự, blocklist, không quy tắc thành phần), dẫn xuất khóa Fernet bằng HKDF (SP 800-56C Rev.2, MultiFernet giữ dữ liệu cũ); giao diện sáng/tối; thêm `KIEN_THUC_AP_DUNG.md` |

Mọi lỗ hổng mức Nghiêm trọng / Cao phát hiện qua 3 vòng đều đã được kiểm chứng bằng PoC là **đã đóng**, ở cả `DEMO_MODE=0` và `DEMO_MODE=1`.

---

## Vòng 3 — chi tiết

### P1 — Lỗi 429 của `/api/...` trả JSON
- `app/__init__.py`: thêm `@app.errorhandler(429)`. Request tới `/api/...` nhận JSON `error_code = "TOO_MANY_REQUESTS"` (kèm `Retry-After` nếu có); các trang web giữ trang 429 mặc định.
- Lý do: trước đây vượt limiter 120 request/phút/IP trả trang HTML, Playground gọi `resp.json()` sẽ lỗi.
- Test: `test_v3_api_global_limit_returns_json`, `test_v3_web_rate_limit_still_html`.

### P2 — Endpoint API chưa đăng nhập trả 401 JSON
- `app/__init__.py`: thêm `@login_manager.unauthorized_handler`. Với `/api/...` trả `401` JSON `LOGIN_REQUIRED`; các trang web vẫn flash thông báo và chuyển hướng về `/auth/login` như cũ.
- Ảnh hưởng: chỉ `/api/v1/demo/compute-hmac` khi chưa đăng nhập (trước là 302).
- Test: `test_v3_compute_hmac_unauth_json_401`, `test_v3_dashboard_unauth_still_redirects`.

### P3 — Bỏ API cũ `Query.get_or_404`
- `app/routes/dashboard.py` (rotate / revoke / unlock): `ApiKey.query.get_or_404(id)` thành `db.get_or_404(ApiKey, id)`. Hành vi không đổi; hết `LegacyAPIWarning`.

### P4 — Gom toàn bộ bí mật vào một file `.env`
- **Trước:** raw key + signing secret của 8 key demo và mật khẩu `dev_hoang` viết cứng trong `app/services/seed_service.py`; mật khẩu demo viết cứng trong `login.html`, `seed.py`.
- **Sau:**
  - `app/services/seed_service.py`: `DEMO_KEYS_CATALOG` đọc `DEMO_KEY_<TÊN>` / `DEMO_SIGNING_SECRET_<TÊN>` từ `.env`. Thêm hàm `missing_demo_secrets()`. Mật khẩu demo lấy từ `config.DEMO_ADMIN_PASSWORD` / `DEMO_DEV_PASSWORD`.
  - `app/config.py`: thêm `DEMO_ADMIN_PASSWORD`, `DEMO_DEV_PASSWORD` (đọc từ `.env`).
  - `app/__init__.py`: nếu `DEMO_MODE=1` mà `.env` thiếu key demo thì dừng ngay, báo rõ tên biến thiếu.
  - `app/templates/login.html`: bỏ mật khẩu viết cứng trên nút đăng nhập nhanh; ô mật khẩu chỉ điền sẵn (lấy từ `.env`) khi `DEMO_MODE=1`.
  - `seed.py`: không in mật khẩu viết cứng.
  - **Mới** `scripts/tao_env.py`: sinh `.env` đầy đủ (khóa server, mật khẩu demo, 8 cặp key demo) bằng CSPRNG. Prefix key demo giữ cố định (`ak_live_1001full`, …) để khớp tài liệu; phần bí mật ngẫu nhiên. Không ghi đè `.env` có sẵn nếu không có `--force`.
  - **Mới** `tests/conftest.py`: bộ key "TESTONLY" riêng cho test, nên test không cần `.env`.
  - `.env.example`: cập nhật đủ cấu trúc, chỉ có placeholder `CHANGE_ME`.
  - `.gitignore`: thêm `.env.*` (trừ `.env.example`) để chặn cả các bản sao lưu `.env`.
- Test: `test_v3_tao_env_generates_all_secrets`, `test_v3_no_demo_secret_in_source`.

### P5 — Tài liệu & dọn dẹp
- **Mới** `HUONG_DAN_CHAY.md`: cài đặt, tạo `.env`, seed, chạy, test, lỗi thường gặp.
- `README.md`: thêm mục Quản lý bí mật, Hạn chế đã biết; trỏ sang `HUONG_DAN_CHAY.md`.
- `DANH_GIA_VA_DE_XUAT.md`: cập nhật cây thư mục, số test, danh sách route 404 khi tắt demo.
- Đã xóa (đã gộp vào file này): `BAO_CAO_REVIEW_CHO_GEMINI.md`, `BAO_CAO_REVIEW_VONG2_CHO_GEMINI.md`, `BAO_CAO_VONG3_KE_HOACH_SUA.md`, `CHANGELOG_VONG1.md`, `CHANGELOG_FIX_V2.md`, và các file `.gitkeep` trong thư mục đã có code.
- Đính chính `CHANGELOG_FIX_V2.md` (đã xóa): 2 tên test bị ghi sai; tên đúng là `test_replay_same_signature_rejected` và `test_no_seed_when_not_demo`.

### Kiểm chứng vòng 3
- `pytest -q`: **59 passed** (10 test gốc không đổi + 24 vòng 1 + 19 vòng 2 + 6 vòng 3).
- PoC vòng 1+2 chạy lại ở cả `DEMO_MODE=0/1`: không lỗ hổng nào tái hiện được.
- Bấm thử trên trình duyệt thật (server tạm, `.env` và DB tạm): 13 nút Playground (kịch bản 0 → 8C) cho kết quả đúng, không lỗi JavaScript, không lỗi CSP; Dashboard, Logs, DB Inspector hiển thị bình thường.

| # | Tính năng | DEMO_MODE=1 | DEMO_MODE=0 |
|---|---|---|---|
| R1 | Đăng nhập bằng mật khẩu | ✅ | ✅ |
| R2 | Đăng nhập nhanh 1-Click | ✅ | ✅ ẩn, 404 |
| R3 | Đăng ký developer | ✅ | ✅ |
| R4 | Tạo key Show-Once / Rotate / Revoke / Unlock | ✅ | ✅ |
| R5 | Reset Demo | ✅ (admin) | ✅ ẩn, 404 |
| R6 | Playground 0 → 8 | ✅ (đã bấm trên trình duyệt) | ✅ ẩn, 404 |
| R7 | Logs / DB Inspector | ✅ | ✅ Logs; DB Inspector 404 |
| R8 | pytest | ✅ 59/59 | ✅ |
