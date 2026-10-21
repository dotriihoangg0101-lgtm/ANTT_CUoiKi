# HƯỚNG DẪN CHẠY ĐỒ ÁN

**Đề tài:** Xây dựng ứng dụng Web quản lý, cấp phát và kiểm soát API Key an toàn
**Yêu cầu:** Python 3.12 trở lên (Windows hoặc Linux/Kali), Git.

> Các lệnh dưới đây chạy ở **thư mục gốc dự án** (thư mục chứa `run.py`).
> Trên Windows dùng PowerShell; trên Linux/Kali thay `.\venv\Scripts\python.exe` bằng `venv/bin/python`.

---

## Bước 1 — Tạo môi trường ảo & cài thư viện (chỉ làm 1 lần)

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

**Linux / Kali:**
```bash
python3 -m venv venv
venv/bin/python -m pip install -r requirements-dev.txt
```

`requirements-dev.txt` đã bao gồm `requirements.txt` (thư viện chạy app) và thêm `pytest` để chạy test.

---

## Bước 2 — Chuẩn bị file bí mật `.env`

Mọi bí mật của dự án nằm trong **một file `.env` duy nhất**: khóa server, mật khẩu tài khoản demo, 8 API Key demo. File này **không có trên Git**. Chọn một trong hai cách:

**Cách A — Nhận file `.env` từ bạn cùng nhóm:** chép file đó vào thư mục gốc dự án (cùng chỗ với `run.py`). Mọi người dùng chung `.env` thì sẽ có chung mật khẩu và key demo.

**Cách B — Tự sinh file `.env` mới (mọi giá trị ngẫu nhiên):**
```powershell
.\venv\Scripts\python.exe scripts\tao_env.py
```
Nếu đã có `.env` mà muốn sinh lại toàn bộ khóa mới:
```powershell
.\venv\Scripts\python.exe scripts\tao_env.py --force
```
⚠️ Sau khi đổi khóa phải làm lại Bước 3 (xóa DB cũ rồi seed lại), vì dữ liệu mã hóa bằng khóa cũ không đọc được nữa.

Các biến chính trong `.env`:

| Biến | Ý nghĩa |
|---|---|
| `DEMO_MODE=1` | Bật tính năng thuyết trình: Playground, đăng nhập nhanh, DB Inspector, giả lập IP. Đặt `0` khi chạy thật |
| `FLASK_DEBUG=0` | Chỉ đặt `1` khi đang code (bật debugger) |
| `DEMO_ADMIN_PASSWORD` / `DEMO_DEV_PASSWORD` | Mật khẩu tài khoản `admin` / `dev_hoang` |
| `SECRET_KEY`, `API_KEY_PEPPER`, `MASTER_ENCRYPTION_KEY` | Khóa bí mật phía server, **không chia sẻ công khai** |
| `DEMO_KEY_*`, `DEMO_SIGNING_SECRET_*` | 8 API Key demo dùng trên trang Playground |

---

## Bước 3 — Khởi tạo dữ liệu mẫu (8 kịch bản demo)

**Windows:**
```powershell
Remove-Item -Force instance\secure_api_manager.db -ErrorAction SilentlyContinue
.\venv\Scripts\python.exe seed.py
```
**Linux:**
```bash
rm -f instance/secure_api_manager.db
venv/bin/python seed.py
```
Lệnh này tạo 2 tài khoản (`admin`, `dev_hoang`), 5 hồ sơ mẫu và 8 API Key demo. Có thể chạy lại bất cứ lúc nào để đưa dữ liệu về trạng thái ban đầu. Trong web cũng có nút **Reset 8 Kịch bản Demo** (tài khoản admin).

---

## Bước 4 — Chạy web

```powershell
.\venv\Scripts\python.exe run.py
```
Mở trình duyệt: **http://127.0.0.1:5000**

- **Đăng nhập:** `admin` hoặc `dev_hoang`, mật khẩu xem trong `.env` (`DEMO_ADMIN_PASSWORD`, `DEMO_DEV_PASSWORD`). Khi `DEMO_MODE=1` có thể bấm nút **Đăng nhập nhanh 1-Click**.
- **Các trang chính:**
  - `/dashboard`: tạo key (hiển thị 1 lần), Rotate, Revoke, mở khóa key bị đóng băng.
  - `/playground`: bấm thử 8 kịch bản tấn công/phòng thủ (chỉ khi `DEMO_MODE=1`).
  - `/logs`: nhật ký truy cập & kiểm toán (admin).
  - `/db-inspector`: xem dữ liệu đã băm/mã hóa trong DB (admin, chỉ khi `DEMO_MODE=1`).

---

## Bước 5 — Chạy bộ kiểm thử bảo mật tự động

```powershell
.\venv\Scripts\python.exe -m pytest -q
```
Kết quả mong đợi: `59 passed`. Test dùng bộ key "TESTONLY" riêng trong `tests/conftest.py` và DB tạm trong bộ nhớ, nên **không cần `.env`** và không đụng tới dữ liệu thật.

---

## Lỗi thường gặp

| Thông báo | Cách xử lý |
|---|---|
| `RuntimeError: Thiếu hoặc dùng secret mẫu: SECRET_KEY` (hoặc `API_KEY_PEPPER`, `MASTER_ENCRYPTION_KEY`) | Chưa có `.env` hoặc `.env` còn giá trị mẫu, xem Bước 2 |
| `RuntimeError: DEMO_MODE=1 nhưng file .env thiếu Key demo: ...` | `.env` cũ chưa có key demo. Chạy `scripts\tao_env.py --force`, sau đó làm lại Bước 3 |
| `[LỖI] seed.py chỉ chạy khi DEMO_MODE=1 trong .env.` | Sửa `DEMO_MODE=1` trong `.env` |
| Không đăng nhập được | Mật khẩu nằm trong `.env`. Nếu vừa đổi `.env` thì làm lại Bước 3 |
| Dữ liệu hiện `[DECRYPTION_FAILED]` | DB được tạo bằng khóa cũ: làm lại Bước 3 |
| `ModuleNotFoundError` | Chưa cài thư viện hoặc đang không dùng python trong `venv`, xem Bước 1 |
| Cổng 5000 bị chiếm | Đặt biến `PORT=5001` trước khi chạy `run.py` |

---

## Lưu ý khi đưa lên Git / chia sẻ

- `.env`, `venv/`, `instance/` (DB) đã nằm trong `.gitignore`, **không bao giờ commit** chúng.
- Chia sẻ `.env` cho thành viên nhóm qua kênh riêng tư (tin nhắn riêng, USB), **không** đăng lên nhóm chat công khai hay Git.
- Nếu nghi ngờ `.env` bị lộ: chạy `scripts\tao_env.py --force`, làm lại Bước 3, rồi gửi `.env` mới cho cả nhóm.
