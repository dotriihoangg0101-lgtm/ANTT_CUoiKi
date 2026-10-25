# Hướng Dẫn Chụp Ảnh Minh Họa Cho Đồ Án

Ứng dụng đang chạy tại **http://127.0.0.1:5000**. Muốn dừng, bấm `Ctrl + C` trong cửa sổ terminal. Muốn chạy lại, gõ `.\venv\Scripts\python.exe run.py`.

## Chuẩn bị

1. Tạo thư mục **`anh_do_an`** ngay trong thư mục dự án. Mọi ảnh đều lưu vào đó.
2. **Cách chụp:** bấm `Win + Shift + S`, chọn kiểu *Window* (chụp cả cửa sổ) hoặc *Rectangle* (kéo khung). Ảnh được chép vào clipboard. Bấm vào thông báo hiện ra, chọn **Save** và lưu dạng **PNG**.
3. **Đặt tên file:** `Hinh_<số 2 chữ số>_<mô_tả_không_dấu>.png`, ví dụ `Hinh_04_dashboard_tong_quan.png`. Bắt buộc giữ đúng tên như bảng bên dưới, vì lúc viết Word mình sẽ dựa vào tên file để chèn ảnh và chú thích.
4. **Trình duyệt:** để zoom 100%, mở toàn màn hình (`F11` hoặc phóng to cửa sổ), và tắt các tab hoặc bookmark không liên quan.
5. **Chế độ màu:** chụp ở chế độ **sáng** (in ra giấy rõ hơn), trừ những ảnh ghi "tối". Nút chuyển chế độ là biểu tượng mặt trăng / mặt trời ở góc phải thanh menu.
6. **Đăng nhập:** dùng nút **"Vào ngay tài khoản admin"** trên trang đăng nhập, không cần gõ mật khẩu. Nếu cần mật khẩu, xem dòng `DEMO_ADMIN_PASSWORD` trong file `.env`.

> **Bảo mật khi chụp:** ảnh **Hinh_06** có hiện API Key thật. Đây là key demo nên đưa vào báo cáo được, nhưng **không** chụp hay gửi nội dung file `.env`.

---

## Phần A. Xác thực và giao diện

| Tên file | Làm gì | Trong ảnh phải thấy |
|---|---|---|
| `Hinh_01_dang_nhap.png` | Mở http://127.0.0.1:5000 (chế độ sáng) | Form đăng nhập, dòng "PBKDF2-HMAC-SHA256 (NIST SP 800-132)" |
| `Hinh_02_dang_nhap_che_do_toi.png` | Bấm nút mặt trăng để chuyển sang tối | Cùng trang ở chế độ tối |
| `Hinh_03_dang_ky_mat_khau_ngan.png` | Bấm "Đăng ký Developer mới", điền username, email và mật khẩu `abc123`, rồi bấm **Tạo tài khoản an toàn** | Thông báo trình duyệt yêu cầu mật khẩu tối thiểu 15 ký tự |
| `Hinh_04_dang_ky_thanh_cong.png` | Điền lại username `sinhvien_demo`, email `sv@demo.vn`, mật khẩu `con meo nho ngoi tren mai nha` | Dashboard với thông báo xanh "Đăng ký tài khoản thành công!..." |

Sau ảnh 04, bấm nút **đăng xuất** (biểu tượng cửa ra màu đỏ), rồi bấm **"Vào ngay tài khoản admin"**.

## Phần B. Quản lý và cấp phát API Key (trang "Quản lý API Key")

| Tên file | Làm gì | Trong ảnh phải thấy |
|---|---|---|
| `Hinh_05_dashboard_tong_quan.png` | Vừa đăng nhập admin xong | 5 thẻ thống kê, form cấp phát, khung sự kiện kiểm toán |
| `Hinh_06_form_cap_phat_key.png` | Điền form: Tên `Ung dung Mobile Banking`, Môi trường *Production*, TTL *30 ngày*, IP `127.0.0.1`, Rate limit `60`, tick `read:records` và `write:records`. **Chụp trước khi bấm nút** | Form đã điền đầy đủ |
| `Hinh_07_show_once_key_moi.png` | Bấm **Sinh Khóa & Băm HMAC-SHA256** | Khung xanh "SHOW-ONCE SECRET PATTERN" có API Key, Signing Secret và mã băm |
| `Hinh_08_show_once_mat_sau_tai_lai.png` | Bấm `F5` (nếu trình duyệt hỏi gửi lại form thì chọn **Hủy**), hoặc bấm lại menu "Quản lý API Key" | Khung Show-Once đã biến mất |
| `Hinh_09_danh_sach_key_vong_doi.png` | Cuộn xuống bảng "Danh sách API Key" | Các trạng thái ACTIVE, GRACE PERIOD, EXPIRED, REVOKED |
| `Hinh_10_rotate_key.png` | Bấm **Rotate** ở key "Ung dung Mobile Banking" vừa tạo | Khung xanh "Đã xoay vòng (Rotate)..." có dòng Grace Period |
| `Hinh_11_key_cu_grace_period.png` | Cuộn xuống bảng | Key cũ chuyển sang GRACE PERIOD, key mới ghi "Rotated từ #..." |
| `Hinh_12_revoke_key.png` | Bấm **Revoke** ở key mới vừa rotate | Thông báo thu hồi; dòng đó chuyển sang REVOKED |

## Phần C. Phòng thí nghiệm 13 kịch bản (menu "8 Ngữ cảnh Demo & Tấn công")

Mỗi ảnh: bấm nút ở cột trái, chờ kết quả hiện ở khung terminal đen bên phải, rồi chụp **cả cột phải** (thấy cả ô cấu hình request và kết quả). Chạy **đúng thứ tự** dưới đây, vì kịch bản 7 sẽ khóa một key.

| Tên file | Bấm nút | Kết quả mong đợi |
|---|---|---|
| `Hinh_13_playground_tong_quan.png` | Chưa bấm gì, chụp cả trang | 13 nút kịch bản |
| `Hinh_14_kb1_xac_thuc_hop_le.png` | 1. Ngữ cảnh Chuẩn | HTTP 200, dữ liệu giải mã từ DB |
| `Hinh_15_kb2a_vi_pham_scope.png` | 2A. Vi phạm Phân quyền Scope | HTTP 403, `INSUFFICIENT_SCOPE` |
| `Hinh_16_kb2b_tao_ban_ghi.png` | 2B. Tạo Bản ghi DB | HTTP 201 |
| `Hinh_17_kb3_chan_ip_la.png` | 3. Kiểm soát Mạng | HTTP 403, `IP_NOT_WHITELISTED` |
| `Hinh_18_kb4a_key_het_han.png` | 4A. Key Hết hạn | HTTP 401, `API_KEY_EXPIRED` |
| `Hinh_19_kb4b_key_thu_hoi.png` | 4B. Key Đã Thu hồi | HTTP 401, `API_KEY_REVOKED` |
| `Hinh_20_kb5_grace_period.png` | 5. Xoay vòng Khóa | HTTP 200 kèm header `x-api-key-deprecated` |
| `Hinh_21_kb6_rate_limit.png` | 6. Chống DDoS/Spam | HTTP 429; 5 lần đầu ALLOWED, lần 6 và 7 BLOCKED |
| `Hinh_22_kb7_auto_freeze.png` | 7. Tự động Đóng băng | 5 lần vi phạm, lần 6 bị chặn do key đã AUTO_FROZEN |
| `Hinh_23_kb8a_chu_ky_hop_le.png` | 8A. Chữ ký Chuẩn | HTTP 200 |
| `Hinh_24_kb8b_replay_attack.png` | 8B. Replay 15p trước | HTTP 401, `TIMESTAMP_EXPIRED_REPLAY_DETECTED` |
| `Hinh_25_kb8c_sua_so_tien_mitm.png` | 8C. Sửa Số tiền MITM | HTTP 401, `INVALID_HMAC_SIGNATURE_TAMPERED` |
| `Hinh_26_kb0_key_tren_url.png` | Chốt chặn 0 | HTTP 400, `API_KEY_IN_URL_FORBIDDEN` |
| `Hinh_27_playground_che_do_toi.png` | Chuyển sang chế độ tối, bấm lại kịch bản 1 | Playground ở chế độ tối |

Chuyển lại chế độ sáng trước khi sang phần D.

| Tên file | Làm gì | Trong ảnh phải thấy |
|---|---|---|
| `Hinh_28_key_bi_dong_bang.png` | Về trang "Quản lý API Key", cuộn tới "Intrusion Target Key" | Trạng thái AUTO-FROZEN (IDS), nút **Mở khóa** |
| `Hinh_29_mo_khoa_key.png` | Bấm **Mở khóa** | Thông báo mở khóa, key trở lại ACTIVE, vi phạm 0/5 |

## Phần D. Chứng minh lưu trữ an toàn và nhật ký

| Tên file | Làm gì | Trong ảnh phải thấy |
|---|---|---|
| `Hinh_30_db_bang_api_keys.png` | Menu "Soi Database (Hashes)", bảng 1 | Cột `key_hash` (64 ký tự hex) và `signing_secret_enc` (bản mã Fernet), không có key gốc |
| `Hinh_31_db_bang_users.png` | Cuộn tới bảng 2 | `password_hash` dạng `$pbkdf2-sha256$600000$...` |
| `Hinh_32_db_bang_vault_records.png` | Cuộn tới bảng 3 | Cột bản mã Fernet và cột nội dung giải mã |
| `Hinh_33_nhat_ky_truy_cap_api.png` | Menu "Audit & Usage Logs", bảng trái | Các request ALLOWED/DENIED và lý do chặn |
| `Hinh_34_nhat_ky_kiem_toan.png` | Cùng trang, bảng phải | Sự kiện KEY_CREATED, KEY_ROTATED, KEY_REVOKED, AUTO_FROZEN |
| `Hinh_35_dashboard_dien_thoai.png` | Bấm `F12`, bấm biểu tượng điện thoại (*Toggle device toolbar*), chọn iPhone, về trang Dashboard | Giao diện co gọn trên màn hình nhỏ. Xong bấm `F12` lại để tắt |

## Phần E. Kiểm thử tự động

| Tên file | Làm gì | Trong ảnh phải thấy |
|---|---|---|
| `Hinh_36_ket_qua_pytest.png` | Mở **một terminal PowerShell mới** trong thư mục dự án, chạy `.\venv\Scripts\python.exe -m pytest -v`, chờ chạy xong rồi cuộn tới cuối | Dòng `69 passed` |

## Sau khi chụp xong

1. Kiểm tra trong thư mục `anh_do_an` có đủ **36 file** đúng tên.
2. Bấm nút **"Reset 8 Kịch bản Demo"** (màu vàng trên menu) để đưa dữ liệu về trạng thái ban đầu.
3. Nhắn mình trong thread là đã chụp xong. Mình sẽ viết file Word, chèn ảnh theo đúng tên và thêm chú thích "Hình X: ..." cho từng ảnh.

Nếu ảnh nào có kết quả khác cột "Kết quả mong đợi", cứ chụp lại rồi gửi kèm, mình sẽ kiểm tra.
