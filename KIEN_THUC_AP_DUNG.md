# Kiến Thức, Chuẩn Và Thuật Toán Áp Dụng Trong Đồ Án

**Đề tài:** Xây dựng ứng dụng Web quản lý, cấp phát và kiểm soát API Key an toàn
**Mục đích tài liệu:** giải thích từng kỹ thuật bảo mật trong code, nó dựa trên chuẩn nào (tên, năm, mục), vì sao chọn, và những điểm mạnh/yếu của đồ án. Dùng để ôn trước khi bảo vệ.

> **Lưu ý khi trình bày:** NIST và ISO là **tiêu chuẩn / hướng dẫn kỹ thuật**, không phải **bộ luật**. Đồ án *tham chiếu* (align with) các chuẩn này. Đồ án **không** được chứng nhận (certified) theo chuẩn nào, nên không nói "đạt chuẩn NIST" hay "đạt ISO 27001". Câu nên dùng: *"Thiết kế tuân theo khuyến nghị của NIST SP 800-xx"*.

---

## Mục lục

1. [Bảng tổng hợp chuẩn áp dụng](#1-bảng-tổng-hợp-chuẩn-áp-dụng)
2. [Sinh API Key (CSPRNG, độ dài khóa)](#2-sinh-api-key)
3. [Lưu trữ API Key (HMAC-SHA256 + Pepper)](#3-lưu-trữ-api-key)
4. [Băm mật khẩu (PBKDF2-HMAC-SHA256)](#4-băm-mật-khẩu)
5. [Chính sách mật khẩu (NIST SP 800-63B-4)](#5-chính-sách-mật-khẩu)
6. [Mã hóa dữ liệu nhạy cảm (Fernet + HKDF)](#6-mã-hóa-dữ-liệu-nhạy-cảm)
7. [Ký gói tin HMAC và chống Replay](#7-ký-gói-tin-hmac-và-chống-replay)
8. [Vòng đời khóa (NIST SP 800-57)](#8-vòng-đời-khóa)
9. [Middleware kiểm soát truy cập 6 lớp](#9-middleware-kiểm-soát-truy-cập-6-lớp)
10. [Bảo mật ứng dụng web](#10-bảo-mật-ứng-dụng-web)
11. [Đối chiếu ISO/IEC 27001:2022](#11-đối-chiếu-isoiec-270012022)
12. [Đối chiếu OWASP API Security Top 10 (2023)](#12-đối-chiếu-owasp-api-security-top-10-2023)
13. [Điểm mạnh của đồ án](#13-điểm-mạnh-của-đồ-án)
14. [Điểm yếu và hướng phát triển](#14-điểm-yếu-và-hướng-phát-triển)
15. [Câu hỏi thầy có thể hỏi và gợi ý trả lời](#15-câu-hỏi-thầy-có-thể-hỏi-và-gợi-ý-trả-lời)

---

## 1. Bảng tổng hợp chuẩn áp dụng

| Chuẩn | Năm | Nội dung chính | Áp dụng ở đâu trong code |
|---|---|---|---|
| **NIST SP 800-63B-4** – Digital Identity Guidelines: Authentication and Authenticator Management | 08/2025 | Chính sách mật khẩu, lưu mật khẩu | `app/services/password_policy.py`, `app/routes/auth.py` |
| **NIST SP 800-132** – Recommendation for Password-Based Key Derivation | 12/2010 | PBKDF2, salt, số vòng lặp | `hash_password()` trong `app/services/crypto_service.py` |
| **NIST SP 800-57 Part 1 Rev. 5** – Recommendation for Key Management | 05/2020 | Độ mạnh bảo mật (security strength), trạng thái và thời hạn dùng khóa | Độ dài key, TTL, Rotate, Revoke (`app/services/key_service.py`) |
| **NIST SP 800-131A Rev. 2** – Transitioning the Use of Cryptographic Algorithms and Key Lengths | 03/2019 | Mức tối thiểu 112 bit, thuật toán còn được phép | Lựa chọn SHA-256, AES, độ dài key |
| **NIST SP 800-90A Rev. 1** – Random Number Generation Using Deterministic RBGs | 06/2015 | Bộ sinh số ngẫu nhiên an toàn (DRBG) | `secrets` (CSPRNG của hệ điều hành) |
| **NIST SP 800-56C Rev. 2** – Recommendation for Key-Derivation Methods in Key-Establishment Schemes | 08/2020 | KDF dạng extract-then-expand (HKDF) | `_get_fernet()` |
| **FIPS 180-4** – Secure Hash Standard | 08/2015 | SHA-256 | Mọi chỗ dùng SHA-256 |
| **FIPS 198-1** – The Keyed-Hash Message Authentication Code (HMAC) | 07/2008 | HMAC | Băm API Key, ký gói tin, Fernet |
| **FIPS 197** – Advanced Encryption Standard (bản cập nhật 05/2023) | 11/2001 | AES | Fernet (AES-128) |
| **NIST SP 800-38A** – Block Cipher Modes of Operation | 12/2001 | Chế độ CBC | Fernet (AES-128-CBC) |
| **NIST SP 800-53 Rev. 5** – Security and Privacy Controls | 09/2020 | Bộ control: AC-6, AC-7, AU-2, SC-5, IA-5… | Ánh xạ ở mục 9 |
| **ISO/IEC 27001:2022** và **ISO/IEC 27002:2022** | 10/2022 và 02/2022 | Hệ thống quản lý ATTT, Phụ lục A gồm 93 control | Ánh xạ ở mục 11 |
| **OWASP API Security Top 10** | 2023 | 10 rủi ro API phổ biến | Ánh xạ ở mục 12 |
| **RFC 2104** (HMAC, 1997), **RFC 5869** (HKDF, 2010), **RFC 8018** (PKCS #5 v2.1 / PBKDF2, 2017), **Fernet Spec** | — | Đặc tả kỹ thuật | Như trên |
| **CWE-598** (Use of GET Request Method With Sensitive Query Strings), **CWE-208** (Observable Timing Discrepancy), **CWE-307** (Improper Restriction of Excessive Authentication Attempts) | — | Danh mục lỗi phần mềm | Chốt chặn 0, so sánh hằng thời gian, Auto-Freeze |

---

## 2. Sinh API Key

**Code:** `generate_raw_api_key()` trong `app/services/crypto_service.py`

```
ak_live_9f8a1b2c_Xy7...(32 ký tự)
└┬┘└┬─┘└───┬───┘└────────┬────────┘
 │  │      │             └ secret: secrets.token_urlsafe(24) = 24 byte = 192 bit ngẫu nhiên
 │  │      └ id: secrets.token_hex(4) = 8 ký tự hex (32 bit), dùng làm key_prefix để tra cứu
 │  └ môi trường: live / test
 └ loại: ak = API key
```

**Kiến thức cần nắm:**

- **CSPRNG** (Cryptographically Secure Pseudo-Random Number Generator): module `secrets` của Python gọi `os.urandom()`, tức bộ sinh ngẫu nhiên của hệ điều hành. Trên Windows đó là `BCryptGenRandom`, dùng CTR_DRBG theo **NIST SP 800-90A**. Trên Linux là `getrandom()`.
  - **Không** dùng `random` vì đó là Mersenne Twister, dự đoán được khi biết 624 giá trị đầu ra.
- **Entropy 192 bit:** kẻ tấn công phải thử trung bình 2^191 lần. Theo **SP 800-57 Part 1 Rev.5, Bảng 2–4**, cần tối thiểu **112 bit** độ mạnh đến hết năm 2030 và **128 bit** từ 2031 trở đi. 192 bit vượt cả hai mức.
- **Vì sao có prefix?**
  - Để tra cứu trong DB theo cột `key_prefix` có index, độ phức tạp O(1), không phải băm thử từng dòng.
  - Để nhận diện nhanh key `live` hay `test`, giúp công cụ quét bí mật (secret scanning, như GitHub) phát hiện được key bị lộ.
- **Show-Once Pattern:** key gốc chỉ hiển thị 1 lần ngay khi tạo. DB chỉ lưu bản băm nên ngay cả admin cũng không xem lại được.

**Câu hỏi hay gặp:** *"32 ký tự sao lại là 192 bit?"* Vì Base64 URL-safe mã hóa mỗi 6 bit thành 1 ký tự: 24 byte × 8 = 192 bit, và 192 ÷ 6 = 32 ký tự.

---

## 3. Lưu trữ API Key

**Code:** `hash_api_key()`, `verify_api_key_hash()`

```
key_hash = HMAC-SHA256(key = API_KEY_PEPPER, message = raw_key)   → 64 ký tự hex
```

- **HMAC** theo **FIPS 198-1 (2008)** và RFC 2104: `HMAC(K, m) = H((K ⊕ opad) ‖ H((K ⊕ ipad) ‖ m))`. **SHA-256** theo **FIPS 180-4 (2015)**.
- **Pepper** là khóa bí mật nằm trong `.env`, không nằm trong DB. Nếu chỉ lộ DB, kẻ tấn công không có pepper nên không thể tự tính hash để dò key.
- **Vì sao không dùng bcrypt/PBKDF2 cho API Key?** Hàm băm chậm chỉ cần cho bí mật ít entropy như mật khẩu người dùng. API Key có 192 bit ngẫu nhiên nên brute-force là bất khả thi, và một HMAC nhanh là đủ an toàn. Nhờ vậy mỗi request chỉ tốn vài micro-giây, phù hợp API có lưu lượng lớn.
- **So sánh hằng thời gian** `hmac.compare_digest()` chống **Timing Side-Channel (CWE-208)**. Phép so sánh `==` thường dừng ngay ở byte sai đầu tiên, nên kẻ tấn công có thể đo thời gian phản hồi để đoán dần từng byte.

---

## 4. Băm mật khẩu

**Code:** `hash_password()`, `verify_password()`, `password_needs_rehash()`

```
salt = 16 byte ngẫu nhiên (128 bit)
DK   = PBKDF2(PRF = HMAC-SHA256, Password, salt, c = 600.000, dkLen = 32 byte)
Lưu  : $pbkdf2-sha256$600000$<salt_base64>$<DK_base64>
```

**Thuật toán PBKDF2** (SP 800-132 mục 5.3 và RFC 8018):

```
T_1 = U_1 ⊕ U_2 ⊕ … ⊕ U_c
U_1 = HMAC(P, S ‖ INT(1))
U_j = HMAC(P, U_{j-1})        (lặp c lần)
```

- **Salt ≥ 128 bit:** SP 800-132 mục 5.1 yêu cầu salt tối thiểu 128 bit, sinh ngẫu nhiên. Salt khiến hai người dùng cùng mật khẩu vẫn có hash khác nhau và làm vô hiệu bảng tra sẵn (rainbow table).
- **600.000 vòng lặp:** SP 800-132 chỉ yêu cầu tối thiểu 1.000 vòng và khuyên chọn càng lớn càng tốt. Con số **600.000** lấy theo OWASP Password Storage Cheat Sheet (2023). Trên máy chạy đồ án đo được khoảng **0,18 giây** mỗi lần băm: người dùng không cảm thấy chậm, nhưng kẻ tấn công thử hàng tỷ mật khẩu sẽ rất tốn kém.
- **SP 800-63B-4 mục 3.1.1.2:** mật khẩu **SHALL** được lưu ở dạng chống tấn công ngoại tuyến (offline attack), **SHALL** có salt và được băm bằng một lược đồ băm mật khẩu phù hợp.
- **Vì sao bỏ Argon2id?**
  - Argon2id (RFC 9106, 2021) là thuật toán mạnh, tốn nhiều bộ nhớ (memory-hard) và được OWASP xếp hạng đầu. Tuy vậy nó **không nằm trong danh sách thuật toán được NIST phê duyệt**.
  - Đồ án chọn tuân theo NIST nên dùng PBKDF2, là thuật toán được NIST phê duyệt (FIPS-approved).
  - Đây là **đánh đổi có chủ đích**: PBKDF2 không memory-hard nên GPU/ASIC dò nhanh hơn so với Argon2. Bù lại, đồ án dùng số vòng lặp lớn và chính sách mật khẩu dài.
- **Chuyển đổi không làm hỏng dữ liệu cũ (rehash-on-login):**
  - Hash Argon2id cũ vẫn xác minh được.
  - Khi người dùng đăng nhập đúng, hệ thống tự băm lại mật khẩu bằng PBKDF2.
  - Nếu sau này tăng số vòng lặp, hash cũ cũng được nâng cấp theo cách này.

---

## 5. Chính sách mật khẩu

**Code:** `app/services/password_policy.py` (`MIN_LENGTH = 15`, `MAX_LENGTH = 128`)
**Chuẩn:** **NIST SP 800-63B-4 (08/2025), mục 3.1.1.2 "Password Verifiers"**

| Yêu cầu của chuẩn | Mức | Đồ án làm gì |
|---|---|---|
| Mật khẩu là yếu tố xác thực **duy nhất** phải dài **tối thiểu 15 ký tự** (nếu chỉ dùng trong MFA thì tối thiểu 8) | SHALL | Đã làm: đồ án chưa có MFA nên áp 15 ký tự |
| Cho phép độ dài tối đa **ít nhất 64 ký tự** | SHOULD | Đã làm: cho phép 128 |
| So sánh với **blocklist** gồm mật khẩu phổ biến, dễ đoán, đã bị lộ và từ theo ngữ cảnh | SHALL | Đã làm: danh sách rút gọn, chặn ký tự lặp, dãy số, username, email, tên hệ thống |
| **Không** áp quy tắc thành phần (bắt buộc chữ hoa, số, ký tự đặc biệt) | SHALL NOT | Đã làm: chuỗi "con meo nho ngoi tren mai nha" hợp lệ |
| **Không** bắt đổi mật khẩu định kỳ, chỉ bắt đổi khi có dấu hiệu bị lộ | SHALL NOT | Đã làm: không có tính năng hết hạn mật khẩu |
| Chấp nhận ký tự ASCII in được, khoảng trắng, Unicode; đếm mỗi code point là 1 ký tự | SHOULD / SHALL | Đã làm: chuẩn hóa NFKC rồi đếm `len()`, tiếng Việt có dấu dùng được |
| Cho phép trình quản lý mật khẩu và dán (paste) | SHALL / SHOULD | Đã làm: ô nhập có `autocomplete="new-password"` và không chặn paste |
| Giới hạn số lần đăng nhập sai liên tiếp trên **mỗi tài khoản** (≤ 100 lần), mục 3.2.2 | SHALL | **Một phần:** mới giới hạn 20 lần/phút **theo IP**, chưa đếm theo tài khoản (xem mục 14) |

**Vì sao NIST bỏ yêu cầu "chữ hoa + số + ký tự đặc biệt"?** Nghiên cứu cho thấy quy tắc này khiến người dùng đặt mật khẩu theo mẫu dễ đoán như `Password@1`, vừa khó nhớ vừa không mạnh hơn. Độ dài mới là yếu tố quyết định: một cụm 15 ký tự chữ thường có khoảng 26^15 ≈ 2^70 khả năng, lớn hơn rất nhiều so với 8 ký tự hỗn hợp, khoảng 95^8 ≈ 2^52.

---

## 6. Mã hóa dữ liệu nhạy cảm

**Code:** `_get_fernet()`, `encrypt_sensitive_value()`, `decrypt_sensitive_value()`
**Dữ liệu được mã hóa:** cột `signing_secret_enc` (bảng `api_keys`) và cột `encrypted_secret_note` (bảng `vault_records`).

**Bước 1. Dẫn xuất khóa bằng HKDF-SHA256** (RFC 5869; là KDF dạng "extract-then-expand" của **SP 800-56C Rev.2**)

```
PRK = HMAC-SHA256(salt, MASTER_ENCRYPTION_KEY)              (Extract)
OKM = HMAC-SHA256(PRK, info ‖ 0x01)  → 32 byte              (Expand)
info = "SEC-GATEWAY/fernet-data-encryption/v1"
```

Trước đây code chỉ tính `SHA-256(master_key)`. Cách đó không phải KDF được NIST phê duyệt và không tách được khóa theo mục đích sử dụng (domain separation). Tham số `info` cho phép dẫn xuất nhiều khóa khác nhau từ cùng một master key cho các mục đích khác nhau.

**Bước 2. Fernet** (đặc tả Fernet của thư viện `cryptography`). Khóa 32 byte được chia đôi:

- 16 byte đầu là **Signing key** dùng cho **HMAC-SHA256** (FIPS 198-1).
- 16 byte sau là **Encryption key** dùng cho **AES-128-CBC** (FIPS 197 + SP 800-38A), đệm (padding) theo PKCS#7, IV ngẫu nhiên 128 bit.

```
Token = Version(0x80) ‖ Timestamp ‖ IV ‖ Ciphertext ‖ HMAC(Version‖Timestamp‖IV‖Ciphertext)
```

- Đây là mô hình **Encrypt-then-MAC**: kiểm tra HMAC trước rồi mới giải mã, chống được padding oracle và chống sửa bản mã.
- **MultiFernet:** luôn mã hóa bằng khóa HKDF mới nhưng vẫn thử giải mã bằng khóa cũ (SHA-256 trần). Nhờ vậy dữ liệu trong DB cũ không bị mất. Đây cũng là cơ chế **xoay vòng khóa mã hóa** (key rotation).
- **AES-128 có đủ không?** Có. AES-128 cho 128 bit độ mạnh, đạt mức SP 800-57 yêu cầu sau năm 2030.

---

## 7. Ký gói tin HMAC và chống Replay

**Code:** `compute_request_signature()`, `verify_request_signature()`; áp dụng cho `POST /api/v1/transfer`

```
canonical = "<timestamp>.<METHOD>.<path>.<body>"
X-Signature = HMAC-SHA256(signing_secret, canonical)   (hex)
```

Server kiểm tra theo 3 bước:

1. **Độ lệch thời gian:** `|now − X-Timestamp| ≤ 300 giây`. Gói tin cũ hơn 5 phút bị từ chối với mã `TIMESTAMP_EXPIRED_REPLAY_DETECTED`.
2. **Tính lại HMAC và so sánh hằng thời gian:** nếu body bị sửa trên đường truyền (MITM), chữ ký không khớp và bị từ chối với mã `INVALID_HMAC_SIGNATURE_TAMPERED`.
3. **Bộ nhớ đệm chữ ký đã dùng** `_SEEN_SIGNATURES` (key_id, signature) giữ trong 300 giây: gửi lại đúng gói tin cũ lần thứ 2 bị từ chối với mã `REPLAY_DETECTED`.

**Chuẩn tham chiếu:**

- **FIPS 198-1** cho HMAC.
- **SP 800-53 Rev.5 IA-2(8)** "Access to Accounts — Replay Resistant" và **SC-8** "Transmission Confidentiality and Integrity".
- Cùng mô hình mà Stripe và GitHub dùng cho webhook signature.

**Vì sao cần cả timestamp lẫn cache?** Timestamp giới hạn cửa sổ tấn công trong 5 phút. Cache chặn việc phát lại ngay **bên trong** 5 phút đó. Thiếu một trong hai thì vẫn còn lỗ hổng.

---

## 8. Vòng đời khóa

**Chuẩn:** **NIST SP 800-57 Part 1 Rev.5 (2020)**, mục 7 "Key States and Transitions" và mục 5.3 "Cryptoperiods"

| Trạng thái trong đồ án | Trạng thái theo SP 800-57 | Ý nghĩa |
|---|---|---|
| `ACTIVE` | Active | Được dùng bình thường |
| `GRACE_PERIOD` (sau khi Rotate, 1–168 giờ) | Deactivated, vẫn cho phép xử lý tiếp | Key cũ còn sống tạm để client kịp chuyển sang key mới (**zero-downtime rotation**). Response có header `X-API-Key-Deprecated` và `X-API-Key-Sunset` |
| `EXPIRED` (quá `expires_at`, TTL 1–365 ngày) | Deactivated, đã hết cryptoperiod | Thời hạn dùng khóa đã hết |
| `AUTO_FROZEN` (vi phạm 5 lần liên tiếp) | Suspended | Tạm ngưng, admin có thể **Mở khóa** |
| `REVOKED` | Compromised hoặc Destroyed | Trạng thái cuối, không thể mở lại hay rotate |

- **Cryptoperiod:** SP 800-57 khuyên mỗi khóa có thời hạn sử dụng giới hạn để giảm thiệt hại nếu bị lộ. Đồ án bắt buộc chọn TTL và mặc định 30 ngày.
- **Rotate** tạo key mới và signing secret mới, ghi lại `rotated_from_id` để truy vết.

---

## 9. Middleware kiểm soát truy cập 6 lớp

**Code:** `require_api_key()` trong `app/middleware/api_auth.py`

| Lớp | Kiểm tra | Mã lỗi | Chuẩn / control tham chiếu |
|---|---|---|---|
| 0 | Cấm truyền API Key trên URL `?api_key=` (URL bị lưu vào log, lịch sử trình duyệt, Referer) | 400 `API_KEY_IN_URL_FORBIDDEN` | **CWE-598** |
| 1 | Định dạng key, tra theo prefix, so sánh HMAC hằng thời gian | 401 | SP 800-53 **IA-5** (Authenticator Management), **CWE-208** |
| 2 | Vòng đời: revoked / frozen / expired / hết ân hạn | 401 | **SP 800-57** (mục 8) |
| 3 | IP Whitelist / CIDR (`ipaddress.ip_network`) | 403 `IP_NOT_WHITELISTED` | SP 800-53 **AC-3** (Access Enforcement), **SC-7** (Boundary Protection) |
| 4 | Scope theo nguyên tắc đặc quyền tối thiểu (`read:records`, `write:records`, `admin:records`, `transfer:funds`) | 403 `INSUFFICIENT_SCOPE` | SP 800-53 **AC-6** (Least Privilege) |
| 5 | Rate limit theo key (**sliding window 60 giây**) và theo IP (120/phút) | 429 + `Retry-After` | SP 800-53 **SC-5** (Denial-of-Service Protection) |
| 6 | Chữ ký HMAC và chống Replay (mục 7) | 401 | SP 800-53 **IA-2(8)**, **SC-8** |

**Thuật toán Sliding Window:** mỗi key có một danh sách mốc thời gian của các request. Mỗi lần gọi, hệ thống xóa các mốc cũ hơn 60 giây; nếu số mốc còn lại ≥ giới hạn thì trả 429, ngược lại ghi thêm mốc mới. Cách này chính xác hơn Fixed Window, vốn cho phép dồn gấp đôi request ở ranh giới giữa hai phút.

**Auto-Freeze (phát hiện xâm nhập đơn giản):**

- Hệ thống đếm `failed_attempts` cho các vi phạm ở Lớp 3, 4 và 6, chỉ tính sau khi người gọi đã chứng minh có đủ raw key. Khi đạt 5 lần liên tiếp, key bị khóa và một sự kiện `CRITICAL` được ghi vào audit log.
- Cơ chế này tham chiếu SP 800-53 **AC-7** (Unsuccessful Logon Attempts) và **CWE-307**.
- **Vì sao sai secret không bị đếm?** Prefix của key là công khai. Nếu đếm cả lần sai secret, bất kỳ ai biết prefix cũng có thể cố tình gửi sai 5 lần để khóa key của người khác, tức một kiểu tấn công từ chối dịch vụ.

**Nhật ký kiểm toán:** bảng `api_usage_logs` (mọi request: IP, endpoint, kết quả, lý do chặn, độ trễ) và `security_audit_logs` (sự kiện quản trị) đáp ứng SP 800-53 **AU-2, AU-3, AU-12** và ISO 27001 A.8.15. Key sai định dạng được ghi là `MALFORMED` để không lưu lộ một phần bí mật vào log.

---

## 10. Bảo mật ứng dụng web

| Kỹ thuật | Chống lại | Vị trí |
|---|---|---|
| CSRF token (Flask-WTF) cho mọi form POST | Cross-Site Request Forgery | Mọi template có `csrf_token()` |
| Cookie `HttpOnly`, `SameSite=Lax`, có thể bật `Secure` | XSS đánh cắp session, CSRF | `app/config.py` |
| `Content-Security-Policy`, `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, HSTS khi chạy HTTPS | XSS, Clickjacking, MIME sniffing | `apply_security_headers()` trong `app/__init__.py` |
| RBAC (admin / developer) và kiểm tra quyền sở hữu key | IDOR / BOLA | `@admin_required`, `app/routes/dashboard.py` |
| Jinja2 tự động escape; JavaScript dùng `textContent` | XSS | Templates |
| Kiểm tra bí mật khi khởi động (`validate_secrets`) | Chạy với khóa mặc định / yếu | `app/config.py` |
| `DEMO_MODE=0` thì các trang demo trả 404 | Lộ tính năng thử nghiệm ra production | Routes |

---

## 11. Đối chiếu ISO/IEC 27001:2022

ISO/IEC 27001 là chuẩn về **hệ thống quản lý** ATTT (ISMS): nói **cần kiểm soát gì**, không chỉ định thuật toán cụ thể. Vì vậy đồ án dùng NIST cho phần kỹ thuật và dùng ISO để chỉ ra mỗi tính năng phục vụ control nào. Hướng dẫn triển khai chi tiết nằm trong ISO/IEC 27002:2022 với cùng số hiệu.

| Control Phụ lục A | Tên | Tính năng tương ứng |
|---|---|---|
| A.5.15 | Access control | Scope, IP whitelist, RBAC |
| A.5.17 | Authentication information | Băm mật khẩu, chính sách mật khẩu, Show-Once |
| A.5.18 | Access rights | Cấp, xoay, thu hồi key; developer không tự cấp scope nhạy cảm |
| A.8.2 | Privileged access rights | Trang `/logs`, `/db-inspector` chỉ dành cho admin |
| A.8.5 | Secure authentication | Middleware 6 lớp, chữ ký HMAC |
| A.8.6 | Capacity management | Rate limit |
| A.8.15 | Logging | `api_usage_logs`, `security_audit_logs` |
| A.8.16 | Monitoring activities | Auto-Freeze, dashboard thống kê tấn công |
| A.8.24 | Use of cryptography (gồm quản lý khóa) | HMAC, PBKDF2, Fernet, HKDF, vòng đời key |
| A.8.25–A.8.28 | Secure development lifecycle, secure coding | Bộ test tự động (69 test), 3 vòng review bảo mật |

---

## 12. Đối chiếu OWASP API Security Top 10 (2023)

| Rủi ro | Biện pháp trong đồ án |
|---|---|
| API1 – Broken Object Level Authorization | Developer chỉ thấy và thao tác key của chính mình |
| API2 – Broken Authentication | HMAC key hash, so sánh hằng thời gian, cấm key trên URL, Auto-Freeze |
| API4 – Unrestricted Resource Consumption | Rate limit theo key và theo IP |
| API5 – Broken Function Level Authorization | Scope `admin:records`, `transfer:funds` |
| API8 – Security Misconfiguration | Security headers, `DEMO_MODE`, `TRUST_PROXY`, kiểm tra bí mật khi khởi động |

---

## 13. Điểm mạnh của đồ án

1. **Đúng trọng tâm đề tài:** có đủ 3 mảng Quản lý (Dashboard, Logs), Cấp phát (sinh key CSPRNG, Show-Once, Rotate) và Kiểm soát (6 lớp middleware, Auto-Freeze).
2. **Không lưu bí mật dạng rõ trong DB:** API Key lưu bằng HMAC, mật khẩu bằng PBKDF2, signing secret và ghi chú nhạy cảm mã hóa bằng Fernet. Trang "Soi Database" chứng minh trực quan điều này.
3. **Phòng thủ nhiều lớp (Defense in Depth):** lộ key vẫn bị chặn bởi IP whitelist, scope, rate limit và chữ ký.
4. **Vòng đời khóa đầy đủ theo SP 800-57,** có zero-downtime rotation với grace period, giống cách Stripe và AWS làm.
5. **Chống Replay hai tầng** (timestamp và nonce cache) và chống sửa gói tin bằng HMAC.
6. **Có tính toán chống lạm dụng chính cơ chế bảo vệ:** không đếm sai secret vào Auto-Freeze, không làm lộ `allowed_ips` hay `granted_scopes` trong thông báo lỗi.
7. **Chuyển đổi thuật toán không làm mất dữ liệu:** rehash-on-login cho mật khẩu và MultiFernet cho dữ liệu mã hóa.
8. **Kiểm chứng được:** 69 test tự động và Playground 13 kịch bản tấn công bấm 1 lần là chạy.
9. **Quản lý bí mật tập trung** trong `.env` sinh bằng CSPRNG; ứng dụng từ chối chạy khi thiếu khóa hoặc dùng khóa mẫu.

---

## 14. Điểm yếu và hướng phát triển

Khi bảo vệ, nên chủ động nói ra những điểm dưới đây. Thầy thường đánh giá cao việc sinh viên tự biết giới hạn của hệ thống mình.

| # | Điểm yếu | Ảnh hưởng | Hướng khắc phục |
|---|---|---|---|
| 1 | Cache chống Replay và bộ đếm rate limit lưu **trong bộ nhớ** | Chỉ đúng khi chạy 1 process; restart thì mất | Redis `SET NX EX 300`, `RATELIMIT_STORAGE_URI=redis://` |
| 2 | **Chưa có MFA** | Theo SP 800-63B-4, chỉ dùng mật khẩu thì chỉ đạt AAL1 | Thêm TOTP (RFC 6238) hoặc WebAuthn/passkey để lên AAL2 |
| 3 | Giới hạn đăng nhập sai mới tính **theo IP**, chưa tính theo tài khoản (SP 800-63B-4 mục 3.2.2) | Kẻ tấn công đổi IP liên tục vẫn dò được | Đếm lỗi theo `user_id`, khóa tạm hoặc tăng dần thời gian chờ |
| 4 | Blocklist mật khẩu nhỏ (khoảng 40 mục) | Chưa chặn hết mật khẩu đã bị lộ | Tra Have I Been Pwned (k-anonymity) hoặc nạp danh sách lớn |
| 5 | Chạy **HTTP** khi demo (Flask dev server) | Key và cookie đi dạng rõ trên mạng | Triển khai sau Nginx với TLS 1.2+ (NIST SP 800-52 Rev.2), bật `SESSION_COOKIE_SECURE=1` |
| 6 | Master key và pepper nằm trong file `.env` | Lộ `.env` thì lộ toàn bộ | Dùng KMS hoặc HSM (AWS KMS, HashiCorp Vault), đúng khuyến nghị bảo vệ khóa của SP 800-57 |
| 7 | **Chưa hỗ trợ xoay pepper** | Đổi pepper làm toàn bộ key hash hiện có mất hiệu lực | Lưu `pepper_version` cho từng key |
| 8 | PBKDF2 **không memory-hard** | GPU dò nhanh hơn so với Argon2id | Đánh đổi để tuân thủ NIST; nếu không cần tuân thủ NIST thì Argon2id mạnh hơn |
| 9 | Fernet dùng AES-CBC + HMAC, không phải mã hóa xác thực (AEAD) tích hợp | Vẫn an toàn nhờ Encrypt-then-MAC, nhưng không hiện đại bằng | AES-256-GCM (SP 800-38D) |
| 10 | Thư viện mật mã **không phải module được chứng nhận FIPS 140-3** | Không được nói "đạt chuẩn FIPS" | Dùng OpenSSL FIPS provider đã được chứng nhận |
| 11 | `key_prefix` ngẫu nhiên 32 bit, không thử lại khi trùng | Khả năng trùng rất nhỏ; nếu trùng thì DB báo lỗi `unique` và tạo key thất bại | Thêm vòng thử lại hoặc tăng lên 64 bit |
| 12 | Audit log có thể bị sửa bởi người có quyền vào DB | Không chống chối bỏ (non-repudiation) | Hash-chain các bản ghi log, hoặc đẩy sang hệ thống SIEM |
| 13 | CSP còn `'unsafe-inline'` cho script | Giảm hiệu quả chống XSS | Chuyển script inline ra file và dùng nonce |
| 14 | Show-Once render trong response POST | Bấm F5 và gửi lại form sẽ tạo thêm 1 key | Áp mẫu Post/Redirect/Get kèm token dùng 1 lần |
| 15 | SQLite | Không phù hợp tải lớn và nhiều người dùng | MySQL/PostgreSQL (code đã dùng SQLAlchemy nên dễ chuyển) |

---

## 15. Câu hỏi thầy có thể hỏi và gợi ý trả lời

**H1. Đồ án theo chuẩn nào?**
Phần kỹ thuật theo NIST: SP 800-63B-4 (2025) cho mật khẩu, SP 800-132 (2010) cho PBKDF2, SP 800-57 Part 1 Rev.5 (2020) cho quản lý khóa, SP 800-56C Rev.2 (2020) cho HKDF, cùng FIPS 180-4 và FIPS 198-1 cho SHA-256 và HMAC. Phần quản lý ánh xạ sang ISO/IEC 27001:2022 Phụ lục A, đặc biệt A.8.24 Use of cryptography. Rủi ro API đối chiếu với OWASP API Top 10 (2023).

**H2. Vì sao mật khẩu phải tối thiểu 15 ký tự?**
Theo NIST SP 800-63B-4 mục 3.1.1.2, khi mật khẩu là yếu tố xác thực duy nhất thì độ dài tối thiểu là 15 (bắt buộc, mức SHALL). Nếu có thêm yếu tố thứ hai (MFA) thì được giảm xuống 8. Đồ án chưa có MFA nên áp 15.

**H3. Sao không bắt mật khẩu có chữ hoa và ký tự đặc biệt?**
Vì SP 800-63B-4 cấm điều đó (SHALL NOT). Quy tắc thành phần làm người dùng đặt theo mẫu dễ đoán. Chuẩn chọn cách kết hợp độ dài với blocklist.

**H4. API Key lưu thế nào? Admin có xem lại được key không?**
Không xem lại được. DB chỉ lưu `HMAC-SHA256(pepper, key)`. Key gốc hiển thị đúng 1 lần lúc tạo. Mất key thì phải Rotate để tạo key mới.

**H5. Sao API Key dùng HMAC nhanh, còn mật khẩu dùng PBKDF2 chậm?**
Vì entropy khác nhau. API Key có 192 bit ngẫu nhiên nên brute-force là bất khả thi. Mật khẩu do người đặt có entropy thấp nên cần hàm băm chậm, có salt, để mỗi lần thử của kẻ tấn công tốn khoảng 0,18 giây.

**H6. Pepper khác salt chỗ nào?**
Salt là giá trị ngẫu nhiên riêng cho từng bản ghi, **lưu cùng hash trong DB** và không bí mật. Pepper là một bí mật chung **không lưu trong DB** (nằm trong `.env`). Lộ DB mà không lộ `.env` thì không dò được.

**H7. Timing attack là gì, chống bằng cách nào?**
Phép so sánh `==` dừng ở byte sai đầu tiên, nên thời gian phản hồi tiết lộ có bao nhiêu byte đúng. `hmac.compare_digest` luôn so hết toàn bộ chuỗi trong cùng một khoảng thời gian (CWE-208).

**H8. Replay attack là gì? Nếu kẻ tấn công bắt được gói tin hợp lệ rồi gửi lại ngay thì sao?**
Gửi lại sau hơn 5 phút thì bị chặn bởi timestamp. Gửi lại trong vòng 5 phút thì bị chặn bởi cache chữ ký đã dùng (`REPLAY_DETECTED`). Sửa nội dung gói tin thì HMAC không khớp.

**H9. Key bị lộ lên GitHub thì xử lý thế nào?**
Bấm Revoke để vô hiệu hóa ngay (trạng thái cuối, Compromised theo SP 800-57). Nếu cần duy trì dịch vụ thì Rotate để client chuyển sang key mới. Kể cả khi chưa kịp thu hồi, kẻ tấn công vẫn bị chặn nếu key có IP whitelist hoặc thiếu scope, và sau 5 lần vi phạm key tự đóng băng.

**H10. Vì sao chuyển từ Argon2id sang PBKDF2? Argon2 chẳng phải mạnh hơn sao?**
Đúng, Argon2id là memory-hard nên chống GPU tốt hơn. Nhưng nó không thuộc danh sách thuật toán NIST phê duyệt. Đồ án chọn tuân thủ NIST, dùng 600.000 vòng theo OWASP và bù bằng chính sách mật khẩu dài. Hash Argon2 cũ tự chuyển sang PBKDF2 khi người dùng đăng nhập.

**H11. HKDF dùng để làm gì?**
HKDF biến master key thành khóa mã hóa đúng độ dài và đúng mục đích (tham số `info`), theo mô hình extract-then-expand của SP 800-56C Rev.2. Băm SHA-256 trực tiếp không phải KDF chuẩn và không tách được khóa cho từng mục đích.

**H12. Fernet có an toàn không?**
Có. Fernet dùng AES-128-CBC với IV ngẫu nhiên, thêm HMAC-SHA256 theo mô hình Encrypt-then-MAC. Hệ thống kiểm tra toàn vẹn trước khi giải mã nên chống được padding oracle. AES-128 cho 128 bit độ mạnh, đạt mức SP 800-57 yêu cầu sau năm 2030.

**H13. Hệ thống chạy nhiều server thì có vấn đề gì?**
Có. Cache Replay và bộ đếm rate limit đang nằm trong RAM nên mỗi process có bản riêng. Cần chuyển sang Redis (xem điểm yếu số 1).

**H14. Rate limit dùng thuật toán gì?**
Sliding Window Log: lưu mốc thời gian của từng request trong 60 giây gần nhất, xóa các mốc cũ rồi đếm. Cách này chính xác hơn Fixed Window, vốn bị dồn gấp đôi request ở ranh giới giữa hai phút.

**H15. Vì sao cấm gửi API Key qua URL?**
URL được ghi vào access log của server và proxy, vào lịch sử trình duyệt và header Referer, nên key dễ bị lộ (CWE-598). Key phải gửi trong header `X-API-Key`.

---

*Tài liệu đi kèm: [README.md](README.md) (kiến trúc), [HUONG_DAN_CHAY.md](HUONG_DAN_CHAY.md) (cách chạy). Khi trích dẫn trong báo cáo, nên ghi kèm đường dẫn gốc của chuẩn (csrc.nist.gov, iso.org) và kiểm tra lại số mục so với bản gốc.*
