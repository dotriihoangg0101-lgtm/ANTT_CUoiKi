"""
Chính sách mật khẩu theo NIST SP 800-63B-4 "Digital Identity Guidelines: Authentication
and Authenticator Management" (bản chính thức 08/2025), mục 3.1.1.2 Password Verifiers:

  - SHALL: mật khẩu dùng làm yếu tố xác thực DUY NHẤT phải dài tối thiểu 15 ký tự.
  - SHOULD: cho phép độ dài tối đa ít nhất 64 ký tự (ở đây cho phép 128).
  - SHALL: so sánh mật khẩu với danh sách chặn (blocklist) gồm mật khẩu phổ biến,
    dễ đoán hoặc đã bị lộ, kèm các từ theo ngữ cảnh (tên dịch vụ, username...).
  - SHALL NOT: áp quy tắc thành phần (bắt buộc chữ hoa / số / ký tự đặc biệt).
  - SHALL NOT: bắt đổi mật khẩu định kỳ (chỉ bắt đổi khi có bằng chứng bị lộ).
  - SHOULD: chấp nhận mọi ký tự ASCII in được, khoảng trắng và ký tự Unicode.
  - SHALL: mỗi Unicode code point được đếm là 1 ký tự khi kiểm tra độ dài.

Mật khẩu được chuẩn hóa NFKC trước khi đếm độ dài (SP 800-63B-4 khuyến nghị NFKC/NFKD).
"""
import unicodedata

MIN_LENGTH = 15
MAX_LENGTH = 128

# Danh sách chặn rút gọn (mật khẩu phổ biến nhất trong các vụ lộ dữ liệu, đã viết thường).
# Môi trường thật nên tra thêm dịch vụ Have I Been Pwned (k-anonymity) hoặc danh sách lớn hơn.
COMMON_PASSWORDS = {
    "123456789012345", "1234567890123456", "123456789123456", "000000000000000",
    "111111111111111", "qwertyuiopasdfg", "qwertyuiopasdfgh", "qwertyuiop123456",
    "1q2w3e4r5t6y7u8i", "1qaz2wsx3edc4rfv", "zaq12wsxcde34rfv", "passwordpassword",
    "password1234567", "password12345678", "password123456789", "iloveyou1234567",
    "administrator123", "administrator1234", "adminadminadmin", "admin1234567890",
    "letmeinletmein", "letmein123456789", "welcome12345678", "welcome123456789",
    "changeme1234567", "changemechangeme", "abc123456789012", "abcdefghijklmno",
    "abcdefghijklmnop", "matkhau12345678", "matkhaucuatoi123", "matkhaumanh12345",
    "toilanguoivietnam", "anhyeuem1234567", "emyeuanh1234567", "hutech123456789",
}

# Từ theo ngữ cảnh của chính hệ thống này.
CONTEXT_WORDS = ("hutech", "secgateway", "sec-gateway", "apikey", "api_key", "matkhau", "password")


def _normalize(password: str) -> str:
    return unicodedata.normalize("NFKC", password)


def validate_password(password: str, username: str = "", email: str = "") -> list[str]:
    """Trả về danh sách lỗi (rỗng nghĩa là mật khẩu hợp lệ theo SP 800-63B-4)."""
    errors: list[str] = []
    normalized = _normalize(password)
    lowered = normalized.lower()

    if len(normalized) < MIN_LENGTH:
        errors.append(f"Mật khẩu phải dài tối thiểu {MIN_LENGTH} ký tự (NIST SP 800-63B-4).")
    if len(normalized) > MAX_LENGTH:
        errors.append(f"Mật khẩu dài tối đa {MAX_LENGTH} ký tự.")

    if lowered in COMMON_PASSWORDS:
        errors.append("Mật khẩu nằm trong danh sách mật khẩu phổ biến / đã bị lộ.")
    if len(set(lowered)) <= 2:
        errors.append("Mật khẩu chỉ lặp lại 1–2 ký tự, quá dễ đoán.")
    if lowered.isdigit() and lowered in "01234567890123456789" * 2:
        errors.append("Mật khẩu là dãy số liên tiếp, quá dễ đoán.")

    context = [w for w in CONTEXT_WORDS]
    if username and len(username) >= 3:
        context.append(username.lower())
    if email and "@" in email:
        local_part = email.split("@", 1)[0].lower()
        if len(local_part) >= 3:
            context.append(local_part)
    stripped = lowered
    for word in context:
        stripped = stripped.replace(word, "")
    if stripped != lowered and len(stripped) < 8:
        errors.append("Mật khẩu chủ yếu chứa username, email hoặc tên hệ thống (từ theo ngữ cảnh).")

    return errors
