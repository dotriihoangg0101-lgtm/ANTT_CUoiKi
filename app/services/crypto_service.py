import base64
import hashlib
import hmac
import secrets
import time
from typing import Tuple

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError, VerificationError
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import current_app, has_app_context

# =============================================================================
# BĂM MẬT KHẨU: PBKDF2-HMAC-SHA256
#   - NIST SP 800-132 (12/2010): PBKDF2, salt >= 128 bit, số vòng lặp càng cao càng tốt.
#   - NIST SP 800-63B-4 (08/2025) mục 3.1.1.2: mật khẩu SHALL được lưu ở dạng chống tấn công
#     ngoại tuyến, có salt và băm bằng lược đồ băm mật khẩu phù hợp (PBKDF2 theo SP 800-132).
#   - OWASP Password Storage Cheat Sheet: PBKDF2-HMAC-SHA256 tối thiểu 600.000 vòng.
# Định dạng lưu: $pbkdf2-sha256$<số_vòng>$<salt_base64>$<hash_base64>
# =============================================================================
PBKDF2_SCHEME = "pbkdf2-sha256"
PBKDF2_DEFAULT_ITERATIONS = 600_000
PBKDF2_SALT_BYTES = 16   # 128 bit (SP 800-132 mục 5.1)
PBKDF2_DKLEN = 32        # 256 bit đầu ra

# Chỉ dùng để XÁC MINH các hash Argon2id cũ (tạo trước khi chuyển sang PBKDF2).
# Khi người dùng đăng nhập thành công, hash cũ được băm lại bằng PBKDF2 (rehash-on-login).
_legacy_argon2 = PasswordHasher()

# Bộ nhớ đệm chống phát lại (Nonce cache) trong cửa sổ thời gian hiệu lực.
# Lưu ý: In-memory chỉ đúng với 1 process; môi trường Production nên dùng Redis: SET NX EX 300.
_SEEN_SIGNATURES: dict[tuple, float] = {}


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4))


def _pbkdf2_iterations() -> int:
    if has_app_context():
        return int(current_app.config.get("PASSWORD_PBKDF2_ITERATIONS", PBKDF2_DEFAULT_ITERATIONS))
    return PBKDF2_DEFAULT_ITERATIONS


def hash_password(raw_password: str) -> str:
    """Băm mật khẩu bằng PBKDF2-HMAC-SHA256 (NIST SP 800-132) với salt ngẫu nhiên 128 bit."""
    iterations = _pbkdf2_iterations()
    salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", raw_password.encode("utf-8"), salt, iterations, PBKDF2_DKLEN)
    return f"${PBKDF2_SCHEME}${iterations}${_b64e(salt)}${_b64e(dk)}"


def verify_password(password_hash: str, raw_password: str) -> bool:
    """Kiểm tra mật khẩu (so sánh hằng thời gian). Hỗ trợ cả hash Argon2id cũ."""
    if not password_hash:
        return False
    if password_hash.startswith(f"${PBKDF2_SCHEME}$"):
        try:
            _, _, iter_s, salt_s, hash_s = password_hash.split("$")
            iterations = int(iter_s)
            salt, expected = _b64d(salt_s), _b64d(hash_s)
        except (ValueError, TypeError):
            return False
        dk = hashlib.pbkdf2_hmac("sha256", raw_password.encode("utf-8"), salt, iterations, len(expected))
        return hmac.compare_digest(dk, expected)
    if password_hash.startswith("$argon2"):
        try:
            return _legacy_argon2.verify(password_hash, raw_password)
        except (VerifyMismatchError, InvalidHashError, VerificationError):
            return False
    return False


def password_needs_rehash(password_hash: str) -> bool:
    """True nếu hash là Argon2 cũ hoặc PBKDF2 có số vòng thấp hơn cấu hình hiện tại."""
    if not password_hash.startswith(f"${PBKDF2_SCHEME}$"):
        return True
    try:
        return int(password_hash.split("$")[2]) < _pbkdf2_iterations()
    except (IndexError, ValueError):
        return True


def _get_pepper() -> bytes:
    pepper = current_app.config["API_KEY_PEPPER"]
    return pepper.encode("utf-8")


def hash_api_key(raw_key: str) -> str:
    """
    Băm một chiều API Key bằng HMAC-SHA256 kết hợp với khóa bí mật Server Pepper.
    Đảm bảo ngay cả khi lộ toàn bộ Database thì kẻ tấn công cũng không thể khôi phục API Key.
    """
    return hmac.new(_get_pepper(), raw_key.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_api_key_hash(raw_key: str, stored_hash: str) -> bool:
    """
    So sánh mã băm API Key bằng thuật toán hằng thời gian (Constant-Time Comparison)
    nhằm triệt tiêu hoàn toàn lỗ hổng Timing Side-Channel Attack.
    """
    computed_hash = hash_api_key(raw_key)
    return hmac.compare_digest(computed_hash, stored_hash)


def _get_fernet() -> MultiFernet:
    """
    Dẫn xuất khóa Fernet 256 bit từ MASTER_ENCRYPTION_KEY bằng HKDF-SHA256
    (RFC 5869; là KDF dạng "extract-then-expand" của NIST SP 800-56C Rev.2, 08/2020).
    MultiFernet: luôn MÃ HÓA bằng khóa HKDF mới; vẫn GIẢI MÃ được dữ liệu cũ
    được mã hóa bằng khóa dẫn xuất kiểu SHA-256 trần (phiên bản trước).
    """
    master = current_app.config["MASTER_ENCRYPTION_KEY"].encode("utf-8")
    hkdf_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"SEC-GATEWAY/HKDF-salt/v1",
        info=b"SEC-GATEWAY/fernet-data-encryption/v1",
    ).derive(master)
    legacy_key = hashlib.sha256(master).digest()
    return MultiFernet([
        Fernet(base64.urlsafe_b64encode(hkdf_key)),
        Fernet(base64.urlsafe_b64encode(legacy_key)),
    ])


def encrypt_sensitive_value(plaintext: str) -> str:
    """Mã hóa đối xứng dữ liệu nhạy cảm bằng Fernet (AES-128-CBC + HMAC-SHA256)."""
    if not plaintext:
        return ""
    f = _get_fernet()
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_sensitive_value(ciphertext: str) -> str:
    """Giải mã dữ liệu nhạy cảm đã mã hóa bằng Fernet."""
    if not ciphertext:
        return ""
    f = _get_fernet()
    try:
        return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return "[DECRYPTION_FAILED]"


def generate_raw_api_key(environment: str = "live") -> Tuple[str, str]:
    """
    Sinh API Key có cấu trúc chuẩn công nghiệp bằng CSPRNG (secrets module):
    Định dạng: ak_<env>_<8_hex_prefix>_<32_chars_secret>
    Trả về: (key_prefix, full_raw_key)
    """
    env_tag = "live" if environment == "live" else "test"
    prefix_id = secrets.token_hex(4)  # 8 ký tự hex ngẫu nhiên
    key_prefix = f"ak_{env_tag}_{prefix_id}"
    secret_body = secrets.token_urlsafe(24)  # 32 ký tự URL-safe độ ngẫu nhiên cao (192-bit entropy)
    full_raw_key = f"{key_prefix}_{secret_body}"
    return key_prefix, full_raw_key


def generate_signing_secret() -> str:
    """Sinh khóa bí mật phụ (Signing Secret) dùng để ký gói tin HMAC Request Signing."""
    return f"whsec_{secrets.token_urlsafe(24)}"


def compute_request_signature(
    signing_secret: str,
    timestamp: str,
    method: str,
    path: str,
    body: str = ""
) -> str:
    """
    Tính chữ ký số HMAC-SHA256 cho gói tin HTTP:
    Canonical String = "<timestamp>.<UPPER_METHOD>.<path>.<body>"
    """
    canonical_payload = f"{timestamp}.{method.upper()}.{path}.{body or ''}"
    return hmac.new(
        signing_secret.encode("utf-8"),
        canonical_payload.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def verify_request_signature(
    signing_secret: str,
    timestamp_str: str,
    provided_signature: str,
    method: str,
    path: str,
    body: str = "",
    allow_replay_check: bool = True,
    key_id: int = 0,
) -> Tuple[bool, str]:
    """
    Kiểm tra tính toàn vẹn của gói tin (Anti-Tampering) và chống phát lại (Anti-Replay Attack).
    Lưu ý: Bộ nhớ _SEEN_SIGNATURES in-memory chỉ áp dụng cho 1 process; production nên dùng Redis SET NX EX 300.
    """
    if not timestamp_str or not provided_signature:
        return False, "MISSING_SIGNATURE_OR_TIMESTAMP"

    try:
        req_ts = int(timestamp_str)
    except ValueError:
        return False, "INVALID_TIMESTAMP_FORMAT"

    now_ts = int(time.time())
    max_skew = current_app.config.get("HMAC_MAX_TIMESTAMP_SKEW_SECONDS", 300)

    # 1. Kiểm tra độ lệch thời gian (Mặc định quá 5 phút sẽ bị từ chối -> Chống Replay Attack)
    if abs(now_ts - req_ts) > max_skew:
        return False, "TIMESTAMP_EXPIRED_REPLAY_DETECTED"

    # 2. Tính lại HMAC-SHA256 phía Server và đối chiếu hằng thời gian
    clean_sig = provided_signature.strip()
    expected_sig = compute_request_signature(signing_secret, timestamp_str, method, path, body)
    if not hmac.compare_digest(expected_sig, clean_sig):
        return False, "INVALID_HMAC_SIGNATURE_TAMPERED"

    # 3. Dọn dẹp bộ nhớ đệm chữ ký đã hết hạn
    for sig_key in list(_SEEN_SIGNATURES.keys()):
        if _SEEN_SIGNATURES[sig_key] < now_ts:
            _SEEN_SIGNATURES.pop(sig_key, None)

    # 4. Kiểm tra và ghi nhận chữ ký vào _SEEN_SIGNATURES để chống Replay trong cửa sổ 300s
    if allow_replay_check:
        cache_key = (key_id, clean_sig)
        if cache_key in _SEEN_SIGNATURES:
            return False, "REPLAY_DETECTED"
        _SEEN_SIGNATURES[cache_key] = now_ts + max_skew

    return True, "VALID_SIGNATURE"
