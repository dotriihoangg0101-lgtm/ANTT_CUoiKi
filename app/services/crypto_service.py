import base64
import hashlib
import hmac
import secrets
import time
from typing import Tuple

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError, VerificationError
from cryptography.fernet import Fernet, InvalidToken
from flask import current_app

# Khởi tạo bộ băm mật khẩu chuẩn Argon2id (Chiến thắng cuộc thi Password Hashing Competition)
ph = PasswordHasher(
    time_cost=2,
    memory_cost=32768,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

# Bộ nhớ đệm chống phát lại (Nonce cache) trong cửa sổ thời gian hiệu lực.
# Lưu ý: In-memory chỉ đúng với 1 process; môi trường Production nên dùng Redis: SET NX EX 300.
_SEEN_SIGNATURES: dict[tuple, float] = {}


def hash_password(raw_password: str) -> str:
    """Băm mật khẩu người dùng bằng thuật toán Argon2id."""
    return ph.hash(raw_password)


def verify_password(password_hash: str, raw_password: str) -> bool:
    """Kiểm tra mật khẩu với mã băm Argon2id."""
    try:
        return ph.verify(password_hash, raw_password)
    except (VerifyMismatchError, InvalidHashError, VerificationError):
        return False


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


def _get_fernet() -> Fernet:
    raw_master = current_app.config["MASTER_ENCRYPTION_KEY"]
    # Đảm bảo khóa chuẩn 32-byte urlsafe-base64 cho Fernet (AES-128-CBC + HMAC-SHA256)
    digest = hashlib.sha256(raw_master.encode("utf-8")).digest()
    fernet_key = base64.urlsafe_b64encode(digest)
    return Fernet(fernet_key)


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
