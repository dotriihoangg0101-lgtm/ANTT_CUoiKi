import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Cấu hình cơ sở cho ứng dụng Quản lý, Cấp phát và Kiểm soát API Key an toàn."""

    SECRET_KEY = os.environ.get("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "sqlite:///secure_api_manager.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Khóa bí mật Pepper dùng cho HMAC-SHA256 khi băm API Key
    API_KEY_PEPPER = os.environ.get("API_KEY_PEPPER")

    # Khóa Fernet (32-byte base64) dùng mã hóa đối xứng AES-128-CBC + HMAC
    MASTER_ENCRYPTION_KEY = os.environ.get("MASTER_ENCRYPTION_KEY")

    # Bảo mật Session & Cookie
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = os.getenv("REMEMBER_COOKIE_SECURE", "0") == "1"
    REMEMBER_COOKIE_DURATION = timedelta(days=1)
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # Cấu hình Rate Limiter & Phát hiện xâm nhập (Auto-Freeze)
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    AUTO_FREEZE_THRESHOLD = int(os.getenv("AUTO_FREEZE_THRESHOLD", "5"))
    HMAC_MAX_TIMESTAMP_SKEW_SECONDS = 300  # Chống Replay Attack trong cửa sổ 5 phút
    # Số vòng lặp PBKDF2-HMAC-SHA256 (NIST SP 800-132; OWASP khuyến nghị >= 600.000)
    PASSWORD_PBKDF2_ITERATIONS = int(os.getenv("PASSWORD_PBKDF2_ITERATIONS", "600000"))
    DEMO_MODE = os.environ.get("DEMO_MODE", "0") == "1"
    # Mật khẩu 2 tài khoản demo (chỉ dùng khi DEMO_MODE=1) — khai báo trong .env
    DEMO_ADMIN_PASSWORD = os.environ.get("DEMO_ADMIN_PASSWORD")
    DEMO_DEV_PASSWORD = os.environ.get("DEMO_DEV_PASSWORD")


class TestingConfig(Config):
    TESTING = True
    DEMO_MODE = True
    DEMO_ADMIN_PASSWORD = "Admin@123456"
    DEMO_DEV_PASSWORD = "Dev@123456"
    SECRET_KEY = "testing-only-secret-key-hutech-antt-2026-fixed-value"
    API_KEY_PEPPER = "testing-only-pepper-secret-hutech-antt-2026-fixed-val"
    MASTER_ENCRYPTION_KEY = "dGVzdGluZy1vbmx5LWZlcm5ldC1tYXN0ZXIta2V5LTIwMjY="
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    AUTO_FREEZE_THRESHOLD = 5
    # Giảm số vòng PBKDF2 CHỈ trong test để bộ test chạy nhanh (định dạng hash không đổi)
    PASSWORD_PBKDF2_ITERATIONS = 1000


FORBIDDEN_EXAMPLE_SECRETS = {
    "CHANGE_ME_generate_with_secrets_token_hex_32",
    "CHANGE_ME_generate_with_secrets_token_urlsafe_32",
    "CHANGE_ME_generate_with_fernet_generate_key",
    "dev-secret-key-change-in-production-9f8e7d6c5b4a3f2e1d0c",
    "server-side-hmac-pepper-secret-2026-hutech-antt-99887766",
    "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
    "fallback-dev-secret-key-hutech-antt-2026-secure",
    "default-pepper-hutech-antt-2026-do-not-expose",
}


def validate_secrets(app) -> None:
    """Kiểm tra các khóa bí mật bắt buộc khi khởi tạo ứng dụng."""
    for var_name in ("SECRET_KEY", "API_KEY_PEPPER", "MASTER_ENCRYPTION_KEY"):
        val = app.config.get(var_name)
        if (
            not val
            or not isinstance(val, str)
            or len(val.strip()) < 32
            or val.strip() in FORBIDDEN_EXAMPLE_SECRETS
            or val.strip().startswith("CHANGE_ME")
        ):
            raise RuntimeError(f"Thiếu hoặc dùng secret mẫu: {var_name}")
