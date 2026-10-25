"""
Sinh file .env chứa TOÀN BỘ bí mật của dự án (đã nằm trong .gitignore, không bị đẩy lên Git):
  - SECRET_KEY, API_KEY_PEPPER, MASTER_ENCRYPTION_KEY
  - Mật khẩu 2 tài khoản demo (admin, dev_hoang)
  - 8 API Key demo + 8 Signing Secret cho trang Playground

Cách dùng (chạy ở thư mục gốc dự án):
    python scripts/tao_env.py            # tạo .env mới (dừng lại nếu .env đã tồn tại)
    python scripts/tao_env.py --force    # ghi đè .env cũ (sau đó phải chạy lại: python seed.py)

Muốn chia sẻ cho bạn cùng nhóm: chỉ cần gửi riêng file .env (KHÔNG commit lên Git).
"""
import base64
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env"

# Prefix cố định (không phải bí mật) để khớp tài liệu & kịch bản demo; phần bí mật sinh ngẫu nhiên.
DEMO_KEY_PREFIXES = {
    "FULL_ACCESS": "ak_live_1001full",
    "READ_ONLY": "ak_live_2002read",
    "IP_RESTRICTED": "ak_live_3003ipwl",
    "EXPIRED_KEY": "ak_live_4004expr",
    "REVOKED_KEY": "ak_live_5005revk",
    "ROTATING_OLD_KEY": "ak_live_6006grce",
    "RATE_LIMITED_FREE": "ak_test_7007rate",
    "INTRUSION_TARGET": "ak_live_8008frez",
}


def build_env_text() -> str:
    fernet_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    lines = [
        "# ================================================================",
        "# FILE BÍ MẬT CỦA DỰ ÁN — KHÔNG COMMIT LÊN GIT (đã có trong .gitignore)",
        "# Sinh bởi: python scripts/tao_env.py",
        "# ================================================================",
        "",
        "# --- Cấu hình chạy ---",
        "FLASK_DEBUG=0",
        "DEMO_MODE=1",
        "DATABASE_URL=sqlite:///secure_api_manager.db",
        "RATELIMIT_STORAGE_URI=memory://",
        "AUTO_FREEZE_THRESHOLD=5",
        "",
        "# --- Khóa bí mật phía server ---",
        f"SECRET_KEY={secrets.token_urlsafe(48)}",
        f"API_KEY_PEPPER={secrets.token_urlsafe(48)}",
        f"MASTER_ENCRYPTION_KEY={fernet_key}",
        "",
        "# --- Mật khẩu tài khoản demo (chỉ dùng khi DEMO_MODE=1) ---",
        f"DEMO_ADMIN_PASSWORD={secrets.token_urlsafe(15)}",
        f"DEMO_DEV_PASSWORD={secrets.token_urlsafe(15)}",
        "",
        "# --- 8 API Key demo cho trang Playground (chỉ dùng khi DEMO_MODE=1) ---",
    ]
    for name, prefix in DEMO_KEY_PREFIXES.items():
        lines.append(f"DEMO_KEY_{name}={prefix}_{secrets.token_urlsafe(24)}")
        lines.append(f"DEMO_SIGNING_SECRET_{name}=whsec_{secrets.token_urlsafe(24)}")
    return "\n".join(lines) + "\n"


def main() -> int:
    force = "--force" in sys.argv[1:]
    if ENV_PATH.exists() and not force:
        print(f"[DỪNG] Đã có {ENV_PATH}. Muốn tạo lại toàn bộ khóa mới thì chạy: python scripts/tao_env.py --force")
        return 1
    ENV_PATH.write_text(build_env_text(), encoding="utf-8")
    print(f"[OK] Đã ghi {ENV_PATH}")
    print("Bước tiếp theo: xóa DB cũ (instance/secure_api_manager.db) rồi chạy: python seed.py")
    print("Mật khẩu đăng nhập demo nằm trong .env (DEMO_ADMIN_PASSWORD, DEMO_DEV_PASSWORD).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
