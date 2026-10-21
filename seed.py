"""
Script khởi tạo & đặt lại dữ liệu mẫu (Seed Database) cho 8 Ngữ cảnh Demo Đồ án.
Chạy lệnh:
    python seed.py
"""
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from app import create_app
from app.services.seed_service import DEMO_KEYS_CATALOG, seed_initial_data

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        result = seed_initial_data(force_reset=True)
        if result.get("status") != "seeded":
            print("[LỖI] seed.py chỉ chạy khi DEMO_MODE=1 trong .env.")
            sys.exit(1)
        print("=" * 72)
        print("[SUCCESS] ĐÃ KHỞI TẠO DATABASE & 8 NGỮ CẢNH DEMO THÀNH CÔNG!")
        print(f" - Số lượng Users (Argon2id): {result['users']}")
        print(f" - Số lượng API Keys (HMAC-SHA256 + Pepper): {result['api_keys']}")
        print(f" - Số lượng Hồ sơ VaultRecords (Fernet Encrypted): {result['vault_records']}")
        print("=" * 72)
        print("Tài khoản đăng nhập Dashboard:")
        print(" 1. Admin     : admin      / <giá trị DEMO_ADMIN_PASSWORD trong .env>")
        print(" 2. Developer : dev_hoang  / <giá trị DEMO_DEV_PASSWORD trong .env>")
        print("-" * 72)
        print("Danh sách API Key mẫu cho 8 Ngữ cảnh Demo:")
        for key_id, info in DEMO_KEYS_CATALOG.items():
            print(f" * [{key_id}] {info['name']}")
            print(f"   Raw Key : {info['raw_key']}")
        print("=" * 72)
