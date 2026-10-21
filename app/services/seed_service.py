import os
import secrets
from datetime import datetime, timedelta, timezone
from flask import current_app

from app.extensions import db
from app.middleware.api_auth import reset_rate_limit_buckets
from app.models import ApiKey, ApiUsageLog, SecurityAuditLog, User, VaultRecord
from app.services.key_service import KeyService


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# DEMO ONLY – không dùng production
# Danh sách các API Key mẫu dùng cho 8 Ngữ cảnh Demo trên trang Playground.
# Giá trị raw_key / signing_secret KHÔNG nằm trong mã nguồn: được đọc từ file .env
# (biến DEMO_KEY_<TÊN> và DEMO_SIGNING_SECRET_<TÊN>, sinh tự động bằng scripts/tao_env.py).
# LƯU Ý BẢO MẬT: Trong CSDL (bảng api_keys), các khóa này CHỈ được lưu dưới dạng mã băm HMAC-SHA256!
DEMO_KEYS_CATALOG = {
    "full_access": {
        "name": "1. Production Full-Access Key (Chuẩn)",
        "raw_key": os.environ.get("DEMO_KEY_FULL_ACCESS", ""),
        "signing_secret": os.environ.get("DEMO_SIGNING_SECRET_FULL_ACCESS", ""),
        "environment": "live",
        "scopes": "read:records,write:records,admin:records,transfer:funds",
        "rate_limit": 60,
        "allowed_ips": "",
        "scenario_desc": "Key hợp lệ có toàn quyền đọc/ghi/xóa và ký giao dịch HMAC.",
    },
    "read_only": {
        "name": "2. Partner Read-Only Key (Giới hạn Scope)",
        "raw_key": os.environ.get("DEMO_KEY_READ_ONLY", ""),
        "signing_secret": os.environ.get("DEMO_SIGNING_SECRET_READ_ONLY", ""),
        "environment": "live",
        "scopes": "read:records",
        "rate_limit": 30,
        "allowed_ips": "",
        "scenario_desc": "Chỉ có quyền 'read:records'. Gọi POST/DELETE sẽ bị chặn ở Lớp 4 (403 Insufficient Scope).",
    },
    "ip_restricted": {
        "name": "3. Internal Core Server Key (Giới hạn IP Whitelist)",
        "raw_key": os.environ.get("DEMO_KEY_IP_RESTRICTED", ""),
        "signing_secret": os.environ.get("DEMO_SIGNING_SECRET_IP_RESTRICTED", ""),
        "environment": "live",
        "scopes": "read:records,write:records",
        "rate_limit": 60,
        "allowed_ips": "127.0.0.1, 10.10.0.0/16",
        "scenario_desc": "Chỉ cho phép gọi từ IP 127.0.0.1 hoặc 10.10.0.0/16. Gọi từ IP ngoài sẽ bị chặn ở Lớp 3 (403 IP Blocked).",
    },
    "expired_key": {
        "name": "4A. Legacy Campaign Key (Đã hết hạn TTL)",
        "raw_key": os.environ.get("DEMO_KEY_EXPIRED_KEY", ""),
        "signing_secret": os.environ.get("DEMO_SIGNING_SECRET_EXPIRED_KEY", ""),
        "environment": "live",
        "scopes": "read:records,write:records",
        "rate_limit": 60,
        "allowed_ips": "",
        "scenario_desc": "Key đã quá hạn sử dụng (expires_at < hiện tại). Gọi API sẽ bị chặn ở Lớp 2 (401 Expired).",
    },
    "revoked_key": {
        "name": "4B. Leaked GitHub Key (Đã bị thu hồi khẩn cấp)",
        "raw_key": os.environ.get("DEMO_KEY_REVOKED_KEY", ""),
        "signing_secret": os.environ.get("DEMO_SIGNING_SECRET_REVOKED_KEY", ""),
        "environment": "live",
        "scopes": "read:records,write:records",
        "rate_limit": 60,
        "allowed_ips": "",
        "scenario_desc": "Key bị phát hiện lộ trên GitHub nên Admin đã bấm Revoke. Bị chặn ngay ở Lớp 2 (401 Revoked).",
    },
    "rotating_old_key": {
        "name": "5. Rotating Service Key (Đang trong 24h Ân hạn - Grace Period)",
        "raw_key": os.environ.get("DEMO_KEY_ROTATING_OLD_KEY", ""),
        "signing_secret": os.environ.get("DEMO_SIGNING_SECRET_ROTATING_OLD_KEY", ""),
        "environment": "live",
        "scopes": "read:records,write:records",
        "rate_limit": 60,
        "allowed_ips": "",
        "scenario_desc": "Key cũ vừa được Rotate sang Key mới nhưng vẫn sống trong 24h ân hạn kèm Header cảnh báo X-API-Key-Deprecated.",
    },
    "rate_limited_free": {
        "name": "6. Free-Tier Sandbox Key (Giới hạn 5 req/phút)",
        "raw_key": os.environ.get("DEMO_KEY_RATE_LIMITED_FREE", ""),
        "signing_secret": os.environ.get("DEMO_SIGNING_SECRET_RATE_LIMITED_FREE", ""),
        "environment": "test",
        "scopes": "read:records",
        "rate_limit": 5,
        "allowed_ips": "",
        "scenario_desc": "Chỉ cho phép tối đa 5 requests/phút. Gọi đến lần thứ 6 sẽ bị chặn ở Lớp 5 (429 Too Many Requests).",
    },
    "intrusion_target": {
        "name": "7. Intrusion Target Key (Dùng để test Tự động Đóng băng Auto-Freeze)",
        "raw_key": os.environ.get("DEMO_KEY_INTRUSION_TARGET", ""),
        "signing_secret": os.environ.get("DEMO_SIGNING_SECRET_INTRUSION_TARGET", ""),
        "environment": "live",
        "scopes": "read:records",
        "rate_limit": 60,
        "allowed_ips": "127.0.0.1",
        "scenario_desc": "Khi bị gọi sai quyền hoặc sai IP 5 lần liên tiếp, hệ thống tự động khóa cứng (AUTO_FROZEN).",
    },
}


def missing_demo_secrets() -> list[str]:
    """Trả về tên các biến .env còn thiếu / sai định dạng cho bộ Key demo (rỗng = đủ)."""
    missing = []
    for key_id, info in DEMO_KEYS_CATALOG.items():
        raw_key = info["raw_key"] or ""
        if len(raw_key.split("_")) < 4 or not raw_key.startswith(("ak_live_", "ak_test_")):
            missing.append(f"DEMO_KEY_{key_id.upper()}")
        if not info["signing_secret"]:
            missing.append(f"DEMO_SIGNING_SECRET_{key_id.upper()}")
    return missing


def seed_initial_data(force_reset: bool = False) -> dict:
    """
    Khởi tạo dữ liệu mẫu toàn diện cho Database phục vụ kiểm thử và thuyết trình 8 Ngữ cảnh Demo.
    """
    db.create_all()

    if not current_app.config.get("DEMO_MODE", False):
        return {"status": "disabled", "message": "DEMO_MODE is disabled; skipping demo seed."}

    if not force_reset and User.query.first() is not None:
        return {"status": "skipped", "message": "Database already seeded."}

    if force_reset:
        from app.services.crypto_service import _SEEN_SIGNATURES
        _SEEN_SIGNATURES.clear()
        reset_rate_limit_buckets()
        ApiUsageLog.query.delete()
        SecurityAuditLog.query.delete()
        ApiKey.query.delete()
        VaultRecord.query.delete()
        User.query.delete()
        db.session.commit()

    # 1. Tạo 2 tài khoản User mẫu (Mật khẩu băm bằng Argon2id)
    # DEMO ONLY – không dùng production
    admin_password = current_app.config.get("DEMO_ADMIN_PASSWORD")
    if not admin_password:
        admin_password = secrets.token_urlsafe(12)
        print(f"[DEMO SEED] Generated one-time DEMO_ADMIN_PASSWORD for 'admin': {admin_password}")
    dev_password = current_app.config.get("DEMO_DEV_PASSWORD")
    if not dev_password:
        dev_password = secrets.token_urlsafe(12)
        print(f"[DEMO SEED] Generated one-time DEMO_DEV_PASSWORD for 'dev_hoang': {dev_password}")

    admin_user = User(
        username="admin",
        email="admin@hutech-sec.vn",
        role="admin",
        is_active=True,
    )
    admin_user.set_password(admin_password)

    dev_user = User(
        username="dev_hoang",
        email="hoang.dev@hutech-sec.vn",
        role="developer",
        is_active=True,
    )
    dev_user.set_password(dev_password)

    db.session.add_all([admin_user, dev_user])
    db.session.commit()

    # 2. Tạo 5 Hồ sơ Nghiệp vụ nhạy cảm trong bảng vault_records (Mã hóa Fernet cho cột secret_note)
    sample_records = [
        (
            "CUST-2026-001",
            "Nguyễn Văn An",
            "9704-15**-****-8821",
            "Hạn mức tín dụng VIP Platinum - Mã PIN dự phòng: 849201",
            158500000.0,
            "SECRET",
        ),
        (
            "CUST-2026-002",
            "Trần Thị Bích Ngọc",
            "9704-36**-****-4410",
            "Tài khoản thanh toán doanh nghiệp - Xác thực 2 lớp bắt buộc",
            420000000.0,
            "CONFIDENTIAL",
        ),
        (
            "CUST-2026-003",
            "Lê Hoàng Minh Quân",
            "9704-22**-****-1095",
            "Khách hàng cá nhân ưu tiên - Chi nhánh TP.HCM",
            64200000.0,
            "CONFIDENTIAL",
        ),
        (
            "CUST-2026-004",
            "Phạm Thu Hà",
            "9704-07**-****-6639",
            "Hồ sơ vay mua nhà đã tất toán - Lưu trữ kiểm toán",
            19500000.0,
            "PUBLIC",
        ),
        (
            "CUST-2026-005",
            "Đỗ Trí Hoàng (HUTECH SecLab)",
            "9704-88**-****-2026",
            "Quỹ bảo mật hệ thống API Gateway - Yêu cầu chữ ký HMAC khi giải ngân",
            999000000.0,
            "SECRET",
        ),
    ]

    for code, name, acc_mask, secret_note, balance, classification in sample_records:
        rec = VaultRecord(
            customer_code=code,
            full_name=name,
            account_number_masked=acc_mask,
            balance=balance,
            classification=classification,
            created_by_key="SYSTEM_SEED",
        )
        rec.set_secret_note(secret_note)
        db.session.add(rec)

    db.session.commit()

    # 3. Tạo bộ API Key đại diện cho 8 Ngữ cảnh Bảo mật
    now = utc_now()

    # Key 1: Full-Access
    c1 = DEMO_KEYS_CATALOG["full_access"]
    KeyService.create_api_key(
        user=admin_user,
        name=c1["name"],
        environment=c1["environment"],
        scopes=c1["scopes"],
        rate_limit_per_minute=c1["rate_limit"],
        allowed_ips=c1["allowed_ips"],
        expires_in_days=90,
        fixed_raw_key=c1["raw_key"],
        fixed_signing_secret=c1["signing_secret"],
    )

    # Key 2: Read-Only Scope
    c2 = DEMO_KEYS_CATALOG["read_only"]
    KeyService.create_api_key(
        user=dev_user,
        name=c2["name"],
        environment=c2["environment"],
        scopes=c2["scopes"],
        rate_limit_per_minute=c2["rate_limit"],
        allowed_ips=c2["allowed_ips"],
        expires_in_days=60,
        fixed_raw_key=c2["raw_key"],
        fixed_signing_secret=c2["signing_secret"],
    )

    # Key 3: IP Whitelisted
    c3 = DEMO_KEYS_CATALOG["ip_restricted"]
    KeyService.create_api_key(
        user=admin_user,
        name=c3["name"],
        environment=c3["environment"],
        scopes=c3["scopes"],
        rate_limit_per_minute=c3["rate_limit"],
        allowed_ips=c3["allowed_ips"],
        expires_in_days=60,
        fixed_raw_key=c3["raw_key"],
        fixed_signing_secret=c3["signing_secret"],
    )

    # Key 4A: Expired Key (hết hạn từ 7 ngày trước)
    c4a = DEMO_KEYS_CATALOG["expired_key"]
    KeyService.create_api_key(
        user=dev_user,
        name=c4a["name"],
        environment=c4a["environment"],
        scopes=c4a["scopes"],
        rate_limit_per_minute=c4a["rate_limit"],
        allowed_ips=c4a["allowed_ips"],
        fixed_raw_key=c4a["raw_key"],
        fixed_signing_secret=c4a["signing_secret"],
        custom_expires_at=now - timedelta(days=7),
    )

    # Key 4B: Revoked Key (Đã bị thu hồi do lộ trên GitHub)
    c4b = DEMO_KEYS_CATALOG["revoked_key"]
    rev_key, _, _ = KeyService.create_api_key(
        user=dev_user,
        name=c4b["name"],
        environment=c4b["environment"],
        scopes=c4b["scopes"],
        rate_limit_per_minute=c4b["rate_limit"],
        allowed_ips=c4b["allowed_ips"],
        expires_in_days=30,
        fixed_raw_key=c4b["raw_key"],
        fixed_signing_secret=c4b["signing_secret"],
    )
    KeyService.revoke_api_key(
        rev_key,
        admin_user,
        reason="Phát hiện lộ mã nguồn chứa Key trên kho lưu trữ GitHub công khai (Secret Scanning Alert)",
    )

    # Key 5: Rotating Old Key (Đang trong thời gian ân hạn 24h - Grace Period)
    c5 = DEMO_KEYS_CATALOG["rotating_old_key"]
    grace_key, _, _ = KeyService.create_api_key(
        user=admin_user,
        name=c5["name"],
        environment=c5["environment"],
        scopes=c5["scopes"],
        rate_limit_per_minute=c5["rate_limit"],
        allowed_ips=c5["allowed_ips"],
        expires_in_days=30,
        fixed_raw_key=c5["raw_key"],
        fixed_signing_secret=c5["signing_secret"],
    )
    grace_key.grace_period_until = now + timedelta(hours=24)
    db.session.commit()

    # Key 6: Free-Tier Rate Limited (5 requests / minute)
    c6 = DEMO_KEYS_CATALOG["rate_limited_free"]
    KeyService.create_api_key(
        user=dev_user,
        name=c6["name"],
        environment=c6["environment"],
        scopes=c6["scopes"],
        rate_limit_per_minute=c6["rate_limit"],
        allowed_ips=c6["allowed_ips"],
        expires_in_days=30,
        fixed_raw_key=c6["raw_key"],
        fixed_signing_secret=c6["signing_secret"],
    )

    # Key 7: Intrusion Target Key (Dùng để demo Auto-Freeze)
    c7 = DEMO_KEYS_CATALOG["intrusion_target"]
    KeyService.create_api_key(
        user=dev_user,
        name=c7["name"],
        environment=c7["environment"],
        scopes=c7["scopes"],
        rate_limit_per_minute=c7["rate_limit"],
        allowed_ips=c7["allowed_ips"],
        expires_in_days=30,
        fixed_raw_key=c7["raw_key"],
        fixed_signing_secret=c7["signing_secret"],
    )

    return {
        "status": "seeded",
        "users": User.query.count(),
        "api_keys": ApiKey.query.count(),
        "vault_records": VaultRecord.query.count(),
    }
