import json
import time
import pytest

from app import create_app
from app.config import TestingConfig
from app.extensions import db
from app.models import ApiKey, User, VaultRecord
from app.services.crypto_service import compute_request_signature
from app.services.key_service import KeyService
from app.services.seed_service import DEMO_KEYS_CATALOG, seed_initial_data


@pytest.fixture()
def client():
    app = create_app(TestingConfig)
    with app.app_context():
        seed_initial_data(force_reset=True)
        with app.test_client() as test_client:
            yield test_client


def test_cryptographic_storage_in_database(client):
    """Kiểm chứng Argon2id, HMAC-SHA256 và Fernet trong Database (Không lưu lộ Plaintext)."""
    admin = User.query.filter_by(username="admin").first()
    assert admin is not None
    assert admin.password_hash.startswith("$argon2id$")
    assert "Admin@123456" not in admin.password_hash
    assert admin.check_password("Admin@123456") is True

    raw_full_key = DEMO_KEYS_CATALOG["full_access"]["raw_key"]
    key_record = ApiKey.query.filter_by(key_prefix="ak_live_1001full").first()
    assert key_record is not None
    # Đảm bảo key_hash không chứa chuỗi raw_key và có độ dài chuẩn 64 ký tự Hex của SHA-256
    assert raw_full_key not in key_record.key_hash
    assert len(key_record.key_hash) == 64

    vault_rec = VaultRecord.query.first()
    assert vault_rec is not None
    assert vault_rec.encrypted_secret_note.startswith("gAAAAAB")
    assert "PIN" not in vault_rec.encrypted_secret_note
    assert "PIN" in vault_rec.get_secret_note()


def test_layer0_forbid_api_key_in_url_query(client):
    """Chốt chặn 0 (CWE-598): Cấm truyền API Key trên URL Query String."""
    raw_key = DEMO_KEYS_CATALOG["full_access"]["raw_key"]
    resp = client.get(f"/api/v1/records?api_key={raw_key}")
    assert resp.status_code == 400
    assert resp.get_json()["error_code"] == "API_KEY_IN_URL_FORBIDDEN"


def test_scenario1_happy_path_authentication(client):
    """Ngữ cảnh 1: Xác thực API Key hợp lệ và truy xuất dữ liệu từ Database."""
    raw_key = DEMO_KEYS_CATALOG["full_access"]["raw_key"]
    resp = client.get("/api/v1/records", headers={"X-API-Key": raw_key})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert data["total_records"] >= 5
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"


def test_scenario2_scope_least_privilege(client):
    """Ngữ cảnh 2: Kiểm soát phân quyền Scope (Read-Only bị chặn POST 403, Full-Access được phép 201)."""
    read_only_key = DEMO_KEYS_CATALOG["read_only"]["raw_key"]
    full_key = DEMO_KEYS_CATALOG["full_access"]["raw_key"]

    # Read-Only gọi GET -> 200 OK
    r_get = client.get("/api/v1/records", headers={"X-API-Key": read_only_key})
    assert r_get.status_code == 200

    # Read-Only gọi POST -> 403 INSUFFICIENT_SCOPE
    r_post_denied = client.post(
        "/api/v1/records",
        headers={"X-API-Key": read_only_key},
        json={"full_name": "Unauthorized Record"},
    )
    assert r_post_denied.status_code == 403
    assert r_post_denied.get_json()["error_code"] == "INSUFFICIENT_SCOPE"

    # Full-Access gọi POST -> 201 Created
    r_post_ok = client.post(
        "/api/v1/records",
        headers={"X-API-Key": full_key},
        json={"full_name": "Authorized New Customer", "balance": 88000000},
    )
    assert r_post_ok.status_code == 201
    assert r_post_ok.get_json()["status"] == "success"


def test_scenario3_ip_whitelist_and_cidr(client):
    """Ngữ cảnh 3: Kiểm soát IP Whitelist (127.0.0.1 & dải CIDR 10.10.0.0/16 được phép, IP lạ bị chặn 403)."""
    ip_key = DEMO_KEYS_CATALOG["ip_restricted"]["raw_key"]

    # Gọi từ IP lạ ngoài danh sách -> 403 IP_NOT_WHITELISTED
    r_blocked = client.get(
        "/api/v1/records",
        headers={"X-API-Key": ip_key, "X-Simulated-IP": "185.220.101.45"},
    )
    assert r_blocked.status_code == 403
    assert r_blocked.get_json()["error_code"] == "IP_NOT_WHITELISTED"

    # Gọi từ IP nằm trong dải CIDR 10.10.0.0/16 -> 200 OK
    r_cidr_ok = client.get(
        "/api/v1/records",
        headers={"X-API-Key": ip_key, "X-Simulated-IP": "10.10.25.88"},
    )
    assert r_cidr_ok.status_code == 200


def test_scenario4_expired_and_revoked_keys(client):
    """Ngữ cảnh 4: Chặn Key đã hết hạn (TTL) và Key đã bị thu hồi khẩn cấp (Revoked)."""
    expired_key = DEMO_KEYS_CATALOG["expired_key"]["raw_key"]
    revoked_key = DEMO_KEYS_CATALOG["revoked_key"]["raw_key"]

    r_exp = client.get("/api/v1/records", headers={"X-API-Key": expired_key})
    assert r_exp.status_code == 401
    assert r_exp.get_json()["error_code"] == "API_KEY_EXPIRED"

    r_rev = client.get("/api/v1/records", headers={"X-API-Key": revoked_key})
    assert r_rev.status_code == 401
    assert r_rev.get_json()["error_code"] == "API_KEY_REVOKED"


def test_scenario5_zero_downtime_key_rotation(client):
    """Ngữ cảnh 5: Xoay vòng khóa không gián đoạn (Cả Key mới và Key cũ trong Grace Period đều hoạt động)."""
    admin = User.query.filter_by(username="admin").first()
    old_key = ApiKey.query.filter_by(key_prefix="ak_live_1001full").first()
    old_raw = DEMO_KEYS_CATALOG["full_access"]["raw_key"]

    new_key, new_raw, _ = KeyService.rotate_api_key(old_key, admin, grace_period_hours=24)

    # Key mới hoạt động bình thường
    r_new = client.get("/api/v1/records", headers={"X-API-Key": new_raw})
    assert r_new.status_code == 200
    assert r_new.headers.get("X-API-Key-Deprecated") is None

    # Key cũ vẫn hoạt động trong 24h ân hạn nhưng trả kèm Header cảnh báo X-API-Key-Deprecated
    r_old = client.get("/api/v1/records", headers={"X-API-Key": old_raw})
    assert r_old.status_code == 200
    assert r_old.headers.get("X-API-Key-Deprecated") == "true"
    assert "X-API-Key-Sunset" in r_old.headers


def test_scenario6_per_key_rate_limiting(client):
    """Ngữ cảnh 6: Giới hạn lưu lượng theo từng Key (Free-Tier 5 req/phút, phát thứ 6 bị chặn 429)."""
    free_key = DEMO_KEYS_CATALOG["rate_limited_free"]["raw_key"]

    for i in range(5):
        r = client.get("/api/v1/records", headers={"X-API-Key": free_key})
        assert r.status_code == 200

    # Phát thứ 6 vượt ngưỡng 5 req/phút -> 429 Too Many Requests
    r6 = client.get("/api/v1/records", headers={"X-API-Key": free_key})
    assert r6.status_code == 429
    assert r6.get_json()["error_code"] == "RATE_LIMIT_EXCEEDED"
    assert "Retry-After" in r6.headers


def test_scenario7_auto_freeze_intrusion_detection(client):
    """Ngữ cảnh 7: Tự động đóng băng Key (Auto-Freeze) sau 5 lần vi phạm bảo mật liên tiếp."""
    target_key = DEMO_KEYS_CATALOG["intrusion_target"]["raw_key"]

    for i in range(1, 6):
        r = client.get(
            "/api/v1/records",
            headers={"X-API-Key": target_key, "X-Simulated-IP": "203.113.148.99"},
        )
        assert r.status_code == 403
        data = r.get_json()
        if i == 5:
            assert data["auto_frozen_triggered"] is True

    # Lần thứ 6: Quay lại dùng đúng IP hợp lệ 127.0.0.1 cũng bị từ chối vì Key đã bị AUTO_FROZEN!
    r6 = client.get(
        "/api/v1/records",
        headers={"X-API-Key": target_key, "X-Simulated-IP": "127.0.0.1"},
    )
    assert r6.status_code == 401
    assert r6.get_json()["error_code"] == "API_KEY_AUTO_FROZEN"


def test_scenario8_hmac_signature_anti_replay_and_anti_tampering(client):
    """Ngữ cảnh 8: Xác thực chữ ký số HMAC-SHA256, chống Replay Attack và chống sửa dữ liệu MITM."""
    raw_key = DEMO_KEYS_CATALOG["full_access"]["raw_key"]
    secret = DEMO_KEYS_CATALOG["full_access"]["signing_secret"]
    path = "/api/v1/transfer"

    # 8A. Hợp lệ
    now_ts = str(int(time.time()))
    valid_body = json.dumps({"customer_code": "CUST-2026-001", "amount": 1000000, "recipient": "VN-001"})
    valid_sig = compute_request_signature(secret, now_ts, "POST", path, valid_body)

    r_ok = client.post(
        path,
        data=valid_body,
        content_type="application/json",
        headers={"X-API-Key": raw_key, "X-Timestamp": now_ts, "X-Signature": valid_sig},
    )
    assert r_ok.status_code == 200
    assert r_ok.get_json()["status"] == "success"

    # 8B. Replay Attack (Timestamp cũ 15 phút trước)
    old_ts = str(int(time.time()) - 900)
    old_sig = compute_request_signature(secret, old_ts, "POST", path, valid_body)
    r_replay = client.post(
        path,
        data=valid_body,
        content_type="application/json",
        headers={"X-API-Key": raw_key, "X-Timestamp": old_ts, "X-Signature": old_sig},
    )
    assert r_replay.status_code == 401
    assert r_replay.get_json()["error_code"] == "TIMESTAMP_EXPIRED_REPLAY_DETECTED"

    # 8C. MITM Tampering (Sửa số tiền từ 1,000,000 thành 999,000,000 mà giữ nguyên chữ ký)
    tampered_body = json.dumps({"customer_code": "CUST-2026-001", "amount": 999000000, "recipient": "HACKER"})
    r_tamper = client.post(
        path,
        data=tampered_body,
        content_type="application/json",
        headers={"X-API-Key": raw_key, "X-Timestamp": now_ts, "X-Signature": valid_sig},
    )
    assert r_tamper.status_code == 401
    assert r_tamper.get_json()["error_code"] == "INVALID_HMAC_SIGNATURE_TAMPERED"
