import pytest
from app import create_app
from app.config import TestingConfig
from app.services.seed_service import seed_initial_data


@pytest.fixture()
def app_instance():
    app = create_app(TestingConfig)
    with app.app_context():
        seed_initial_data(force_reset=True)
        yield app


def test_quick_login_disabled_when_not_demo(app_instance):
    """C1: Khi DEMO_MODE=False, route quick-login phải trả về 404."""
    app_instance.config["DEMO_MODE"] = False
    with app_instance.test_client() as c:
        resp = c.post("/auth/quick-login/admin", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        assert resp.status_code == 404


def test_quick_login_works_in_demo_localhost(app_instance):
    """C1: Khi DEMO_MODE=True và gọi từ 127.0.0.1 thì hoạt động, gọi từ IP ngoài trả 404."""
    app_instance.config["DEMO_MODE"] = True
    with app_instance.test_client() as c:
        resp_remote = c.post("/auth/quick-login/admin", environ_base={"REMOTE_ADDR": "203.113.148.10"})
        assert resp_remote.status_code == 404

        resp_local = c.post("/auth/quick-login/admin", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        assert resp_local.status_code in (200, 302)


def test_developer_cannot_revoke_admin_key(app_instance):
    """C2: Developer không được phép revoke/rotate/unlock key của Admin (403)."""
    from app.models import ApiKey, User

    admin = User.query.filter_by(username="admin").first()
    admin_key = ApiKey.query.filter_by(user_id=admin.id).first()

    with app_instance.test_client() as c:
        c.post("/auth/login", data={"username": "dev_hoang", "password": "Dev@123456"})
        resp = c.post(f"/dashboard/keys/{admin_key.id}/revoke")
        assert resp.status_code == 403


def test_developer_cannot_open_db_inspector(app_instance):
    """C2: Developer không được xem db-inspector, logs toàn hệ thống hoặc reset-demo (403)."""
    with app_instance.test_client() as c:
        c.post("/auth/login", data={"username": "dev_hoang", "password": "Dev@123456"})
        assert c.get("/db-inspector").status_code == 403
        assert c.get("/logs").status_code == 403
        assert c.post("/dashboard/reset-demo").status_code == 403


def test_developer_sees_only_own_keys(app_instance):
    """C2: Trên Dashboard, Developer chỉ nhìn thấy các key của chính mình."""
    from app.models import ApiKey, User

    admin = User.query.filter_by(username="admin").first()
    admin_key = ApiKey.query.filter_by(user_id=admin.id).first()

    with app_instance.test_client() as c:
        c.post("/auth/login", data={"username": "dev_hoang", "password": "Dev@123456"})
        resp = c.get("/dashboard")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert admin_key.key_prefix not in html


def test_admin_can_open_db_inspector(app_instance):
    """C2: Admin vẫn mở được db-inspector (200)."""
    with app_instance.test_client() as c:
        c.post("/auth/login", data={"username": "admin", "password": "Admin@123456"})
        assert c.get("/db-inspector").status_code == 200


def test_simulated_ip_ignored_when_not_demo(app_instance):
    """C3: Khi DEMO_MODE=False, header X-Simulated-IP bị bỏ qua."""
    from app.services.seed_service import DEMO_KEYS_CATALOG

    ip_key = DEMO_KEYS_CATALOG["ip_restricted"]["raw_key"]
    app_instance.config["DEMO_MODE"] = False
    with app_instance.test_client() as c:
        # Gọi từ REMOTE_ADDR=203.113.148.99 nhưng giả mạo X-Simulated-IP=127.0.0.1 -> Vẫn bị chặn 403
        resp = c.get(
            "/api/v1/records",
            headers={"X-API-Key": ip_key, "X-Simulated-IP": "127.0.0.1"},
            environ_base={"REMOTE_ADDR": "203.113.148.99"},
        )
        assert resp.status_code == 403


def test_x_forwarded_for_ignored(app_instance):
    """C3: Header X-Forwarded-For do client tự gửi không được dùng để vượt qua IP Whitelist."""
    from app.services.seed_service import DEMO_KEYS_CATALOG

    ip_key = DEMO_KEYS_CATALOG["ip_restricted"]["raw_key"]
    app_instance.config["DEMO_MODE"] = False
    with app_instance.test_client() as c:
        resp = c.get(
            "/api/v1/records",
            headers={"X-API-Key": ip_key, "X-Forwarded-For": "127.0.0.1"},
            environ_base={"REMOTE_ADDR": "198.51.100.25"},
        )
        assert resp.status_code == 403


def test_cidr_string_as_ip_rejected(app_instance):
    """C3: Gửi chuỗi '10.10.0.0/16' làm IP client (không phải địa chỉ IP hợp lệ) phải bị từ chối 403."""
    from app.services.seed_service import DEMO_KEYS_CATALOG

    ip_key = DEMO_KEYS_CATALOG["intrusion_target"]["raw_key"]
    app_instance.config["DEMO_MODE"] = True
    with app_instance.test_client() as c:
        resp = c.get(
            "/api/v1/records",
            headers={"X-API-Key": ip_key, "X-Simulated-IP": "10.10.0.0/16"},
            environ_base={"REMOTE_ADDR": "127.0.0.2"},
        )
        assert resp.status_code == 403


def test_403_does_not_leak_allowed_ips(app_instance):
    """C3: Phản hồi 403 IP_NOT_WHITELISTED không được làm lộ danh sách allowed_ips."""
    from app.services.seed_service import DEMO_KEYS_CATALOG

    ip_key = DEMO_KEYS_CATALOG["ip_restricted"]["raw_key"]
    app_instance.config["DEMO_MODE"] = True
    with app_instance.test_client() as c:
        resp = c.get(
            "/api/v1/records",
            headers={"X-API-Key": ip_key, "X-Simulated-IP": "185.220.101.45"},
        )
        assert resp.status_code == 403
        body = resp.get_json()
        assert "allowed_ips" not in body
        assert "10.10.0.0/16" not in body.get("message", "")


def test_no_seed_when_not_demo():
    """C4: Khi DEMO_MODE=False, app không tự động seed user/key demo."""
    from app.models import User

    class NonDemoTestConfig(TestingConfig):
        DEMO_MODE = False

    app = create_app(NonDemoTestConfig)
    with app.app_context():
        seed_initial_data(force_reset=True)
        assert User.query.count() == 0


def test_playground_404_when_not_demo(app_instance):
    """C4: Khi DEMO_MODE=False, route /playground phải trả về 404."""
    app_instance.config["DEMO_MODE"] = False
    with app_instance.test_client() as c:
        c.post("/auth/login", data={"username": "admin", "password": "Admin@123456"})
        resp = c.get("/playground")
        assert resp.status_code == 404


def test_app_refuses_empty_pepper():
    """C5: App từ chối khởi chạy khi thiếu hoặc rỗng API_KEY_PEPPER."""
    class BadPepperConfig(TestingConfig):
        TESTING = False
        DEMO_MODE = False
        API_KEY_PEPPER = ""

    with pytest.raises(RuntimeError, match="API_KEY_PEPPER"):
        create_app(BadPepperConfig)


def test_app_refuses_example_master_key():
    """C5: App từ chối khởi chạy khi dùng MASTER_ENCRYPTION_KEY mẫu từ .env.example."""
    class ExampleMasterKeyConfig(TestingConfig):
        TESTING = False
        DEMO_MODE = False
        MASTER_ENCRYPTION_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

    with pytest.raises(RuntimeError, match="MASTER_ENCRYPTION_KEY"):
        create_app(ExampleMasterKeyConfig)


def test_replay_same_signature_rejected(app_instance):
    """H1: Gửi lại cùng một request đã ký HMAC hợp lệ lần thứ 2 phải bị từ chối 401 REPLAY_DETECTED."""
    import json
    import time
    from app.services.crypto_service import compute_request_signature
    from app.services.seed_service import DEMO_KEYS_CATALOG

    raw_key = DEMO_KEYS_CATALOG["full_access"]["raw_key"]
    secret = DEMO_KEYS_CATALOG["full_access"]["signing_secret"]
    path = "/api/v1/transfer"
    now_ts = str(int(time.time()))
    body = json.dumps({"customer_code": "CUST-2026-001", "amount": 500000, "recipient": "VN-002"})
    sig = compute_request_signature(secret, now_ts, "POST", path, body)
    headers = {"X-API-Key": raw_key, "X-Timestamp": now_ts, "X-Signature": sig}

    with app_instance.test_client() as c:
        r1 = c.post(path, data=body, content_type="application/json", headers=headers)
        assert r1.status_code == 200

        r2 = c.post(path, data=body, content_type="application/json", headers=headers)
        assert r2.status_code == 401
        assert r2.get_json()["error_code"] == "REPLAY_DETECTED"


def test_compute_hmac_requires_secret(app_instance):
    """H2: /api/v1/demo/compute-hmac phải trả 400 nếu không gửi signing_secret."""
    app_instance.config["DEMO_MODE"] = True
    with app_instance.test_client() as c:
        c.post("/auth/login", data={"username": "admin", "password": "Admin@123456"})
        resp = c.post("/api/v1/demo/compute-hmac", json={"mode": "valid"})
        assert resp.status_code == 400


def test_compute_hmac_404_when_not_demo(app_instance):
    """H2: /api/v1/demo/compute-hmac phải trả 404 khi DEMO_MODE=False."""
    app_instance.config["DEMO_MODE"] = False
    with app_instance.test_client() as c:
        c.post("/auth/login", data={"username": "admin", "password": "Admin@123456"})
        resp = c.post(
            "/api/v1/demo/compute-hmac",
            json={"signing_secret": "whsec_test", "mode": "valid"},
        )
        assert resp.status_code == 404


def test_transfer_negative_amount_rejected(app_instance):
    """H3: Giao dịch chuyển tiền với số tiền âm, 0, NaN/Infinity hoặc vượt quá số dư phải bị từ chối 400."""
    import json
    import time
    from app.services.crypto_service import compute_request_signature
    from app.services.seed_service import DEMO_KEYS_CATALOG

    raw_key = DEMO_KEYS_CATALOG["full_access"]["raw_key"]
    secret = DEMO_KEYS_CATALOG["full_access"]["signing_secret"]
    path = "/api/v1/transfer"

    with app_instance.test_client() as c:
        for idx, bad_amount in enumerate([-5000, 0, "NaN", "Infinity", 999999999999]):
            ts = str(int(time.time()) + idx)
            body = json.dumps({"customer_code": "CUST-2026-001", "amount": bad_amount, "recipient": "VN-01"})
            sig = compute_request_signature(secret, ts, "POST", path, body)
            resp = c.post(
                path,
                data=body,
                content_type="application/json",
                headers={"X-API-Key": raw_key, "X-Timestamp": ts, "X-Signature": sig},
            )
            assert resp.status_code == 400


def test_transfer_unknown_customer_404(app_instance):
    """H3: Giao dịch chuyển tiền với customer_code không tồn tại phải trả về 404."""
    import json
    import time
    from app.services.crypto_service import compute_request_signature
    from app.services.seed_service import DEMO_KEYS_CATALOG

    raw_key = DEMO_KEYS_CATALOG["full_access"]["raw_key"]
    secret = DEMO_KEYS_CATALOG["full_access"]["signing_secret"]
    path = "/api/v1/transfer"
    ts = str(int(time.time()) + 50)
    body = json.dumps({"customer_code": "CUST-NOT-FOUND-999", "amount": 1000, "recipient": "VN-01"})
    sig = compute_request_signature(secret, ts, "POST", path, body)

    with app_instance.test_client() as c:
        resp = c.post(
            path,
            data=body,
            content_type="application/json",
            headers={"X-API-Key": raw_key, "X-Timestamp": ts, "X-Signature": sig},
        )
        assert resp.status_code == 404


def test_unknown_scope_rejected(app_instance):
    """H4: Tự gửi scope lạ hoặc developer tự cấp quyền admin:records / transfer:funds phải bị từ chối 400."""
    with app_instance.test_client() as c:
        c.post("/auth/login", data={"username": "dev_hoang", "password": "Dev@123456"})
        resp_unknown = c.post(
            "/dashboard/keys/create",
            data={
                "name": "Bad Scope Key",
                "environment": "live",
                "scopes": ["super:root"],
                "rate_limit_per_minute": "60",
                "expires_in_days": "30",
            },
        )
        assert resp_unknown.status_code == 400

        resp_priv = c.post(
            "/dashboard/keys/create",
            data={
                "name": "Escalated Key",
                "environment": "live",
                "scopes": ["admin:records"],
                "rate_limit_per_minute": "60",
                "expires_in_days": "30",
            },
        )
        assert resp_priv.status_code == 400


def test_zero_ttl_rejected(app_instance):
    """H4: Tạo key với expires_in_days <= 0, > 365 hoặc không phải số phải bị từ chối 400."""
    with app_instance.test_client() as c:
        c.post("/auth/login", data={"username": "admin", "password": "Admin@123456"})
        for bad_ttl in ("0", "-10", "999", "abc"):
            resp = c.post(
                "/dashboard/keys/create",
                data={
                    "name": "Bad TTL Key",
                    "environment": "live",
                    "scopes": ["read:records"],
                    "rate_limit_per_minute": "60",
                    "expires_in_days": bad_ttl,
                },
            )
            assert resp.status_code == 400


def test_cannot_unlock_revoked_key(app_instance):
    """H5: Key đã bị REVOKED là trạng thái cuối, không được phép unlock (400 / ValueError)."""
    from app.models import ApiKey

    revoked_key = ApiKey.query.filter_by(key_prefix="ak_live_5005revk").first()
    assert revoked_key is not None
    assert revoked_key.status_label == "REVOKED"

    with app_instance.test_client() as c:
        c.post("/auth/login", data={"username": "admin", "password": "Admin@123456"})
        resp = c.post(f"/dashboard/keys/{revoked_key.id}/unlock")
        assert resp.status_code == 400


def test_cannot_rotate_revoked_key(app_instance):
    """H5: Key đã bị REVOKED không được phép rotate (400 / ValueError)."""
    from app.models import ApiKey

    revoked_key = ApiKey.query.filter_by(key_prefix="ak_live_5005revk").first()
    assert revoked_key is not None

    with app_instance.test_client() as c:
        c.post("/auth/login", data={"username": "admin", "password": "Admin@123456"})
        resp = c.post(f"/dashboard/keys/{revoked_key.id}/rotate", data={"grace_period_hours": "24"})
        assert resp.status_code == 400


def test_m1_m3_m4_m5_hardening(app_instance):
    """M1–M5: Không lưu raw_key trong session, đếm sai secret theo prefix, ẩn granted_scopes/revoked_reason, gắn CSP/HSTS."""
    from app.models import ApiKey
    from app.services.seed_service import DEMO_KEYS_CATALOG

    with app_instance.test_client() as c:
        # M1: Tạo key mới trả thẳng HTML chứa key 1 lần, không lưu trong session
        c.post("/auth/login", data={"username": "admin", "password": "Admin@123456"})
        resp_create = c.post(
            "/dashboard/keys/create",
            data={
                "name": "Direct Render Key",
                "environment": "live",
                "scopes": ["read:records"],
                "rate_limit_per_minute": "60",
                "expires_in_days": "30",
            },
        )
        assert resp_create.status_code == 200
        assert "SHOW-ONCE SECRET PATTERN" in resp_create.get_data(as_text=True)
        with c.session_transaction() as sess:
            assert "show_once_key_data" not in sess

        # M3 (V2-H1): Sai secret KHÔNG được tăng failed_attempts (tránh DoS bằng prefix)
        k_read = ApiKey.query.filter_by(key_prefix="ak_live_2002read").first()
        before_fails = k_read.failed_attempts
        r_bad_secret = c.get(
            "/api/v1/records",
            headers={"X-API-Key": "ak_live_2002read_WRONGSECRET12345678901234567890"},
        )
        assert r_bad_secret.status_code == 401
        assert k_read.failed_attempts == before_fails

        # M4: Không trả granted_scopes khi thiếu scope, không trả revoked_reason khi key bị revoke
        r_scope = c.post(
            "/api/v1/records",
            headers={"X-API-Key": DEMO_KEYS_CATALOG["read_only"]["raw_key"]},
            json={"full_name": "Test"},
        )
        assert r_scope.status_code == 403
        assert "granted_scopes" not in r_scope.get_json()

        r_rev = c.get(
            "/api/v1/records",
            headers={"X-API-Key": DEMO_KEYS_CATALOG["revoked_key"]["raw_key"]},
        )
        assert r_rev.status_code == 401
        assert "GitHub" not in r_rev.get_json().get("message", "")

        # M5: Kiểm tra CSP và HSTS khi có HTTPS
        assert "Content-Security-Policy" in r_rev.headers
        r_https = c.get("/", base_url="https://localhost")
        assert "Strict-Transport-Security" in r_https.headers










