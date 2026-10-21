import pytest
from app import create_app
from app.config import TestingConfig
from app.models import ApiKey
from app.services.seed_service import DEMO_KEYS_CATALOG, seed_initial_data


@pytest.fixture()
def app_v2():
    """Fixture không giữ app_context bao ngoài các request để tránh dùng lẫn flask.g giữa nhiều user."""
    app = create_app(TestingConfig)
    with app.app_context():
        seed_initial_data(force_reset=True)
    yield app


def test_v2_wrong_secret_does_not_freeze(app_v2):
    """V2-H1: Gửi 6 lần đúng prefix nhưng sai secret không được làm đóng băng key thật."""
    with app_v2.test_client() as c:
        for i in range(6):
            r_bad = c.get(
                "/api/v1/records",
                headers={"X-API-Key": f"ak_live_1001full_WRONGSECRET{i:021d}"},
            )
            assert r_bad.status_code == 401
            assert r_bad.get_json()["error_code"] == "INVALID_API_KEY"

        r_ok = c.get(
            "/api/v1/records",
            headers={"X-API-Key": DEMO_KEYS_CATALOG["full_access"]["raw_key"]},
        )
        assert r_ok.status_code == 200

    with app_v2.app_context():
        k_full = ApiKey.query.filter_by(key_prefix="ak_live_1001full").first()
        assert k_full.failed_attempts == 0
        assert k_full.status_label == "ACTIVE"


def test_v2_simulated_ip_ignored_from_remote_in_demo(app_v2):
    """V2-H2: Kể cả khi DEMO_MODE=True, request từ IP ngoài (không phải loopback) gửi X-Simulated-IP vẫn bị bỏ qua -> 403."""
    app_v2.config["DEMO_MODE"] = True
    ip_key = DEMO_KEYS_CATALOG["ip_restricted"]["raw_key"]
    with app_v2.test_client() as c:
        resp = c.get(
            "/api/v1/records",
            headers={"X-API-Key": ip_key, "X-Simulated-IP": "127.0.0.1"},
            environ_base={"REMOTE_ADDR": "185.220.101.45"},
        )
        assert resp.status_code == 403


def test_v2_simulated_ip_works_from_localhost_in_demo(app_v2):
    """V2-H2: Khi DEMO_MODE=True và gọi từ 127.0.0.1, X-Simulated-IP vẫn hoạt động để phục vụ Playground."""
    app_v2.config["DEMO_MODE"] = True
    ip_key = DEMO_KEYS_CATALOG["ip_restricted"]["raw_key"]
    with app_v2.test_client() as c:
        resp = c.get(
            "/api/v1/records",
            headers={"X-API-Key": ip_key, "X-Simulated-IP": "185.220.101.45"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert resp.status_code == 403


def test_v2_is_ip_allowed_rejects_cidr_string(app_v2):
    """V2-H2: Hàm _is_ip_allowed từ chối chuỗi CIDR truyền vào làm client_ip."""
    from app.middleware.api_auth import _is_ip_allowed

    with app_v2.app_context():
        assert _is_ip_allowed("10.10.0.0/16", ["10.10.0.0/16"]) is False


def test_v2_cannot_rotate_key_in_grace_period(app_v2):
    """V2-H3: Rotate lần 1 thành công (key cũ sang GRACE_PERIOD), gọi rotate lần 2 trên cùng key cũ phải ném ValueError."""
    from app.models import User
    from app.services.key_service import KeyService

    with app_v2.app_context():
        admin = User.query.filter_by(username="admin").first()
        old_key = ApiKey.query.filter_by(key_prefix="ak_live_1001full").first()
        KeyService.rotate_api_key(old_key, admin, grace_period_hours=24)
        assert old_key.status_label == "GRACE_PERIOD"

        with pytest.raises(ValueError):
            KeyService.rotate_api_key(old_key, admin, grace_period_hours=24)


def test_v2_grace_hours_bounds(app_v2):
    """V2-H3: grace_period_hours ngoài khoảng 1..168 phải ném ValueError (không phải OverflowError); 168 thì hợp lệ."""
    from app.models import User
    from app.services.key_service import KeyService

    with app_v2.app_context():
        admin = User.query.filter_by(username="admin").first()
        target_key = ApiKey.query.filter_by(key_prefix="ak_live_1001full").first()

        for bad_hours in (0, 169, 10**8):
            with pytest.raises(ValueError):
                KeyService.rotate_api_key(target_key, admin, grace_period_hours=bad_hours)

        new_key, _, _ = KeyService.rotate_api_key(target_key, admin, grace_period_hours=168)
        assert new_key.status_label == "ACTIVE"


def test_v2_rotate_route_huge_grace_not_500(app_v2):
    """V2-H3: Qua route POST rotate với grace_period_hours=100000000 phải trả 400 (không phải 500)."""
    with app_v2.app_context():
        k_id = ApiKey.query.filter_by(key_prefix="ak_live_1001full").first().id

    with app_v2.test_client() as c:
        c.post("/auth/login", data={"username": "admin", "password": "Admin@123456"})
        resp = c.post(f"/dashboard/keys/{k_id}/rotate", data={"grace_period_hours": "100000000"})
        assert resp.status_code == 400


def test_v2_dev_dashboard_no_foreign_audit(app_v2):
    """V2-M1: Developer xem /dashboard không thấy audit log của admin hay SYSTEM."""
    with app_v2.app_context():
        admin_key_id = ApiKey.query.filter_by(key_prefix="ak_live_1001full").first().id

    with app_v2.test_client() as c_admin:
        c_admin.post("/auth/login", data={"username": "admin", "password": "Admin@123456"})
        c_admin.post(
            f"/dashboard/keys/{admin_key_id}/revoke",
            data={"reason": "ADMIN_ONLY_AUDIT_EVENT_XYZ"},
        )

    with app_v2.test_client() as c_dev:
        c_dev.post("/auth/login", data={"username": "dev_hoang", "password": "Dev@123456"})
        resp = c_dev.get("/dashboard")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "ADMIN_ONLY_AUDIT_EVENT_XYZ" not in html
        assert "ak_live_1001full" not in html


def test_v2_db_inspector_404_when_not_demo(app_v2):
    """V2-M1: Khi DEMO_MODE=False, ngay cả Admin gọi GET /db-inspector cũng nhận 404."""
    app_v2.config["DEMO_MODE"] = False
    with app_v2.test_client() as c:
        c.post("/auth/login", data={"username": "admin", "password": "Admin@123456"})
        resp = c.get("/db-inspector")
        assert resp.status_code == 404


def test_v2_transfer_non_string_customer_code(app_v2):
    """V2-M2: POST /api/v1/transfer với customer_code là int (123) và chữ ký HMAC hợp lệ phải trả 400 MISSING_CUSTOMER_CODE (không 500)."""
    import json
    import time
    from app.services.crypto_service import compute_request_signature

    hmac_info = DEMO_KEYS_CATALOG["full_access"]
    ts_str = str(int(time.time()))
    body_str = json.dumps({"customer_code": 123, "amount": 1000})
    with app_v2.app_context():
        sig = compute_request_signature(
            hmac_info["signing_secret"], ts_str, "POST", "/api/v1/transfer", body_str
        )

    with app_v2.test_client() as c:
        resp = c.post(
            "/api/v1/transfer",
            data=body_str,
            content_type="application/json",
            headers={
                "X-API-Key": hmac_info["raw_key"],
                "X-Timestamp": ts_str,
                "X-Signature": sig,
            },
        )
        assert resp.status_code == 400
        assert resp.get_json()["error_code"] == "MISSING_CUSTOMER_CODE"


def test_v2_create_record_invalid_balance(app_v2):
    """V2-M2: POST /api/v1/records với balance không hợp lệ hoặc full_name không phải chuỗi không gây 500."""
    full_key = DEMO_KEYS_CATALOG["full_access"]["raw_key"]
    with app_v2.test_client() as c:
        for bad_bal in ("abc", -100, "NaN", "Infinity", True):
            resp = c.post(
                "/api/v1/records",
                json={"balance": bad_bal},
                headers={"X-API-Key": full_key},
            )
            assert resp.status_code == 400
            assert resp.get_json()["error_code"] == "INVALID_BALANCE"

        resp_ok = c.post(
            "/api/v1/records",
            json={"full_name": 12345, "balance": 100000},
            headers={"X-API-Key": full_key},
        )
        assert resp_ok.status_code == 201


def test_v2_rate_limit_upper_bound(app_v2):
    """V2-M3: rate_limit_per_minute ngoài 1..1000 phải trả 400 qua route (không tạo key mới) và 1000 trả 200."""
    from app.models import User
    from app.services.key_service import KeyService

    with app_v2.app_context():
        dev = User.query.filter_by(username="dev_hoang").first()
        for bad_rl in (0, -5, 1001, 10**9):
            with pytest.raises(ValueError):
                KeyService.create_api_key(
                    user=dev,
                    name="Bad RL Key",
                    scopes="read:records",
                    rate_limit_per_minute=bad_rl,
                    expires_in_days=30,
                )
        before_count = ApiKey.query.count()

    with app_v2.test_client() as c:
        c.post("/auth/login", data={"username": "admin", "password": "Admin@123456"})
        r_high = c.post(
            "/dashboard/keys/create",
            data={
                "name": "Too High RL",
                "scopes": ["read:records"],
                "rate_limit_per_minute": "100000000",
                "expires_in_days": "30",
            },
        )
        assert r_high.status_code == 400

        with app_v2.app_context():
            assert ApiKey.query.count() == before_count

        r_ok = c.post(
            "/dashboard/keys/create",
            data={
                "name": "Max Allowed RL",
                "scopes": ["read:records"],
                "rate_limit_per_minute": "1000",
                "expires_in_days": "30",
            },
        )
        assert r_ok.status_code == 200
        with app_v2.app_context():
            assert ApiKey.query.count() == before_count + 1


def test_v2_dev_nav_hidden(app_v2):
    """V2-M4: Developer đăng nhập không thấy link /logs, /db-inspector, reset-demo, hay scope transfer:funds; Admin thì có đủ."""
    app_v2.config["DEMO_MODE"] = True
    with app_v2.test_client() as c_dev:
        c_dev.post("/auth/login", data={"username": "dev_hoang", "password": "Dev@123456"})
        r_dev = c_dev.get("/dashboard")
        assert r_dev.status_code == 200
        html_dev = r_dev.get_data(as_text=True)
        assert 'href="/logs"' not in html_dev
        assert "/db-inspector" not in html_dev
        assert "reset-demo" not in html_dev
        assert 'value="transfer:funds"' not in html_dev
        assert 'value="admin:records"' not in html_dev

    with app_v2.test_client() as c_admin:
        c_admin.post("/auth/login", data={"username": "admin", "password": "Admin@123456"})
        r_adm = c_admin.get("/dashboard")
        assert r_adm.status_code == 200
        html_adm = r_adm.get_data(as_text=True)
        assert 'href="/logs"' in html_adm
        assert "/db-inspector" in html_adm
        assert "reset-demo" in html_adm
        assert 'value="transfer:funds"' in html_adm


def test_v2_playground_link_hidden_when_not_demo(app_v2):
    """V2-M4: Khi DEMO_MODE=False, trang /dashboard vẫn trả 200 nhưng không chứa href="/playground"."""
    app_v2.config["DEMO_MODE"] = False
    with app_v2.test_client() as c:
        c.post("/auth/login", data={"username": "admin", "password": "Admin@123456"})
        resp = c.get("/dashboard")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert 'href="/playground"' not in html
        assert "/db-inspector" not in html
        assert "reset-demo" not in html


def test_v2_malformed_key_not_logged(app_v2):
    """V2-L1: Gửi X-API-Key sai định dạng không lưu 16 ký tự đầu vào key_prefix_attempted mà lưu 'MALFORMED'."""
    from app.models import ApiUsageLog

    with app_v2.test_client() as c:
        resp = c.get("/api/v1/records", headers={"X-API-Key": "SECRETPART1234567890"})
        assert resp.status_code == 401
        assert resp.get_json()["error_code"] == "MALFORMED_API_KEY"

    with app_v2.app_context():
        latest_log = ApiUsageLog.query.order_by(ApiUsageLog.id.desc()).first()
        assert latest_log.key_prefix_attempted == "MALFORMED"
        assert "SECRETPART" not in (latest_log.key_prefix_attempted or "")


def test_v2_compute_hmac_requires_login(app_v2):
    """V2-L3: Chưa đăng nhập gọi POST /api/v1/demo/compute-hmac phải trả 302 hoặc 401 (không trả 200)."""
    app_v2.config["DEMO_MODE"] = True
    with app_v2.test_client() as c:
        resp = c.post(
            "/api/v1/demo/compute-hmac",
            json={"signing_secret": "whsec_test", "mode": "valid"},
        )
        assert resp.status_code in (302, 401)


def test_v2_compute_hmac_invalid_mode(app_v2):
    """V2-L3: Đã đăng nhập nhưng gửi mode không hợp lệ ('zzz') phải trả 400 INVALID_MODE."""
    app_v2.config["DEMO_MODE"] = True
    with app_v2.test_client() as c:
        c.post("/auth/login", data={"username": "admin", "password": "Admin@123456"})
        resp = c.post(
            "/api/v1/demo/compute-hmac",
            json={"signing_secret": "whsec_test", "mode": "zzz"},
        )
        assert resp.status_code == 400
        assert resp.get_json()["error_code"] == "INVALID_MODE"


def test_v2_quick_login_unknown_user_404(app_v2):
    """V2-L6: Khi DEMO_MODE=True, gọi quick-login cho tài khoản ngoài danh sách ('khongton') phải trả 404."""
    app_v2.config["DEMO_MODE"] = True
    with app_v2.test_client() as c:
        resp = c.post(
            "/auth/quick-login/khongton",
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert resp.status_code == 404


def test_v2_login_form_no_prefill_when_not_demo(app_v2):
    """V2-L6: Khi DEMO_MODE=False, GET /auth/login không điền sẵn mật khẩu mẫu trong HTML."""
    app_v2.config["DEMO_MODE"] = False
    with app_v2.test_client() as c:
        resp = c.get("/auth/login")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "Admin@123456" not in html









