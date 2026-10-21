import pytest
from app import create_app
from app.config import TestingConfig
from app.services.seed_service import seed_initial_data


@pytest.fixture()
def app_v3():
    """Fixture không giữ app_context bao ngoài các request (tránh dùng lẫn flask.g giữa nhiều client)."""
    app = create_app(TestingConfig)
    with app.app_context():
        seed_initial_data(force_reset=True)
    yield app


def test_v3_api_global_limit_returns_json(app_v3):
    """P1: Vượt giới hạn 120 request/phút/IP trên /api/v1 phải trả 429 dạng JSON (không phải trang HTML)."""
    bad_key = "ak_live_1001full_" + "A" * 32
    with app_v3.test_client() as c:
        last = None
        for _ in range(121):
            last = c.get("/api/v1/records", headers={"X-API-Key": bad_key})
        assert last.status_code == 429
        assert last.is_json
        assert last.get_json()["error_code"] == "TOO_MANY_REQUESTS"


def test_v3_web_rate_limit_still_html(app_v3):
    """P1: Trang web (không phải /api/) vượt giới hạn vẫn trả trang 429 mặc định, không đổi sang JSON."""
    with app_v3.test_client() as c:
        last = None
        for _ in range(21):
            last = c.post("/auth/login", data={"username": "x", "password": "y"})
        assert last.status_code == 429
        assert not last.is_json


def test_v3_compute_hmac_unauth_json_401(app_v3):
    """P2: Gọi /api/v1/demo/compute-hmac khi chưa đăng nhập trả 401 JSON LOGIN_REQUIRED."""
    with app_v3.test_client() as c:
        resp = c.post("/api/v1/demo/compute-hmac", json={"signing_secret": "whsec_test", "mode": "valid"})
        assert resp.status_code == 401
        assert resp.get_json()["error_code"] == "LOGIN_REQUIRED"


def test_v3_dashboard_unauth_still_redirects(app_v3):
    """P2: Trang web chưa đăng nhập vẫn chuyển hướng về /auth/login như cũ."""
    with app_v3.test_client() as c:
        resp = c.get("/dashboard")
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]


def test_v3_tao_env_generates_all_secrets():
    """Gom bí mật: scripts/tao_env.py sinh đủ khóa server, mật khẩu demo và 8 cặp Key/Signing Secret hợp lệ."""
    import importlib.util
    from cryptography.fernet import Fernet
    from app.services.seed_service import DEMO_KEYS_CATALOG

    spec = importlib.util.spec_from_file_location("tao_env", "scripts/tao_env.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    text = mod.build_env_text()
    env = dict(line.split("=", 1) for line in text.splitlines() if line and not line.startswith("#"))

    for name in ("SECRET_KEY", "API_KEY_PEPPER", "MASTER_ENCRYPTION_KEY"):
        assert len(env[name]) >= 32
    Fernet(env["MASTER_ENCRYPTION_KEY"].encode())
    assert env["DEMO_ADMIN_PASSWORD"] and env["DEMO_DEV_PASSWORD"]
    for key_id in DEMO_KEYS_CATALOG:
        raw = env[f"DEMO_KEY_{key_id.upper()}"]
        assert raw.startswith(DEMO_KEYS_CATALOG[key_id]["raw_key"][:17])  # cùng prefix ak_<env>_<id>_
        assert env[f"DEMO_SIGNING_SECRET_{key_id.upper()}"].startswith("whsec_")
    # Hai lần sinh phải ra khóa khác nhau (ngẫu nhiên)
    assert mod.build_env_text() != text


def test_v3_no_demo_secret_in_source():
    """Gom bí mật: mã nguồn app/ không còn chứa raw key / signing secret / mật khẩu demo viết cứng."""
    import pathlib

    leaked_markers = ["xK9mP2vQ8nL5", "SigningSecretKey2026Hutech", "Admin@123456", "Dev@123456"]
    for path in pathlib.Path("app").rglob("*"):
        if path.suffix not in (".py", ".html", ".js", ".css"):
            continue
        if path.as_posix() == "app/config.py":
            continue  # TestingConfig chứa mật khẩu CHỈ DÙNG CHO TEST (không phải bí mật thật)
        text = path.read_text(encoding="utf-8")
        for marker in leaked_markers:
            assert marker not in text, f"{marker} còn nằm trong {path}"
