"""
Vòng 4 – Chuẩn hóa theo NIST:
  - SP 800-132 (12/2010): băm mật khẩu PBKDF2-HMAC-SHA256, salt 128 bit.
  - SP 800-63B-4 (08/2025): mật khẩu tối thiểu 15 ký tự, blocklist, không áp quy tắc thành phần.
  - SP 800-56C Rev.2 (08/2020): dẫn xuất khóa Fernet bằng HKDF thay cho SHA-256 trần.
"""
import base64
import hashlib

import pytest
from argon2 import PasswordHasher
from cryptography.fernet import Fernet

from app import create_app
from app.config import TestingConfig
from app.extensions import db
from app.models import User
from app.services.crypto_service import (
    decrypt_sensitive_value,
    hash_password,
    password_needs_rehash,
    verify_password,
)
from app.services.password_policy import validate_password
from app.services.seed_service import seed_initial_data


@pytest.fixture
def app_v4():
    app = create_app(TestingConfig)
    with app.app_context():
        seed_initial_data(force_reset=True)
        yield app


def test_v4_pbkdf2_format_and_verify(app_v4):
    h = hash_password("mot cum tu rat dai de nho 2026")
    parts = h.split("$")
    assert parts[1] == "pbkdf2-sha256"
    assert int(parts[2]) == app_v4.config["PASSWORD_PBKDF2_ITERATIONS"]
    assert len(base64.b64decode(parts[3] + "==")) == 16  # salt 128 bit
    assert verify_password(h, "mot cum tu rat dai de nho 2026") is True
    assert verify_password(h, "mot cum tu rat dai de nho 2027") is False
    # Salt ngẫu nhiên: cùng mật khẩu cho ra 2 hash khác nhau
    assert hash_password("mot cum tu rat dai de nho 2026") != h


def test_v4_legacy_argon2_login_and_rehash(app_v4):
    user = User.query.filter_by(username="dev_hoang").first()
    user.password_hash = PasswordHasher().hash("Dev@123456")
    db.session.commit()
    assert password_needs_rehash(user.password_hash) is True

    with app_v4.test_client() as c:
        resp = c.post("/auth/login", data={"username": "dev_hoang", "password": "Dev@123456"})
        assert resp.status_code == 302

    db.session.refresh(user)
    assert user.password_hash.startswith("$pbkdf2-sha256$")
    assert user.check_password("Dev@123456") is True


@pytest.mark.parametrize("pwd", [
    "ngan qua",                    # < 15 ký tự
    "passwordpassword",            # nằm trong blocklist
    "aaaaaaaaaaaaaaaaaaaa",        # lặp 1 ký tự
    "123456789012345678",          # dãy số liên tiếp
    "newdev_userhutech1",          # chủ yếu là username + tên hệ thống
])
def test_v4_password_policy_rejects(pwd):
    assert validate_password(pwd, username="newdev_user", email="newdev_user@hutech.edu.vn")


def test_v4_short_password_only_reports_length():
    # Mật khẩu ngắn không chứa từ ngữ cảnh chỉ báo lỗi độ dài, không báo nhầm lỗi ngữ cảnh
    assert validate_password("abc123", username="sinhvien_demo", email="sv@demo.vn") == [
        "Mật khẩu phải dài tối thiểu 15 ký tự (NIST SP 800-63B-4)."
    ]


def test_v4_password_policy_accepts_passphrase_without_composition_rules():
    # Không có chữ hoa, số hay ký tự đặc biệt vẫn hợp lệ (SP 800-63B-4: SHALL NOT composition rules)
    assert validate_password("con meo nho ngoi tren mai nha", username="newdev_user") == []
    # Unicode tiếng Việt có dấu được chấp nhận
    assert validate_password("Mùa thu Hà Nội lá vàng rơi", username="newdev_user") == []


def test_v4_register_enforces_15_chars(app_v4):
    app_v4.config["WTF_CSRF_ENABLED"] = False
    with app_v4.test_client() as c:
        c.post("/auth/register", data={"username": "short_pw", "email": "s@x.vn", "password": "Abc@12345678"})
        assert User.query.filter_by(username="short_pw").first() is None

        c.post("/auth/register", data={"username": "long_pw", "email": "l@x.vn",
                                       "password": "mot cau rat dai cho de nho"})
        created = User.query.filter_by(username="long_pw").first()
        assert created is not None
        assert created.password_hash.startswith("$pbkdf2-sha256$")


def test_v4_fernet_hkdf_and_legacy_decrypt(app_v4):
    master = app_v4.config["MASTER_ENCRYPTION_KEY"].encode("utf-8")
    legacy = Fernet(base64.urlsafe_b64encode(hashlib.sha256(master).digest()))
    old_ciphertext = legacy.encrypt(b"du lieu ma hoa bang khoa cu").decode()
    # Dữ liệu cũ vẫn giải mã được qua MultiFernet
    assert decrypt_sensitive_value(old_ciphertext) == "du lieu ma hoa bang khoa cu"

    from app.services.crypto_service import encrypt_sensitive_value
    new_ciphertext = encrypt_sensitive_value("du lieu moi")
    # Dữ liệu mới KHÔNG được mã hóa bằng khóa SHA-256 trần nữa (đã dùng khóa HKDF)
    with pytest.raises(Exception):
        legacy.decrypt(new_ciphertext.encode())
    assert decrypt_sensitive_value(new_ciphertext) == "du lieu moi"
