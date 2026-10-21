from datetime import datetime, timezone
from flask_login import UserMixin
from app.extensions import db, login_manager
from app.services.crypto_service import hash_password, verify_password


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    """Bảng người dùng (Admin / Developer) với mật khẩu băm bằng Argon2id."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="developer")  # admin | developer
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)

    api_keys = db.relationship("ApiKey", backref="owner", lazy="dynamic")
    audit_logs = db.relationship("SecurityAuditLog", backref="user", lazy="dynamic")

    def set_password(self, raw_password: str) -> None:
        self.password_hash = hash_password(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return verify_password(self.password_hash, raw_password)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


@login_manager.user_loader
def load_user(user_id: str):
    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None
