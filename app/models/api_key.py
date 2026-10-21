from datetime import datetime, timezone
from app.extensions import db
from app.services.crypto_service import decrypt_sensitive_value


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ApiKey(db.Model):
    """
    Bảng lưu trữ thông tin kiểm soát API Key an toàn.
    TUYỆT ĐỐI KHÔNG lưu trữ plaintext API Key trong CSDL!
    Chỉ lưu:
      - key_prefix (ví dụ: ak_live_9f8a1b2c) để định danh & tra cứu nhanh O(1)
      - key_hash: Băm một chiều bằng HMAC-SHA256(raw_key, API_KEY_PEPPER)
      - signing_secret_enc: Khóa ký gói tin HMAC được mã hóa đối xứng bằng Fernet (AES-128-CBC + HMAC)
    """

    __tablename__ = "api_keys"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    environment = db.Column(db.String(16), nullable=False, default="live")  # live | test

    key_prefix = db.Column(db.String(32), unique=True, nullable=False, index=True)
    key_hash = db.Column(db.String(128), nullable=False)
    signing_secret_enc = db.Column(db.String(512), nullable=True)

    # Kiểm soát phân quyền Đặc quyền tối thiểu (Least Privilege Scopes)
    scopes = db.Column(db.String(256), nullable=False, default="read:records")

    # Kiểm soát lưu lượng (Rate Limiting theo từng Key)
    rate_limit_per_minute = db.Column(db.Integer, nullable=False, default=60)

    # Kiểm soát địa chỉ mạng (IP Whitelisting / CIDR)
    allowed_ips = db.Column(db.String(256), nullable=True, default="")

    # Quản lý vòng đời (TTL Expiration, Revocation, Zero-Downtime Rotation)
    expires_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    revoked_reason = db.Column(db.String(256), nullable=True)

    rotated_from_id = db.Column(db.Integer, db.ForeignKey("api_keys.id"), nullable=True)
    grace_period_until = db.Column(db.DateTime, nullable=True)

    # Theo dõi hành vi bất thường & tự động khóa (Auto-Freeze Intrusion Detection)
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    usage_count = db.Column(db.Integer, default=0, nullable=False)
    last_used_at = db.Column(db.DateTime, nullable=True)
    last_used_ip = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)

    usage_logs = db.relationship("ApiUsageLog", backref="api_key", lazy="dynamic")

    @property
    def masked_key(self) -> str:
        """Hiển thị Key dạng che an toàn trên giao diện."""
        return f"{self.key_prefix}_••••••••••••••••••••••••"

    def get_scopes_list(self) -> list[str]:
        if not self.scopes:
            return []
        return [s.strip() for s in self.scopes.split(",") if s.strip()]

    def get_allowed_ips_list(self) -> list[str]:
        if not self.allowed_ips or self.allowed_ips.strip() == "*":
            return []
        return [ip.strip() for ip in self.allowed_ips.split(",") if ip.strip()]

    def get_signing_secret(self) -> str:
        if not self.signing_secret_enc:
            return ""
        return decrypt_sensitive_value(self.signing_secret_enc)

    @property
    def is_expired(self) -> bool:
        if self.expires_at and utc_now() > self.expires_at:
            return True
        if self.grace_period_until and utc_now() > self.grace_period_until:
            return True
        return False

    @property
    def is_in_grace_period(self) -> bool:
        return bool(
            self.is_active
            and self.grace_period_until
            and utc_now() <= self.grace_period_until
        )

    @property
    def status_label(self) -> str:
        if not self.is_active:
            if self.revoked_reason and "AUTO_FROZEN" in self.revoked_reason:
                return "AUTO_FROZEN"
            return "REVOKED"
        if self.is_expired:
            return "EXPIRED"
        if self.is_in_grace_period:
            return "GRACE_PERIOD"
        return "ACTIVE"
