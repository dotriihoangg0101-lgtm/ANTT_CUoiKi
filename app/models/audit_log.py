from datetime import datetime, timezone
from app.extensions import db


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ApiUsageLog(db.Model):
    """Bảng ghi nhận chi tiết từng request gọi API qua Middleware bảo vệ."""

    __tablename__ = "api_usage_logs"

    id = db.Column(db.Integer, primary_key=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey("api_keys.id"), nullable=True, index=True)
    key_prefix_attempted = db.Column(db.String(64), nullable=True)
    endpoint = db.Column(db.String(128), nullable=False)
    method = db.Column(db.String(16), nullable=False)
    client_ip = db.Column(db.String(64), nullable=False)
    status_code = db.Column(db.Integer, nullable=False)
    decision = db.Column(db.String(16), nullable=False)  # ALLOWED | DENIED
    deny_reason = db.Column(db.String(128), nullable=True)
    latency_ms = db.Column(db.Float, default=0.0, nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)


class SecurityAuditLog(db.Model):
    """Bảng nhật ký kiểm toán các sự kiện an ninh trọng yếu (Tạo/Xoay/Thu hồi/Khóa tự động)."""

    __tablename__ = "security_audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    severity = db.Column(db.String(16), nullable=False, default="INFO")  # INFO | WARNING | CRITICAL
    ip_address = db.Column(db.String(64), nullable=True)
    description = db.Column(db.String(512), nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)
