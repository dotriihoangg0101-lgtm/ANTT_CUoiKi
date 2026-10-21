from datetime import datetime, timezone
from app.extensions import db
from app.services.crypto_service import encrypt_sensitive_value, decrypt_sensitive_value


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class VaultRecord(db.Model):
    """
    Bảng dữ liệu nghiệp vụ mẫu (Hồ sơ khách hàng & Tài khoản ngân hàng nhạy cảm)
    được bảo vệ bởi hệ thống API Key để phục vụ kiểm thử và Demo thực tế.
    """

    __tablename__ = "vault_records"

    id = db.Column(db.Integer, primary_key=True)
    customer_code = db.Column(db.String(32), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(120), nullable=False)
    account_number_masked = db.Column(db.String(64), nullable=False)
    encrypted_secret_note = db.Column(db.String(512), nullable=True)
    balance = db.Column(db.Float, nullable=False, default=0.0)
    classification = db.Column(db.String(32), nullable=False, default="CONFIDENTIAL")
    created_by_key = db.Column(db.String(64), nullable=True, default="SYSTEM_SEED")
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)

    def set_secret_note(self, note: str) -> None:
        self.encrypted_secret_note = encrypt_sensitive_value(note)

    def get_secret_note(self) -> str:
        return decrypt_sensitive_value(self.encrypted_secret_note or "")

    def to_dict(self, include_decrypted_note: bool = True) -> dict:
        return {
            "id": self.id,
            "customer_code": self.customer_code,
            "full_name": self.full_name,
            "account_number_masked": self.account_number_masked,
            "secret_note": self.get_secret_note() if include_decrypted_note else "[ENCRYPTED]",
            "balance": self.balance,
            "classification": self.classification,
            "created_by_key": self.created_by_key,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
