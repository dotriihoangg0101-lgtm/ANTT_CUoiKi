from datetime import datetime, timedelta, timezone
import ipaddress
from typing import Optional, Tuple

from app.extensions import db
from app.models import ApiKey, SecurityAuditLog, User
from app.services.crypto_service import (
    encrypt_sensitive_value,
    generate_raw_api_key,
    generate_signing_secret,
    hash_api_key,
)


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class KeyService:
    """Dịch vụ quản lý vòng đời API Key an toàn (Cấp phát, Xoay vòng, Thu hồi, Mở khóa)."""

    AVAILABLE_SCOPES = [
        ("read:records", "Đọc danh sách & chi tiết hồ sơ nhạy cảm (GET /api/v1/records)"),
        ("write:records", "Tạo mới hồ sơ dữ liệu vào Vault (POST /api/v1/records)"),
        ("admin:records", "Xóa hồ sơ & thao tác quản trị (DELETE /api/v1/records/<id>)"),
        ("transfer:funds", "Thực hiện giao dịch chuyển tiền yêu cầu chữ ký HMAC (POST /api/v1/transfer)"),
    ]

    @staticmethod
    def create_api_key(
        user: User,
        name: str,
        environment: str = "live",
        scopes: str = "read:records",
        rate_limit_per_minute: int = 60,
        allowed_ips: str = "",
        expires_in_days: Optional[int] = 30,
        client_ip: str = "127.0.0.1",
        fixed_raw_key: Optional[str] = None,
        fixed_signing_secret: Optional[str] = None,
        custom_expires_at: Optional[datetime] = None,
    ) -> Tuple[ApiKey, str, str]:
        """
        Tạo API Key mới.
        Trả về bộ 3: (ApiKey model, raw_api_key_show_once, signing_secret_show_once)
        """
        if environment not in ("live", "test"):
            raise ValueError("Invalid environment: must be 'live' or 'test'.")

        valid_scope_codes = {code for code, _ in KeyService.AVAILABLE_SCOPES}
        requested_scopes = [s.strip() for s in (scopes or "").split(",") if s.strip()]
        if not requested_scopes:
            raise ValueError("At least one valid scope is required.")
        for sc in requested_scopes:
            if sc not in valid_scope_codes:
                raise ValueError(f"Unknown scope: {sc}")
            if (sc.startswith("admin:") or sc == "transfer:funds") and not user.is_admin:
                raise ValueError(f"Scope '{sc}' requires admin privileges.")

        cleaned_ips = (allowed_ips or "").strip()
        if cleaned_ips and cleaned_ips != "*":
            for part in cleaned_ips.replace("\n", ",").split(","):
                rule = part.strip()
                if not rule:
                    continue
                try:
                    if "/" in rule:
                        ipaddress.ip_network(rule, strict=False)
                    else:
                        ipaddress.ip_address(rule)
                except ValueError as exc:
                    raise ValueError(f"Invalid IP/CIDR in allowed_ips: {rule}") from exc

        if fixed_raw_key:
            parts = fixed_raw_key.split("_")
            key_prefix = "_".join(parts[:3])
            raw_key = fixed_raw_key
        else:
            key_prefix, raw_key = generate_raw_api_key(environment)

        signing_secret = fixed_signing_secret or generate_signing_secret()
        key_hash = hash_api_key(raw_key)
        signing_secret_enc = encrypt_sensitive_value(signing_secret)

        if custom_expires_at is not None:
            expires_at = custom_expires_at
        else:
            try:
                ttl_days = int(expires_in_days) if expires_in_days is not None else 0
            except (ValueError, TypeError) as exc:
                raise ValueError("expires_in_days must be an integer.") from exc
            if ttl_days < 1 or ttl_days > 365:
                raise ValueError("expires_in_days must be between 1 and 365.")
            expires_at = utc_now() + timedelta(days=ttl_days)

        try:
            rate_limit_per_minute = int(rate_limit_per_minute)
        except (ValueError, TypeError) as exc:
            raise ValueError("rate_limit_per_minute must be an integer.") from exc
        if rate_limit_per_minute < 1 or rate_limit_per_minute > 1000:
            raise ValueError("rate_limit_per_minute must be between 1 and 1000.")

        api_key = ApiKey(
            user_id=user.id,
            name=name.strip(),
            environment=environment,
            key_prefix=key_prefix,
            key_hash=key_hash,
            signing_secret_enc=signing_secret_enc,
            scopes=scopes.strip(),
            rate_limit_per_minute=rate_limit_per_minute,
            allowed_ips=allowed_ips.strip(),
            expires_at=expires_at,
            is_active=True,
        )
        db.session.add(api_key)

        audit = SecurityAuditLog(
            user_id=user.id,
            event_type="KEY_CREATED",
            severity="INFO",
            ip_address=client_ip,
            description=(
                f"Cấp phát API Key mới '{api_key.name}' (Prefix: {key_prefix}, "
                f"Scopes: [{scopes}], RateLimit: {rate_limit_per_minute}/m)"
            ),
        )
        db.session.add(audit)
        db.session.commit()

        return api_key, raw_key, signing_secret

    @staticmethod
    def rotate_api_key(
        old_key: ApiKey,
        user: User,
        grace_period_hours: int = 24,
        client_ip: str = "127.0.0.1",
    ) -> Tuple[ApiKey, str, str]:
        """
        Xoay vòng khóa không gián đoạn (Zero-Downtime Key Rotation):
        - Tạo Key mới kế thừa nguyên vẹn cấu hình của Key cũ.
        - Giữ Key cũ sống trong khoảng thời gian ân hạn (grace_period_until) để hệ thống client kịp cập nhật.
        """
        if old_key.status_label != "ACTIVE":
            raise ValueError("Chỉ được phép xoay vòng (Rotate) các API Key đang ở trạng thái ACTIVE.")

        try:
            grace_period_hours = int(grace_period_hours)
        except (TypeError, ValueError) as exc:
            raise ValueError("grace_period_hours phải là số nguyên.") from exc
        if grace_period_hours < 1 or grace_period_hours > 168:
            raise ValueError("grace_period_hours phải nằm trong khoảng 1..168 giờ.")

        key_prefix, new_raw_key = generate_raw_api_key(old_key.environment)
        new_signing_secret = generate_signing_secret()

        now = utc_now()
        old_key.grace_period_until = now + timedelta(hours=grace_period_hours)

        new_key = ApiKey(
            user_id=old_key.user_id,
            name=f"{old_key.name} (Rotated)",
            environment=old_key.environment,
            key_prefix=key_prefix,
            key_hash=hash_api_key(new_raw_key),
            signing_secret_enc=encrypt_sensitive_value(new_signing_secret),
            scopes=old_key.scopes,
            rate_limit_per_minute=old_key.rate_limit_per_minute,
            allowed_ips=old_key.allowed_ips,
            expires_at=now + timedelta(days=30),
            rotated_from_id=old_key.id,
            is_active=True,
        )
        db.session.add(new_key)

        audit = SecurityAuditLog(
            user_id=user.id,
            event_type="KEY_ROTATED",
            severity="WARNING",
            ip_address=client_ip,
            description=(
                f"Xoay vòng Key '{old_key.key_prefix}' -> Key mới '{key_prefix}'. "
                f"Key cũ được ân hạn (Grace Period) {grace_period_hours}h đến "
                f"{old_key.grace_period_until.strftime('%Y-%m-%d %H:%M UTC')}."
            ),
        )
        db.session.add(audit)
        db.session.commit()

        return new_key, new_raw_key, new_signing_secret

    @staticmethod
    def revoke_api_key(
        api_key: ApiKey,
        user: User,
        reason: str = "Thu hồi khẩn cấp bởi quản trị viên",
        client_ip: str = "127.0.0.1",
    ) -> ApiKey:
        """Thu hồi khẩn cấp API Key (vô hiệu hóa ngay lập tức)."""
        api_key.is_active = False
        api_key.revoked_at = utc_now()
        api_key.revoked_reason = reason

        audit = SecurityAuditLog(
            user_id=user.id,
            event_type="KEY_REVOKED",
            severity="WARNING",
            ip_address=client_ip,
            description=f"Thu hồi khẩn cấp Key '{api_key.name}' ({api_key.key_prefix}). Lý do: {reason}",
        )
        db.session.add(audit)
        db.session.commit()
        return api_key

    @staticmethod
    def unlock_api_key(
        api_key: ApiKey,
        user: User,
        client_ip: str = "127.0.0.1",
    ) -> ApiKey:
        """Mở khóa lại API Key chỉ khi ở trạng thái bị đóng băng tự động (AUTO_FROZEN)."""
        if api_key.status_label != "AUTO_FROZEN":
            raise ValueError("Chỉ được phép mở khóa các API Key đang ở trạng thái AUTO_FROZEN.")

        api_key.is_active = True
        api_key.failed_attempts = 0
        api_key.revoked_at = None
        api_key.revoked_reason = None

        audit = SecurityAuditLog(
            user_id=user.id,
            event_type="KEY_UNLOCKED",
            severity="INFO",
            ip_address=client_ip,
            description=f"Mở khóa & đặt lại bộ đếm vi phạm cho Key '{api_key.name}' ({api_key.key_prefix}).",
        )
        db.session.add(audit)
        db.session.commit()
        return api_key
