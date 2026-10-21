import ipaddress
import time
from collections import defaultdict
from datetime import datetime, timezone
from functools import wraps
from typing import Iterable, Optional

from flask import current_app, g, jsonify, make_response, request

from app.extensions import db
from app.models import ApiKey, ApiUsageLog, SecurityAuditLog
from app.services.crypto_service import verify_api_key_hash, verify_request_signature

# Bộ đếm Sliding-Window (60 giây) theo từng API Key ID
_KEY_RATE_WINDOW: dict[int, list[float]] = defaultdict(list)
_LOOPBACK = {"127.0.0.1", "::1"}


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def reset_rate_limit_buckets(api_key_id: Optional[int] = None) -> None:
    """Đặt lại bộ đếm Rate Limit (dùng khi reset kịch bản demo hoặc chạy test)."""
    if api_key_id is not None:
        _KEY_RATE_WINDOW.pop(api_key_id, None)
    else:
        _KEY_RATE_WINDOW.clear()


def _get_effective_client_ip() -> str:
    """
    Lấy địa chỉ IP của Client.
    Mặc định chỉ lấy request.remote_addr. Chỉ đọc 'X-Simulated-IP' khi DEMO_MODE bật.
    """
    real_ip = request.remote_addr or "0.0.0.0"
    if current_app.config.get("DEMO_MODE") and real_ip in _LOOPBACK:
        sim_ip = request.headers.get("X-Simulated-IP", "").strip()
        if sim_ip:
            try:
                ipaddress.ip_address(sim_ip)
            except ValueError:
                return real_ip
            current_app.logger.warning("DEMO: using simulated IP %s", sim_ip)
            return sim_ip
    return real_ip


def _is_ip_allowed(client_ip_str: str, allowed_ips_list: list[str]) -> bool:
    """Kiểm tra IP người gọi có nằm trong danh sách IP Whitelist hoặc dải mạng CIDR không."""
    if not allowed_ips_list:
        return True
    try:
        client_ip = ipaddress.ip_address(client_ip_str)
    except ValueError:
        return False

    for rule in allowed_ips_list:
        try:
            if "/" in rule:
                network = ipaddress.ip_network(rule, strict=False)
                if client_ip in network:
                    return True
            else:
                allowed_ip = ipaddress.ip_address(rule)
                if client_ip == allowed_ip:
                    return True
        except ValueError:
            continue
    return False


def _record_security_violation(api_key: ApiKey, reason_code: str, client_ip: str) -> bool:
    """
    Ghi nhận hành vi vi phạm bảo mật (sai IP, sai Scope, sai chữ ký HMAC).
    Nếu vượt ngưỡng AUTO_FREEZE_THRESHOLD liên tiếp -> Tự động đóng băng Key (Auto-Freeze).
    Trả về True nếu Key vừa bị đóng băng tự động.
    """
    threshold = current_app.config.get("AUTO_FREEZE_THRESHOLD", 5)
    api_key.failed_attempts = (api_key.failed_attempts or 0) + 1

    if api_key.failed_attempts >= threshold and api_key.is_active:
        api_key.is_active = False
        api_key.revoked_at = utc_now()
        api_key.revoked_reason = (
            f"AUTO_FROZEN: Phát hiện {api_key.failed_attempts} lần vi phạm bảo mật liên tiếp "
            f"(Vi phạm cuối: {reason_code} từ IP {client_ip})"
        )
        audit = SecurityAuditLog(
            user_id=api_key.user_id,
            event_type="AUTO_FROZEN",
            severity="CRITICAL",
            ip_address=client_ip,
            description=(
                f"[CẢNH BÁO XÂM NHẬP] Tự động đóng băng Key '{api_key.name}' ({api_key.key_prefix}) "
                f"do vi phạm bảo mật {api_key.failed_attempts} lần liên tiếp ({reason_code})."
            ),
        )
        db.session.add(audit)
        db.session.commit()
        return True

    db.session.commit()
    return False


def _log_api_attempt(
    api_key_id: Optional[int],
    key_prefix: str,
    client_ip: str,
    status_code: int,
    decision: str,
    deny_reason: Optional[str],
    start_perf: float,
) -> None:
    latency_ms = round((time.perf_counter() - start_perf) * 1000.0, 2)
    log_entry = ApiUsageLog(
        api_key_id=api_key_id,
        key_prefix_attempted=key_prefix or "NONE",
        endpoint=request.path,
        method=request.method,
        client_ip=client_ip,
        status_code=status_code,
        decision=decision,
        deny_reason=deny_reason,
        latency_ms=latency_ms,
    )
    db.session.add(log_entry)
    db.session.commit()


def require_api_key(
    required_scopes: Optional[Iterable[str]] = None,
    require_hmac: bool = False,
):
    """
    Middleware 6 Lớp kiểm soát truy cập API Key an toàn:
      - Chốt chặn 0: Cấm truyền API Key trên URL Query String (CWE-598).
      - Lớp 1: Kiểm tra cấu trúc Prefix & đối chiếu HMAC-SHA256 hằng thời gian (hmac.compare_digest).
      - Lớp 2: Kiểm tra Vòng đời (Revoked, Auto-Frozen, Expired TTL, Rotation Grace Period).
      - Lớp 3: Kiểm soát Địa chỉ mạng (IP Whitelisting & CIDR).
      - Lớp 4: Kiểm soát Phân quyền Đặc quyền tối thiểu (Scope-based Authorization).
      - Lớp 5: Kiểm soát Lưu lượng theo từng Key (Per-Key Sliding-Window Rate Limiting).
      - Lớp 6: Xác thực Chữ ký số HMAC-SHA256 & Timestamp chống Replay Attack / Sửa gói tin.
    """
    scopes_needed = list(required_scopes) if required_scopes else []

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_perf = time.perf_counter()
            client_ip = _get_effective_client_ip()

            # Chốt chặn 0: Từ chối nếu truyền API Key trên URL Query String (?api_key=...)
            if "api_key" in request.args or "key" in request.args:
                _log_api_attempt(
                    None, "URL_QUERY_LEAK", client_ip, 400, "DENIED", "API_KEY_IN_URL_FORBIDDEN", start_perf
                )
                return jsonify({
                    "status": "error",
                    "error_code": "API_KEY_IN_URL_FORBIDDEN",
                    "security_layer": "Layer 0 - Transport Security (CWE-598)",
                    "message": (
                        "Nghiêm cấm truyền API Key trên URL Query String vì sẽ bị lộ trong "
                        "Access Log và lịch sử trình duyệt. Vui lòng truyền qua Header 'X-API-Key'."
                    ),
                }), 400

            # Trích xuất API Key từ Header X-API-Key hoặc Authorization: Bearer
            raw_key = request.headers.get("X-API-Key", "").strip()
            if not raw_key:
                auth_header = request.headers.get("Authorization", "").strip()
                if auth_header.lower().startswith("bearer "):
                    raw_key = auth_header[7:].strip()

            if not raw_key:
                _log_api_attempt(None, "MISSING", client_ip, 401, "DENIED", "MISSING_API_KEY", start_perf)
                return jsonify({
                    "status": "error",
                    "error_code": "MISSING_API_KEY",
                    "security_layer": "Layer 1 - Authentication",
                    "message": "Thiếu thông tin xác thực. Vui lòng cung cấp Header 'X-API-Key'.",
                }), 401

            parts = raw_key.split("_")
            if len(parts) < 4 or parts[0] != "ak" or parts[1] not in ("live", "test"):
                _log_api_attempt(
                    None, "MALFORMED", client_ip, 401, "DENIED", "MALFORMED_API_KEY", start_perf
                )
                return jsonify({
                    "status": "error",
                    "error_code": "MALFORMED_API_KEY",
                    "security_layer": "Layer 1 - Format & Prefix Check",
                    "message": "Định dạng API Key không hợp lệ (Chuẩn yêu cầu: ak_<live|test>_<prefix>_<secret>).",
                }), 401

            key_prefix = "_".join(parts[:3])
            api_key = ApiKey.query.filter_by(key_prefix=key_prefix).first()

            # Lớp 1: Kiểm tra tồn tại & Đối chiếu mã băm HMAC-SHA256 bằng hmac.compare_digest
            if not api_key or not verify_api_key_hash(raw_key, api_key.key_hash):
                _log_api_attempt(
                    api_key.id if api_key else None,
                    key_prefix,
                    client_ip,
                    401,
                    "DENIED",
                    "INVALID_KEY_HASH",
                    start_perf,
                )
                return jsonify({
                    "status": "error",
                    "error_code": "INVALID_API_KEY",
                    "security_layer": "Layer 1 - HMAC-SHA256 Constant-Time Verification",
                    "message": "API Key không hợp lệ hoặc chữ ký băm không khớp.",
                }), 401

            # Lớp 2: Kiểm tra Vòng đời Key (Thu hồi, Tự động đóng băng, Hết hạn TTL, Hết ân hạn Rotate)
            if not api_key.is_active:
                is_frozen = api_key.revoked_reason and "AUTO_FROZEN" in api_key.revoked_reason
                err_code = "API_KEY_AUTO_FROZEN" if is_frozen else "API_KEY_REVOKED"
                _log_api_attempt(api_key.id, key_prefix, client_ip, 401, "DENIED", err_code, start_perf)
                return jsonify({
                    "status": "error",
                    "error_code": err_code,
                    "security_layer": "Layer 2 - Key Lifecycle & Intrusion Freeze",
                    "message": f"API Key đã bị vô hiệu hóa ({err_code}).",
                }), 401

            now = utc_now()
            if api_key.expires_at and now > api_key.expires_at:
                _log_api_attempt(
                    api_key.id, key_prefix, client_ip, 401, "DENIED", "API_KEY_EXPIRED", start_perf
                )
                return jsonify({
                    "status": "error",
                    "error_code": "API_KEY_EXPIRED",
                    "security_layer": "Layer 2 - Key Expiration (TTL)",
                    "expired_at": api_key.expires_at.isoformat(),
                    "message": f"API Key đã hết hạn sử dụng vào lúc {api_key.expires_at.strftime('%Y-%m-%d %H:%M UTC')}.",
                }), 401

            if api_key.grace_period_until and now > api_key.grace_period_until:
                _log_api_attempt(
                    api_key.id, key_prefix, client_ip, 401, "DENIED", "ROTATION_GRACE_EXPIRED", start_perf
                )
                return jsonify({
                    "status": "error",
                    "error_code": "ROTATION_GRACE_PERIOD_EXPIRED",
                    "security_layer": "Layer 2 - Key Rotation Lifecycle",
                    "message": "Thời gian ân hạn (Grace Period) của Key cũ sau khi Rotate đã kết thúc.",
                }), 401

            # Lớp 3: Kiểm soát Địa chỉ mạng (IP Whitelisting / CIDR)
            allowed_ips = api_key.get_allowed_ips_list()
            if not _is_ip_allowed(client_ip, allowed_ips):
                just_frozen = _record_security_violation(api_key, "IP_NOT_WHITELISTED", client_ip)
                _log_api_attempt(
                    api_key.id, key_prefix, client_ip, 403, "DENIED", "IP_NOT_WHITELISTED", start_perf
                )
                return jsonify({
                    "status": "error",
                    "error_code": "IP_NOT_WHITELISTED",
                    "security_layer": "Layer 3 - Network Access Control (IP Whitelist)",
                    "client_ip": client_ip,
                    "failed_attempts": api_key.failed_attempts,
                    "auto_frozen_triggered": just_frozen,
                    "message": (
                        f"Từ chối truy cập: Địa chỉ IP '{client_ip}' không được phép sử dụng API Key này."
                        + (" [CẢNH BÁO: Key đã bị tự động đóng băng do vi phạm liên tiếp!]" if just_frozen else "")
                    ),
                }), 403

            # Lớp 4: Kiểm tra Phân quyền Đặc quyền tối thiểu (Scope-based Authorization)
            granted_scopes = set(api_key.get_scopes_list())
            missing_scopes = [s for s in scopes_needed if s not in granted_scopes]
            if missing_scopes:
                just_frozen = _record_security_violation(api_key, "INSUFFICIENT_SCOPE", client_ip)
                _log_api_attempt(
                    api_key.id, key_prefix, client_ip, 403, "DENIED", "INSUFFICIENT_SCOPE", start_perf
                )
                return jsonify({
                    "status": "error",
                    "error_code": "INSUFFICIENT_SCOPE",
                    "security_layer": "Layer 4 - Least Privilege Scope Control",
                    "required_scopes": scopes_needed,
                    "missing_scopes": missing_scopes,
                    "failed_attempts": api_key.failed_attempts,
                    "auto_frozen_triggered": just_frozen,
                    "message": (
                        f"API Key không đủ quyền thực hiện thao tác này. "
                        f"Thiếu quyền (Scope): {', '.join(missing_scopes)}."
                        + (" [CẢNH BÁO: Key đã bị tự động đóng băng do dò quét trái phép liên tiếp!]" if just_frozen else "")
                    ),
                }), 403

            # Lớp 5: Kiểm soát Lưu lượng theo từng Key (Per-Key Sliding Window Rate Limiting)
            now_ts = time.time()
            window_start = now_ts - 60.0
            bucket = _KEY_RATE_WINDOW[api_key.id]
            bucket[:] = [t for t in bucket if t > window_start]

            limit_per_min = api_key.rate_limit_per_minute
            if len(bucket) >= limit_per_min:
                retry_after = max(1, int(60 - (now_ts - bucket[0])))
                _log_api_attempt(
                    api_key.id, key_prefix, client_ip, 429, "DENIED", "RATE_LIMITED", start_perf
                )
                resp = make_response(
                    jsonify({
                        "status": "error",
                        "error_code": "RATE_LIMIT_EXCEEDED",
                        "security_layer": "Layer 5 - Per-Key Rate Limiting & Quota",
                        "rate_limit_per_minute": limit_per_min,
                        "retry_after_seconds": retry_after,
                        "message": (
                            f"Vượt quá giới hạn lưu lượng của Key ({limit_per_min} requests/phút). "
                            f"Vui lòng thử lại sau {retry_after} giây."
                        ),
                    }),
                    429,
                )
                resp.headers["Retry-After"] = str(retry_after)
                resp.headers["X-RateLimit-Limit"] = str(limit_per_min)
                resp.headers["X-RateLimit-Remaining"] = "0"
                return resp

            # Lớp 6: Kiểm tra Chữ ký số HMAC-SHA256 & Timestamp (Chống Replay Attack & Sửa dữ liệu)
            sig_header = request.headers.get("X-Signature", "").strip()
            ts_header = request.headers.get("X-Timestamp", "").strip()
            if require_hmac or sig_header:
                signing_secret = api_key.get_signing_secret()
                raw_body = request.get_data(as_text=True) or ""
                ok_sig, sig_reason = verify_request_signature(
                    signing_secret=signing_secret,
                    timestamp_str=ts_header,
                    provided_signature=sig_header,
                    method=request.method,
                    path=request.path,
                    body=raw_body,
                    key_id=api_key.id,
                )
                if not ok_sig:
                    just_frozen = _record_security_violation(api_key, sig_reason, client_ip)
                    _log_api_attempt(
                        api_key.id, key_prefix, client_ip, 401, "DENIED", sig_reason, start_perf
                    )
                    return jsonify({
                        "status": "error",
                        "error_code": sig_reason,
                        "security_layer": "Layer 6 - HMAC-SHA256 Request Signing & Anti-Replay",
                        "failed_attempts": api_key.failed_attempts,
                        "auto_frozen_triggered": just_frozen,
                        "message": (
                            "Xác thực chữ ký gói tin thất bại: "
                            + (
                                "Chữ ký này đã được sử dụng trước đó (Phát hiện Replay Attack trong cửa sổ 300 giây)."
                                if sig_reason == "REPLAY_DETECTED"
                                else (
                                    "Gói tin đã quá hạn (Phát hiện tấn công phát lại - Replay Attack!)."
                                    if sig_reason == "TIMESTAMP_EXPIRED_REPLAY_DETECTED"
                                    else "Chữ ký HMAC không khớp hoặc nội dung gói tin đã bị chỉnh sửa trên đường truyền!"
                                )
                            )
                        ),
                    }), 401

            # Vượt qua toàn bộ 6 lớp bảo mật -> Ghi nhận truy cập hợp lệ
            bucket.append(now_ts)
            remaining_quota = max(0, limit_per_min - len(bucket))

            api_key.failed_attempts = 0
            api_key.usage_count = (api_key.usage_count or 0) + 1
            api_key.last_used_at = now
            api_key.last_used_ip = client_ip
            db.session.commit()

            g.current_api_key = api_key
            g.client_ip = client_ip

            response = make_response(func(*args, **kwargs))
            _log_api_attempt(
                api_key.id, key_prefix, client_ip, response.status_code, "ALLOWED", None, start_perf
            )

            # Đính kèm các Header thông tin Rate Limit & Cảnh báo Key đang trong thời gian ân hạn (Grace Period)
            response.headers["X-RateLimit-Limit"] = str(limit_per_min)
            response.headers["X-RateLimit-Remaining"] = str(remaining_quota)
            response.headers["X-API-Key-Prefix"] = api_key.key_prefix

            if api_key.is_in_grace_period and api_key.grace_period_until:
                response.headers["X-API-Key-Deprecated"] = "true"
                response.headers["X-API-Key-Sunset"] = api_key.grace_period_until.isoformat() + "Z"
                response.headers["Warning"] = (
                    f'299 - "API Key {api_key.key_prefix} is in rotation grace period and will expire at '
                    f'{api_key.grace_period_until.strftime("%Y-%m-%d %H:%M UTC")}"'
                )

            return response

        return wrapper

    return decorator
