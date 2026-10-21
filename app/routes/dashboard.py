from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required

from app.extensions import db
from app.middleware.api_auth import reset_rate_limit_buckets
from app.models import ApiKey, ApiUsageLog, SecurityAuditLog, User, VaultRecord
from app.services.key_service import KeyService
from app.services.seed_service import DEMO_KEYS_CATALOG, seed_initial_data
from app.utils.decorators import admin_required

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def home():
    accept = request.headers.get("Accept", "")
    if "text/html" in accept:
        if current_user.is_authenticated:
            return redirect(url_for("dashboard.index"))
        return redirect(url_for("auth.login"))
    return jsonify({
        "message": "Secure API Key Manager",
        "status": "running",
        "security_layers": 6,
    })


@dashboard_bp.route("/dashboard")
@login_required
def index(show_once_data=None):
    if current_user.is_admin:
        keys = ApiKey.query.order_by(ApiKey.id.desc()).all()
    else:
        keys = ApiKey.query.filter_by(user_id=current_user.id).order_by(ApiKey.id.desc()).all()
    total_keys = len(keys)
    active_keys = sum(1 for k in keys if k.status_label in ("ACTIVE", "GRACE_PERIOD"))
    frozen_or_revoked = sum(1 for k in keys if k.status_label in ("REVOKED", "AUTO_FROZEN"))

    if current_user.is_admin:
        usage_q = ApiUsageLog.query
        recent_audits = (
            SecurityAuditLog.query.order_by(SecurityAuditLog.id.desc()).limit(6).all()
        )
    else:
        key_ids = [k.id for k in keys]
        usage_q = (
            ApiUsageLog.query.filter(ApiUsageLog.api_key_id.in_(key_ids))
            if key_ids
            else ApiUsageLog.query.filter_by(api_key_id=-1)
        )
        recent_audits = (
            SecurityAuditLog.query
            .filter_by(user_id=current_user.id)
            .order_by(SecurityAuditLog.id.desc())
            .limit(6)
            .all()
        )
    total_requests = usage_q.count()
    blocked_attacks = usage_q.filter_by(decision="DENIED").count()

    return render_template(
        "dashboard.html",
        keys=keys,
        available_scopes=KeyService.AVAILABLE_SCOPES,
        show_once_data=show_once_data,
        stats={
            "total_keys": total_keys,
            "active_keys": active_keys,
            "frozen_or_revoked": frozen_or_revoked,
            "total_requests": total_requests,
            "blocked_attacks": blocked_attacks,
        },
        recent_audits=recent_audits,
    )


@dashboard_bp.route("/dashboard/keys/create", methods=["POST"])
@login_required
def create_key():
    name = request.form.get("name", "New Service Key").strip() or "New Service Key"
    environment = request.form.get("environment", "live")
    scopes_list = request.form.getlist("scopes")
    scopes = ",".join(scopes_list) if scopes_list else "read:records"
    allowed_ips = request.form.get("allowed_ips", "").strip()

    try:
        rate_limit = int(request.form.get("rate_limit_per_minute", 60))
        expires_days = int(request.form.get("expires_in_days", 30))
    except (ValueError, TypeError, OverflowError):
        abort(400)

    try:
        api_key, raw_key, signing_secret = KeyService.create_api_key(
            user=current_user,
            name=name,
            environment=environment,
            scopes=scopes,
            rate_limit_per_minute=rate_limit,
            allowed_ips=allowed_ips,
            expires_in_days=expires_days,
            client_ip=request.remote_addr or "127.0.0.1",
        )
    except ValueError:
        abort(400)

    # Render trực tiếp trong response POST (M1: Không lưu raw_key/signing_secret vào cookie session)
    show_once_data = {
        "action": "CREATED",
        "name": api_key.name,
        "key_prefix": api_key.key_prefix,
        "raw_key": raw_key,
        "signing_secret": signing_secret,
        "key_hash": api_key.key_hash,
    }
    flash(
        f"Đã cấp phát API Key '{api_key.name}' thành công! Hãy sao chép Key ngay (chỉ hiển thị 1 lần duy nhất).",
        "success",
    )
    return index(show_once_data=show_once_data)


@dashboard_bp.route("/dashboard/keys/<int:key_id>/rotate", methods=["POST"])
@login_required
def rotate_key(key_id: int):
    old_key = db.get_or_404(ApiKey, key_id)
    if not (old_key.user_id == current_user.id or current_user.is_admin):
        abort(403)
    try:
        grace_hours = int(request.form.get("grace_period_hours", 24) or 24)
        new_key, new_raw_key, new_signing_secret = KeyService.rotate_api_key(
            old_key=old_key,
            user=current_user,
            grace_period_hours=grace_hours,
            client_ip=request.remote_addr or "127.0.0.1",
        )
    except (ValueError, TypeError, OverflowError):
        abort(400)

    show_once_data = {
        "action": "ROTATED",
        "name": new_key.name,
        "old_prefix": old_key.key_prefix,
        "grace_until": old_key.grace_period_until.strftime("%Y-%m-%d %H:%M UTC"),
        "key_prefix": new_key.key_prefix,
        "raw_key": new_raw_key,
        "signing_secret": new_signing_secret,
        "key_hash": new_key.key_hash,
    }
    flash(
        f"Đã xoay vòng (Rotate) từ Key '{old_key.key_prefix}' sang Key mới '{new_key.key_prefix}'. "
        f"Key cũ vẫn hoạt động trong {grace_hours}h ân hạn!",
        "info",
    )
    return index(show_once_data=show_once_data)


@dashboard_bp.route("/dashboard/keys/<int:key_id>/revoke", methods=["POST"])
@login_required
def revoke_key(key_id: int):
    api_key = db.get_or_404(ApiKey, key_id)
    if not (api_key.user_id == current_user.id or current_user.is_admin):
        abort(403)
    reason = request.form.get("reason", "Thu hồi khẩn cấp bởi người quản trị trên Dashboard").strip()
    KeyService.revoke_api_key(
        api_key=api_key,
        user=current_user,
        reason=reason,
        client_ip=request.remote_addr or "127.0.0.1",
    )
    flash(f"Đã thu hồi khẩn cấp API Key '{api_key.key_prefix}'!", "warning")
    return redirect(url_for("dashboard.index"))


@dashboard_bp.route("/dashboard/keys/<int:key_id>/unlock", methods=["POST"])
@login_required
def unlock_key(key_id: int):
    api_key = db.get_or_404(ApiKey, key_id)
    if not (api_key.user_id == current_user.id or current_user.is_admin):
        abort(403)
    try:
        KeyService.unlock_api_key(
            api_key=api_key,
            user=current_user,
            client_ip=request.remote_addr or "127.0.0.1",
        )
    except ValueError:
        abort(400)
    reset_rate_limit_buckets(api_key.id)
    flash(f"Đã mở khóa và đặt lại bộ đếm vi phạm cho Key '{api_key.key_prefix}'.", "success")
    return redirect(url_for("dashboard.index"))


@dashboard_bp.route("/dashboard/reset-demo", methods=["POST"])
@login_required
@admin_required
def reset_demo():
    if not current_app.config.get("DEMO_MODE"):
        abort(404)
    seed_initial_data(force_reset=True)
    flash(
        "Đã khôi phục toàn bộ Database & 8 Ngữ cảnh Demo về trạng thái chuẩn ban đầu!",
        "success",
    )
    return redirect(request.referrer or url_for("dashboard.index"))


@dashboard_bp.route("/playground")
@login_required
def playground():
    if not current_app.config.get("DEMO_MODE"):
        abort(404)
    records = VaultRecord.query.order_by(VaultRecord.id.asc()).all()
    keys = ApiKey.query.order_by(ApiKey.id.asc()).all()
    return render_template(
        "playground.html",
        demo_catalog=DEMO_KEYS_CATALOG,
        records=records,
        keys=keys,
    )


@dashboard_bp.route("/logs")
@login_required
@admin_required
def logs():
    usage_logs = ApiUsageLog.query.order_by(ApiUsageLog.id.desc()).limit(100).all()
    audit_logs = SecurityAuditLog.query.order_by(SecurityAuditLog.id.desc()).limit(50).all()
    return render_template(
        "logs.html",
        usage_logs=usage_logs,
        audit_logs=audit_logs,
    )


@dashboard_bp.route("/db-inspector")
@login_required
@admin_required
def db_inspector():
    if not current_app.config.get("DEMO_MODE"):
        abort(404)
    users = User.query.order_by(User.id.asc()).all()
    api_keys = ApiKey.query.order_by(ApiKey.id.asc()).all()
    vault_records = VaultRecord.query.order_by(VaultRecord.id.asc()).all()
    usage_count = ApiUsageLog.query.count()
    audit_count = SecurityAuditLog.query.count()

    return render_template(
        "db_inspector.html",
        users=users,
        api_keys=api_keys,
        vault_records=vault_records,
        usage_count=usage_count,
        audit_count=audit_count,
    )
