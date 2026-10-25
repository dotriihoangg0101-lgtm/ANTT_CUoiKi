from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app.extensions import db, limiter
from app.models import SecurityAuditLog, User
from app.services.crypto_service import password_needs_rehash
from app.services.password_policy import MAX_LENGTH, MIN_LENGTH, validate_password

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("20 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        client_ip = request.remote_addr or "127.0.0.1"

        user = User.query.filter_by(username=username).first()
        if user and user.is_active and user.check_password(password):
            # Nâng cấp hash cũ (Argon2id / PBKDF2 ít vòng) lên PBKDF2-HMAC-SHA256 hiện hành
            if password_needs_rehash(user.password_hash):
                user.set_password(password)
            login_user(user, remember=True)
            db.session.add(
                SecurityAuditLog(
                    user_id=user.id,
                    event_type="LOGIN_SUCCESS",
                    severity="INFO",
                    ip_address=client_ip,
                    description=f"Đăng nhập thành công vào tài khoản '{user.username}' (Role: {user.role}).",
                )
            )
            db.session.commit()
            flash(f"Chào mừng {user.username}! Đã xác thực mật khẩu bằng PBKDF2-HMAC-SHA256 (NIST SP 800-132).", "success")
            return redirect(url_for("dashboard.index"))

        db.session.add(
            SecurityAuditLog(
                user_id=user.id if user else None,
                event_type="LOGIN_FAILED",
                severity="WARNING",
                ip_address=client_ip,
                description=f"Đăng nhập thất bại với tên tài khoản '{username}'.",
            )
        )
        db.session.commit()
        flash("Tên đăng nhập hoặc mật khẩu không chính xác!", "danger")

    return render_template("login.html")


@auth_bp.route("/quick-login/<username>", methods=["POST"])
def quick_login(username: str):
    """Đăng nhập nhanh 1-click dành cho buổi thuyết trình Demo Đồ án."""
    if not current_app.config["DEMO_MODE"]:
        abort(404)
    if request.remote_addr not in ("127.0.0.1", "::1"):
        abort(404)
    if username not in ("admin", "dev_hoang"):
        abort(404)
    user = User.query.filter_by(username=username).first()
    if not user or not user.is_active:
        flash("Không tìm thấy tài khoản mẫu. Vui lòng khởi tạo dữ liệu seed.", "danger")
        return redirect(url_for("auth.login"))

    login_user(user, remember=True)
    db.session.add(
        SecurityAuditLog(
            user_id=user.id,
            event_type="DEMO_QUICK_LOGIN",
            severity="INFO",
            ip_address=request.remote_addr or "127.0.0.1",
            description=f"Đăng nhập nhanh chế độ Demo vào tài khoản '{user.username}' ({user.role}).",
        )
    )
    db.session.commit()
    flash(f"Đã chuyển sang tài khoản Demo: {user.username} ({user.role.upper()})", "info")
    return redirect(url_for("dashboard.index"))


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3:
            flash("Username phải từ 3 ký tự trở lên.", "danger")
            return redirect(url_for("auth.register"))

        # Chính sách mật khẩu NIST SP 800-63B-4: tối thiểu 15 ký tự, kiểm tra blocklist,
        # không áp quy tắc thành phần (chữ hoa / số / ký tự đặc biệt).
        password_errors = validate_password(password, username=username, email=email)
        if password_errors:
            for err in password_errors:
                flash(err, "danger")
            return redirect(url_for("auth.register"))

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username hoặc Email đã tồn tại trong hệ thống.", "danger")
            return redirect(url_for("auth.register"))

        user = User(username=username, email=email, role="developer", is_active=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        db.session.add(
            SecurityAuditLog(
                user_id=user.id,
                event_type="USER_REGISTERED",
                severity="INFO",
                ip_address=request.remote_addr or "127.0.0.1",
                description=f"Đăng ký tài khoản mới '{username}' (Mật khẩu đã băm bằng PBKDF2-HMAC-SHA256).",
            )
        )
        db.session.commit()

        login_user(user)
        flash("Đăng ký tài khoản thành công! Mật khẩu đã được băm bằng PBKDF2-HMAC-SHA256 (NIST SP 800-132).", "success")
        return redirect(url_for("dashboard.index"))

    return render_template("register.html", min_length=MIN_LENGTH, max_length=MAX_LENGTH)


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Đã đăng xuất khỏi hệ thống an toàn.", "info")
    return redirect(url_for("auth.login"))
