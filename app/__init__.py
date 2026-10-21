import os
from flask import Flask, flash, jsonify, redirect, request
from flask_login import login_url
from werkzeug.middleware.proxy_fix import ProxyFix
from .config import Config, validate_secrets
from .extensions import csrf, db, limiter, login_manager, migrate


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    if not app.config.get("TESTING", False):
        validate_secrets(app)
        if app.config.get("DEMO_MODE", False):
            from .services.seed_service import missing_demo_secrets

            missing = missing_demo_secrets()
            if missing:
                raise RuntimeError(
                    "DEMO_MODE=1 nhưng file .env thiếu Key demo: " + ", ".join(missing)
                    + ". Chạy 'python scripts/tao_env.py' để sinh file .env đầy đủ."
                )

    if os.environ.get("TRUST_PROXY") == "1":
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

    # Khởi tạo các Flask Extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Đăng ký các Blueprints
    from .routes import api_bp, auth_bp, dashboard_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp)

    @app.context_processor
    def inject_demo_flag():
        return {"demo_mode": app.config.get("DEMO_MODE", False)}

    # API (/api/...) luôn trả lỗi dạng JSON để client & Playground đọc được error_code
    @app.errorhandler(429)
    def handle_too_many_requests(err):
        if not request.path.startswith("/api/"):
            return err
        resp = jsonify({
            "status": "error",
            "error_code": "TOO_MANY_REQUESTS",
            "security_layer": "Global IP Rate Limit (Flask-Limiter)",
            "message": f"Quá nhiều request từ địa chỉ IP này ({err.description}). Vui lòng thử lại sau.",
        })
        resp.status_code = 429
        retry_after = getattr(err, "retry_after", None)
        if retry_after:
            resp.headers["Retry-After"] = str(retry_after)
        return resp

    @login_manager.unauthorized_handler
    def handle_unauthorized():
        if request.path.startswith("/api/"):
            return jsonify({
                "status": "error",
                "error_code": "LOGIN_REQUIRED",
                "message": "Endpoint này yêu cầu đăng nhập Dashboard.",
            }), 401
        # Giữ nguyên hành vi mặc định của Flask-Login cho các trang web
        flash(login_manager.login_message, login_manager.login_message_category)
        return redirect(login_url(login_manager.login_view, next_url=request.url))

    # Gắn HTTP Security Headers cho mọi phản hồi
    @app.after_request
    def apply_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net data:; "
            "img-src 'self' data:; "
            "frame-ancestors 'self';"
        )
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # Tự động khởi tạo bảng và dữ liệu mẫu chỉ khi DEMO_MODE bật (và không phải TESTING)
    with app.app_context():
        db.create_all()
        if not app.config.get("TESTING", False) and app.config.get("DEMO_MODE", False):
            from .services.seed_service import seed_initial_data
            seed_initial_data(force_reset=False)

    return app
