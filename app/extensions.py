from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=["300 per minute"])

login_manager.login_view = "auth.login"
login_manager.login_message = "Vui lòng đăng nhập để truy cập hệ thống quản lý API Key."
login_manager.login_message_category = "warning"
