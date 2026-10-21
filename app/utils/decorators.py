from functools import wraps
from flask import abort
from flask_login import current_user


def admin_required(func):
    """Decorator yêu cầu người dùng đã đăng nhập và có quyền Admin (role == 'admin')."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not (current_user.is_authenticated and current_user.is_admin):
            abort(403)
        return func(*args, **kwargs)

    return wrapper
