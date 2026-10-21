import json
import math
import time
import uuid
from decimal import Decimal, InvalidOperation
from flask import Blueprint, abort, current_app, g, jsonify, request
from flask_login import login_required

from app.extensions import csrf, db, limiter
from app.middleware.api_auth import require_api_key
from app.models import ApiKey, VaultRecord
from app.services.crypto_service import compute_request_signature

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")
csrf.exempt(api_bp)
limiter.limit("120 per minute")(api_bp)


@api_bp.route("/records", methods=["GET"])
@require_api_key(required_scopes=["read:records"])
def list_records():
    """
    API Lấy danh sách Hồ sơ nhạy cảm từ Database.
    Yêu cầu Scope: 'read:records'
    """
    api_key: ApiKey = g.current_api_key
    records = VaultRecord.query.order_by(VaultRecord.id.asc()).all()

    return jsonify({
        "status": "success",
        "security_verification": {
            "authenticated_key_prefix": api_key.key_prefix,
            "key_name": api_key.name,
            "client_ip": g.client_ip,
            "granted_scopes": api_key.get_scopes_list(),
            "in_rotation_grace_period": api_key.is_in_grace_period,
            "deprecation_notice": (
                f"Key đang trong thời gian ân hạn (Grace Period) đến {api_key.grace_period_until.isoformat()}Z. "
                "Vui lòng cập nhật sang Key mới!"
                if api_key.is_in_grace_period and api_key.grace_period_until
                else None
            ),
        },
        "total_records": len(records),
        "data": [r.to_dict(include_decrypted_note=True) for r in records],
    }), 200


@api_bp.route("/records", methods=["POST"])
@require_api_key(required_scopes=["write:records"])
def create_record():
    """
    API Tạo mới Hồ sơ nhạy cảm vào Database (Ghi chú bí mật được mã hóa Fernet).
    Yêu cầu Scope: 'write:records'
    """
    api_key: ApiKey = g.current_api_key
    payload = request.get_json(silent=True) or {}

    raw_full_name = payload.get("full_name")
    full_name = (
        raw_full_name
        if isinstance(raw_full_name, str) and raw_full_name.strip()
        else "Khách hàng Doanh nghiệp Mới"
    ).strip()
    raw_customer_code = payload.get("customer_code")
    customer_code = (
        raw_customer_code
        if isinstance(raw_customer_code, str) and raw_customer_code.strip()
        else f"CUST-2026-{uuid.uuid4().hex[:4].upper()}"
    ).strip()
    raw_account_masked = payload.get("account_number_masked")
    account_masked = (
        raw_account_masked
        if isinstance(raw_account_masked, str) and raw_account_masked.strip()
        else "9704-99**-****-1234"
    ).strip()
    raw_secret_note = payload.get("secret_note")
    secret_note = (
        raw_secret_note
        if isinstance(raw_secret_note, str) and raw_secret_note.strip()
        else "Hồ sơ tạo mới qua API Gateway - Đã mã hóa Fernet"
    ).strip()
    raw_balance = payload.get("balance", 50000000.0)
    if isinstance(raw_balance, bool):
        return jsonify({"status": "error", "error_code": "INVALID_BALANCE"}), 400
    try:
        balance = float(50000000.0 if raw_balance is None else raw_balance)
    except (ValueError, TypeError):
        return jsonify({"status": "error", "error_code": "INVALID_BALANCE"}), 400
    if not math.isfinite(balance) or balance < 0:
        return jsonify({"status": "error", "error_code": "INVALID_BALANCE"}), 400
    raw_classification = payload.get("classification")
    classification = (
        raw_classification
        if isinstance(raw_classification, str) and raw_classification.strip()
        else "CONFIDENTIAL"
    ).upper()

    if VaultRecord.query.filter_by(customer_code=customer_code).first():
        customer_code = f"{customer_code}-{uuid.uuid4().hex[:3].upper()}"

    rec = VaultRecord(
        customer_code=customer_code,
        full_name=full_name,
        account_number_masked=account_masked,
        balance=balance,
        classification=classification,
        created_by_key=api_key.key_prefix,
    )
    rec.set_secret_note(secret_note)
    db.session.add(rec)
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": f"Đã tạo mới hồ sơ '{customer_code}' và mã hóa dữ liệu nhạy cảm bằng Fernet trong Database.",
        "created_by_key": api_key.key_prefix,
        "record": rec.to_dict(include_decrypted_note=True),
    }), 201


@api_bp.route("/records/<int:record_id>", methods=["DELETE"])
@require_api_key(required_scopes=["admin:records"])
def delete_record(record_id: int):
    """
    API Xóa Hồ sơ trong Database.
    Yêu cầu Scope Quản trị: 'admin:records'
    """
    api_key: ApiKey = g.current_api_key
    rec = db.session.get(VaultRecord, record_id)
    if not rec:
        return jsonify({
            "status": "error",
            "error_code": "RECORD_NOT_FOUND",
            "message": f"Không tìm thấy hồ sơ ID={record_id} trong Database.",
        }), 404

    code = rec.customer_code
    db.session.delete(rec)
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": f"Đã xóa hồ sơ '{code}' (ID={record_id}) bằng quyền 'admin:records'.",
        "deleted_by_key": api_key.key_prefix,
    }), 200


@api_bp.route("/transfer", methods=["POST"])
@require_api_key(required_scopes=["transfer:funds"], require_hmac=True)
def secure_transfer():
    """
    API Giao dịch Chuyển tiền Ngân hàng Nhạy cảm.
    Yêu cầu ĐỒNG THỜI:
      1. Scope: 'transfer:funds'
      2. Chữ ký số gói tin: 'X-Signature' = HMAC-SHA256(signing_secret, timestamp.POST./api/v1/transfer.body)
      3. 'X-Timestamp' trong vòng ±300 giây (Chống Replay Attack & Chống sửa số tiền trên đường truyền)
    """
    api_key: ApiKey = g.current_api_key
    payload = request.get_json(silent=True) or {}

    raw_code = payload.get("customer_code")
    customer_code = raw_code.strip() if isinstance(raw_code, str) else ""
    raw_amount = payload.get("amount")
    recipient = payload.get("recipient", "VAULT-TREASURY-999")

    if not customer_code:
        return jsonify({
            "status": "error",
            "error_code": "MISSING_CUSTOMER_CODE",
            "message": "Thiếu mã khách hàng 'customer_code'.",
        }), 400

    rec = VaultRecord.query.filter_by(customer_code=customer_code).first()
    if not rec:
        return jsonify({
            "status": "error",
            "error_code": "CUSTOMER_NOT_FOUND",
            "message": f"Không tìm thấy hồ sơ khách hàng '{customer_code}'.",
        }), 404

    if raw_amount is None or isinstance(raw_amount, bool):
        return jsonify({
            "status": "error",
            "error_code": "INVALID_AMOUNT",
            "message": "Số tiền giao dịch không hợp lệ.",
        }), 400

    try:
        amount_dec = Decimal(str(raw_amount))
    except (InvalidOperation, ValueError, TypeError):
        return jsonify({
            "status": "error",
            "error_code": "INVALID_AMOUNT",
            "message": "Số tiền giao dịch phải là số hợp lệ.",
        }), 400

    if not amount_dec.is_finite() or amount_dec <= Decimal("0"):
        return jsonify({
            "status": "error",
            "error_code": "INVALID_AMOUNT",
            "message": "Số tiền giao dịch phải lớn hơn 0 và hữu hạn.",
        }), 400

    balance_dec = Decimal(str(rec.balance))
    if amount_dec > balance_dec:
        return jsonify({
            "status": "error",
            "error_code": "INSUFFICIENT_BALANCE",
            "message": "Số tiền chuyển vượt quá số dư khả dụng của tài khoản.",
        }), 400

    old_balance = rec.balance
    amount = float(amount_dec)
    rec.balance = float(round(balance_dec - amount_dec, 2))
    db.session.commit()

    return jsonify({
        "status": "success",
        "security_layer": "Layer 6 - HMAC-SHA256 Signature & Timestamp Anti-Replay Verified",
        "message": "Giao dịch chuyển tiền đã được xác thực toàn vẹn chữ ký HMAC-SHA256 và thực thi thành công!",
        "transaction": {
            "source_customer": rec.customer_code if rec else customer_code,
            "recipient_account": recipient,
            "amount_transferred": amount,
            "previous_balance": old_balance,
            "new_balance": rec.balance if rec else 0.0,
            "authorized_by_key": api_key.key_prefix,
            "verified_timestamp": request.headers.get("X-Timestamp"),
        },
    }), 200


@api_bp.route("/demo/compute-hmac", methods=["POST"])
@login_required
def demo_compute_hmac():
    """
    API hỗ trợ giao diện Playground tính toán chữ ký HMAC-SHA256 để phục vụ trình diễn Ngữ cảnh 8:
      - mode = 'valid': Ký đúng với thời gian hiện tại
      - mode = 'replay': Ký với thời gian lùi về 15 phút trước (Mô phỏng Replay Attack)
      - mode = 'tampered': Ký cho số tiền 1,000,000 nhưng kẻ tấn công sửa body thành 999,000,000 trên đường truyền
    """
    if not current_app.config.get("DEMO_MODE"):
        abort(404)

    data = request.get_json(silent=True) or {}
    signing_secret = (data.get("signing_secret") or "").strip()
    if not signing_secret:
        return jsonify({
            "status": "error",
            "error_code": "MISSING_SIGNING_SECRET",
            "message": "Bắt buộc phải cung cấp 'signing_secret' để tính toán chữ ký HMAC.",
        }), 400
    method = data.get("method", "POST").upper()
    path = data.get("path", "/api/v1/transfer")
    mode = data.get("mode", "valid")
    if mode not in ("valid", "replay", "tampered"):
        return jsonify({"status": "error", "error_code": "INVALID_MODE"}), 400

    now_ts = int(time.time())
    if mode == "replay":
        # Giả lập gói tin cũ bị bắt lén từ 15 phút trước (900 giây > ngưỡng 300 giây)
        ts_str = str(now_ts - 900)
        body_obj = {
            "customer_code": "CUST-2026-001",
            "amount": 5000000,
            "recipient": "ACC-NORMAL-001",
        }
        body_str = json.dumps(body_obj)
        sig = compute_request_signature(signing_secret, ts_str, method, path, body_str)
        return jsonify({
            "timestamp": ts_str,
            "signature": sig,
            "body_to_send": body_str,
            "explanation": "Gói tin có chữ ký đúng nhưng Timestamp đã cũ 15 phút trước (Mô phỏng Replay Attack).",
        })

    if mode == "tampered":
        # Người dùng ký gói tin chuyển 1,000,000 VNĐ, nhưng kẻ tấn công MITM sửa body thành 999,000,000 VNĐ
        ts_str = str(now_ts)
        original_body = json.dumps({
            "customer_code": "CUST-2026-001",
            "amount": 1000000,
            "recipient": "ACC-LEGIT-001",
        })
        sig = compute_request_signature(signing_secret, ts_str, method, path, original_body)
        tampered_body = json.dumps({
            "customer_code": "CUST-2026-001",
            "amount": 999000000,
            "recipient": "HACKER-OFFSHORE-999",
        })
        return jsonify({
            "timestamp": ts_str,
            "signature": sig,
            "body_to_send": tampered_body,
            "explanation": (
                "Chữ ký được tính cho amount=1,000,000 nhưng body gửi lên bị kẻ tấn công sửa thành "
                "amount=999,000,000 & tài khoản HACKER-OFFSHORE-999."
            ),
        })

    # Mặc định: Hợp lệ
    ts_str = str(now_ts)
    body_str = data.get("body") or json.dumps({
        "customer_code": "CUST-2026-001",
        "amount": 5000000,
        "recipient": "VN-TREASURY-888",
    })
    sig = compute_request_signature(signing_secret, ts_str, method, path, body_str)
    return jsonify({
        "timestamp": ts_str,
        "signature": sig,
        "body_to_send": body_str,
        "explanation": "Chữ ký HMAC-SHA256 hợp lệ với Timestamp thời gian thực.",
    })
