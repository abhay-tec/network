from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import argparse
import os
import smtplib
import sys
import ssl
from email.mime.text import MIMEText

from flask import Flask, g, jsonify, request, render_template, send_from_directory

BASE_DIR = Path(__file__).resolve().parent
SESSION_TTL_SECONDS = 60
DASHBOARD_SESSION_TTL_SECONDS = 15 * 60
MAX_FAILED_ATTEMPTS = 3

PRIVACY_MODES = {
    "ghost": "Ghost Mode",
    "semi-private": "Semi-Private",
    "public": "Public Node",
}


@dataclass
class AuthSession:
    username: str
    password_hash: str
    otp_code: str
    email: str = ""
    channel: str = "gmail"
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + SESSION_TTL_SECONDS)
    failed_attempts: int = 0
    verified: bool = False


@dataclass
class DashboardSession:
    username: str
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + DASHBOARD_SESSION_TTL_SECONDS)


@dataclass
class UserRecord:
    id: int
    username: str
    email: str
    password_hash: str
    salt: str
    created_at: float
    privacy_mode: str = "public"
    public_key_id: str | None = None
    setup_completed: int = 0


app = Flask(__name__, template_folder=str(BASE_DIR))
app.config["JSON_SORT_KEYS"] = False

_SESSION_LOCK = threading.Lock()
_AUTH_SESSIONS: dict[str, AuthSession] = {}

# In-memory user store. Vercel serverless functions run on a read-only file
# system, so persistent SQLite writes are impossible. Users are held in a
# thread-safe dictionary guarded by _DB_LOCK to simulate the database in RAM.
_DB_LOCK = threading.Lock()
_USERS: dict[str, UserRecord] = {}
_USER_ID_SEQ = 0

_DASHBOARD_SESSION_LOCK = threading.Lock()
_DASHBOARD_SESSIONS: dict[str, DashboardSession] = {}


def _now() -> float:
    return time.time()


def _generate_otp() -> str:
    return f"{100000 + secrets.randbelow(900000):06d}"


def _generate_tx_token() -> str:
    return secrets.token_urlsafe(32)


def _generate_dashboard_token() -> str:
    return secrets.token_urlsafe(48)


def _generate_public_key_id(username: str) -> str:
    payload = f"{username}-{time.time()}-{secrets.token_hex(8)}"
    return "0x" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _mask_email(email: str) -> str:
    if "@" not in email:
        return email

    local_part, domain = email.split("@", 1)
    if len(local_part) <= 2:
        masked_local = local_part[0] + "*"
    else:
        masked_local = local_part[:2] + "*" * max(2, min(4, len(local_part) - 2))
    return f"{masked_local}@{domain}"


class SMTPNotConfiguredError(RuntimeError):
    """Raised when Gmail SMTP credentials are not present in the environment."""


def _smtp_config() -> dict[str, Any]:
    return {
        "host": "smtp.gmail.com",
        "port": 587,
        "email": os.environ.get("SMTP_EMAIL", "").strip(),
        "password": os.environ.get("SMTP_PASSWORD", "").strip(),
        "timeout": 15.0,
    }


def _send_otp_email(session: AuthSession) -> None:
    settings = _smtp_config()
    if not settings["email"] or not settings["password"]:
        raise SMTPNotConfiguredError("SMTP_EMAIL/SMTP_PASSWORD are not configured.")

    if not session.email:
        raise RuntimeError("Recipient email is missing.")

    otp_code = _issue_otp(session, "gmail")
    body = "\n".join(
        [
            f"Hi {session.username},",
            "",
            "Thanks for making acc here is your otp:",
            otp_code,
            "",
            f"This code expires in {SESSION_TTL_SECONDS // 60} minute.",
            "If you did not request this, you can ignore this email.",
        ]
    )
    message = MIMEText(body)
    message["Subject"] = "Trust System OTP Verification"
    message["From"] = settings["email"]
    message["To"] = session.email

    context = ssl.create_default_context()
    with smtplib.SMTP(settings["host"], settings["port"], timeout=settings["timeout"]) as smtp:
        smtp.starttls(context=context)
        smtp.login(settings["email"], settings["password"])
        smtp.send_message(message)


def _json_error(message: str, status_code: int, code: str) -> tuple[Any, int]:
    return jsonify({"error": message, "code": code}), status_code


# Signing key for client-side sync tokens. Set SYNC_SIGNING_KEY in the
# environment so signatures survive serverless cold starts (a per-process
# fallback is generated otherwise, in which case restore only works within the
# same warm instance).
_SYNC_SIGNING_KEY = os.environ.get("SYNC_SIGNING_KEY", "").strip() or secrets.token_hex(32)
_SYNC_FIELDS = (
    "id",
    "username",
    "email",
    "password_hash",
    "salt",
    "created_at",
    "privacy_mode",
    "public_key_id",
    "setup_completed",
)


def _sync_secret() -> bytes:
    return _SYNC_SIGNING_KEY.encode("utf-8")


def _make_sync_token(user: dict[str, Any]) -> str:
    """Return an HMAC-signed, tamper-evident token encoding the user record."""
    payload = {key: user.get(key) for key in _SYNC_FIELDS}
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    signature = hmac.new(_sync_secret(), encoded.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def _verify_sync_token(token: str) -> dict[str, Any] | None:
    """Validate a sync token's signature and return its payload, or None."""
    try:
        encoded, signature = token.split(".", 1)
    except ValueError:
        return None

    expected = hmac.new(_sync_secret(), encoded.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return None

    try:
        payload = json.loads(base64.urlsafe_b64decode(encoded.encode("ascii")).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None

    if not isinstance(payload, dict):
        return None
    return payload


def _sync_token_for_user(username: str) -> str | None:
    user = _query_user(username)
    if user is None:
        return None
    return _make_sync_token(user)


def _record_to_dict(record: UserRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "username": record.username,
        "email": record.email,
        "password_hash": record.password_hash,
        "created_at": record.created_at,
        "salt": record.salt,
        "privacy_mode": record.privacy_mode,
        "public_key_id": record.public_key_id,
        "setup_completed": record.setup_completed,
    }


def _init_db() -> None:
    # The in-memory store lives in module-level globals, so there is no schema
    # to create or migrate. This hook is kept for flow parity with startup.
    with _DB_LOCK:
        pass


def _add_auth_session(tx_token: str, session_obj: AuthSession) -> None:
    with _SESSION_LOCK:
        _AUTH_SESSIONS[tx_token] = session_obj


def _get_auth_session(tx_token: str) -> tuple[str | None, AuthSession | None]:
    with _SESSION_LOCK:
        session = _AUTH_SESSIONS.get(tx_token)
        if session is None:
            return None, None
        return tx_token, session


def _purge_session(tx_token: str) -> None:
    with _SESSION_LOCK:
        if tx_token in _AUTH_SESSIONS:
            del _AUTH_SESSIONS[tx_token]


def _session_expired(session: AuthSession) -> bool:
    return _now() > session.expires_at


def _issue_otp(session: AuthSession, channel: str) -> str:
    otp_code = _generate_otp()
    session.otp_code = otp_code
    session.channel = channel
    session.expires_at = _now() + SESSION_TTL_SECONDS
    return otp_code


def _add_dashboard_session(token: str, session_obj: DashboardSession) -> None:
    with _DASHBOARD_SESSION_LOCK:
        _DASHBOARD_SESSIONS[token] = session_obj


def _get_dashboard_session(token: str) -> tuple[str | None, DashboardSession | None]:
    with _DASHBOARD_SESSION_LOCK:
        session = _DASHBOARD_SESSIONS.get(token)
        if session is None:
            return None, None
        if _now() > session.expires_at:
            del _DASHBOARD_SESSIONS[token]
            return None, None
        return token, session


def _query_user(username: str) -> dict[str, Any] | None:
    with _DB_LOCK:
        record = _USERS.get(username)
        if record is None:
            return None
        return _record_to_dict(record)


def _insert_user(username: str, email: str, password_hash: str) -> bool:
    global _USER_ID_SEQ
    with _DB_LOCK:
        if username in _USERS:
            return False

        _USER_ID_SEQ += 1
        _USERS[username] = UserRecord(
            id=_USER_ID_SEQ,
            username=username,
            email=email,
            password_hash=password_hash,
            salt=secrets.token_hex(16),
            created_at=_now(),
        )
        return True


def _restore_user_record(payload: dict[str, Any]) -> str:
    """Rehydrate a user into the in-memory store from a verified sync payload.

    Returns "restored" when the record was recreated, "exists" if the store
    already holds the user, or "invalid" if the payload lacks required fields.
    """
    global _USER_ID_SEQ

    username = str(payload.get("username", "")).strip()
    email = str(payload.get("email", "")).strip()
    password_hash = str(payload.get("password_hash", "")).strip()
    if not username or not email or not password_hash:
        return "invalid"

    with _DB_LOCK:
        if username in _USERS:
            return "exists"

        try:
            record_id = int(payload.get("id") or 0)
        except (TypeError, ValueError):
            record_id = 0
        if record_id <= 0:
            record_id = _USER_ID_SEQ + 1

        try:
            created_at = float(payload.get("created_at") or _now())
        except (TypeError, ValueError):
            created_at = _now()

        try:
            setup_completed = int(payload.get("setup_completed") or 0)
        except (TypeError, ValueError):
            setup_completed = 0

        public_key_id = payload.get("public_key_id")

        _USERS[username] = UserRecord(
            id=record_id,
            username=username,
            email=email,
            password_hash=password_hash,
            salt=str(payload.get("salt", "")),
            created_at=created_at,
            privacy_mode=str(payload.get("privacy_mode") or "public"),
            public_key_id=public_key_id if public_key_id else None,
            setup_completed=setup_completed,
        )
        if record_id > _USER_ID_SEQ:
            _USER_ID_SEQ = record_id
        return "restored"


def _update_user_privacy_mode(username: str, mode: str, key_id: str) -> dict[str, Any] | None:
    with _DB_LOCK:
        record = _USERS.get(username)
        if record is None:
            return None

        existing_key = record.public_key_id
        final_key = existing_key if existing_key else key_id

        record.privacy_mode = mode
        record.public_key_id = final_key
        record.setup_completed = 1

        return {
            "id": record.id,
            "username": record.username,
            "email": record.email,
            "privacy_mode": record.privacy_mode,
            "public_key_id": record.public_key_id,
            "setup_completed": record.setup_completed,
        }


@app.after_request
def apply_security_headers(response):
    csp_nonce = getattr(g, "csp_nonce", None)
    if csp_nonce:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{csp_nonce}'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self';"
        )
    else:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self';"
        )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


@app.route("/", methods=["GET"])
def index_page():
    return send_from_directory(str(BASE_DIR), "index.html")


@app.route("/otp", methods=["GET"])
def otp_page():
    return send_from_directory(str(BASE_DIR), "otp.html")


@app.route("/signup", methods=["GET"])
def signup_page():
    return send_from_directory(str(BASE_DIR), "signup.html")


@app.route("/dashboard", methods=["GET"])
def dashboard_page():
    g.csp_nonce = secrets.token_urlsafe(24)
    return render_template("dashboard.html", csp_nonce=g.csp_nonce)


@app.route("/api/auth/signup", methods=["POST"])
def api_signup():
    if not request.is_json:
        return _json_error("Content-Type must be application/json", 400, "bad_request")

    data = request.get_json() or {}
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password_hash = data.get("password_hash", "").strip()
    confirm_password_hash = data.get("confirm_password_hash", "").strip()

    if not username or not email or not password_hash or not confirm_password_hash:
        return _json_error("All registration fields are required.", 400, "missing_fields")

    if password_hash != confirm_password_hash:
        return _json_error("Password hashes do not match initialization targets.", 400, "invalid_payload")

    success = _insert_user(username, email, password_hash)
    if not success:
        return _json_error("Username is already bound to another cryptographic instance.", 409, "identity_conflict")

    return jsonify(
        {
            "status": "created",
            "message": "Cryptographic record stored.",
            "sync_token": _sync_token_for_user(username),
        }
    ), 201


@app.route("/api/auth/sync-restore", methods=["POST"])
def api_sync_restore():
    if not request.is_json:
        return _json_error("Content-Type must be application/json", 400, "bad_request")

    data = request.get_json() or {}
    sync_token = data.get("sync_token", "").strip()
    if not sync_token:
        return _json_error("Sync token missing.", 400, "missing_fields")

    payload = _verify_sync_token(sync_token)
    if payload is None:
        return _json_error("Sync token is invalid or tampered.", 401, "invalid_sync_token")

    result = _restore_user_record(payload)
    if result == "invalid":
        return _json_error("Sync token payload is incomplete.", 400, "invalid_payload")

    return jsonify({"status": result, "username": str(payload.get("username", ""))})


@app.route("/api/auth/step1", methods=["POST"])
def api_login_step1():
    if not request.is_json:
        return _json_error("Content-Type must be application/json", 400, "bad_request")

    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password_hash = data.get("password_hash", "").strip()

    if not username or not password_hash:
        return _json_error("Authentication tokens missing.", 400, "missing_fields")

    user = _query_user(username)
    if user is None:
        return _json_error("Identity not verified in network storage.", 401, "unauthorized")

    if not hmac.compare_digest(user["password_hash"], password_hash):
        return _json_error("Identity not verified in network storage.", 401, "unauthorized")

    session_obj = AuthSession(
        username=username,
        password_hash=password_hash,
        otp_code="",
        email=user["email"],
        channel="gmail",
    )
    try:
        _send_otp_email(session_obj)
    except SMTPNotConfiguredError:
        return _json_error(
            "Email services are configuring. Please try again shortly.",
            503,
            "email_unconfigured",
        )
    except Exception:
        return _json_error(
            "OTP email delivery failed. Please try again.",
            503,
            "email_delivery_failed",
        )

    tx_token = _generate_tx_token()
    _add_auth_session(tx_token, session_obj)

    print("--- SECURITY CHANNEL EMULATION ---")
    print(f"Target Identity: {username} ({user['email']})")
    print("Channel: Gmail Routing Framework")
    print("Dispatched Verification OTP: sent via Gmail SMTP")
    print("----------------------------------")

    return jsonify(
        {
            "status": "handshake_started",
            "tx_token": tx_token,
            "channel": "gmail",
            "message": "OTP sent to your registered Gmail address.",
            "email_hint": _mask_email(user["email"]),
        }
    )


def _resend_email_otp(tx_token: str) -> tuple[Any, int]:
    _, session = _get_auth_session(tx_token)
    if session is None:
        return _json_error("Invalid context transaction.", 401, "session_expired")

    if _session_expired(session):
        _purge_session(tx_token)
        return _json_error("Handshake expired. Restart authorization.", 401, "session_expired")

    try:
        _send_otp_email(session)
    except SMTPNotConfiguredError:
        return _json_error(
            "Email services are configuring. Please try again shortly.",
            503,
            "email_unconfigured",
        )
    except Exception:
        return _json_error(
            "OTP email delivery failed. Please try again.",
            503,
            "email_delivery_failed",
        )

    return jsonify(
        {
            "status": "resent",
            "channel": "gmail",
            "message": "A fresh OTP was sent to your Gmail address.",
            "email_hint": _mask_email(session.email),
        }
    )


@app.route("/api/auth/get-otp", methods=["POST"])
def api_get_otp():
    if not request.is_json:
        return _json_error("Content-Type must be application/json", 400, "bad_request")

    data = request.get_json() or {}
    tx_token = data.get("tx_token", "").strip()
    if not tx_token:
        return _json_error("Required verification context missing.", 400, "missing_fields")
    return _resend_email_otp(tx_token)


@app.route("/api/auth/resend-otp", methods=["POST"])
def api_resend_otp():
    if not request.is_json:
        return _json_error("Content-Type must be application/json", 400, "bad_request")

    data = request.get_json() or {}
    tx_token = data.get("tx_token", "").strip()
    if not tx_token:
        return _json_error("Required verification context missing.", 400, "missing_fields")
    return _resend_email_otp(tx_token)


@app.route("/api/auth/resend-whatsapp", methods=["POST"])
def api_resend_whatsapp():
    return _json_error("WhatsApp routing is disabled. Use Gmail delivery.", 410, "unsupported_channel")


@app.route("/api/auth/verify", methods=["POST"])
def api_verify():
    if not request.is_json:
        return _json_error("Content-Type must be application/json", 400, "bad_request")

    data = request.get_json() or {}
    tx_token = data.get("tx_token", "").strip()
    otp_code = data.get("otp_code", "").strip()

    _, session = _get_auth_session(tx_token)
    if session is None:
        return _json_error("Invalid context transaction.", 401, "session_expired")

    if _session_expired(session):
        _purge_session(tx_token)
        return _json_error("Session expired. Please restart the handshake.", 401, "session_expired")

    if session.failed_attempts >= MAX_FAILED_ATTEMPTS:
        _purge_session(tx_token)
        return _json_error("Too many failed attempts.", 429, "rate_limited")

    if not hmac.compare_digest(session.otp_code, otp_code):
        session.failed_attempts += 1
        if session.failed_attempts >= MAX_FAILED_ATTEMPTS:
            _purge_session(tx_token)
            return _json_error("Too many failed attempts.", 429, "rate_limited")

        return _json_error("Invalid OTP.", 401, "invalid_otp")

    dashboard_token = _generate_dashboard_token()
    dash_session = DashboardSession(username=session.username)
    _add_dashboard_session(dashboard_token, dash_session)

    user_data = _query_user(session.username)
    setup_completed = bool(user_data["setup_completed"]) if user_data else False

    dashboard_payload = {
        "clearance": "L3-Active",
        "node": "Python-Mesh-01",
        "dashboard_token": dashboard_token,
        "setup_completed": setup_completed,
    }
    _purge_session(tx_token)

    return jsonify(
        {
            "status": "verified",
            "dashboard_payload": dashboard_payload,
        }
    )


@app.route("/api/auth/save-mode", methods=["POST"])
def api_save_mode():
    if not request.is_json:
        return _json_error("Content-Type must be application/json", 400, "bad_request")

    data = request.get_json() or {}
    dashboard_token = data.get("dashboard_token", "").strip()
    privacy_mode_value = (data.get("mode") or data.get("privacy_mode") or "").strip()

    if not dashboard_token or not privacy_mode_value:
        return _json_error("Required operational attributes missing.", 400, "missing_fields")

    normalized_mode = privacy_mode_value.strip().lower()
    if normalized_mode not in PRIVACY_MODES:
        return _json_error("Unsupported privacy mode.", 400, "bad_request")

    _, session = _get_dashboard_session(dashboard_token)
    if session is None:
        return _json_error("Dashboard session expired or unknown.", 401, "session_expired")

    public_key_id = _generate_public_key_id(session.username)
    user = _update_user_privacy_mode(session.username, normalized_mode, public_key_id)
    if user is None:
        return _json_error("User account not found.", 404, "not_found")

    return jsonify(
        {
            "status": "ok",
            "username": session.username,
            "privacy_mode": normalized_mode,
            "privacy_mode_label": PRIVACY_MODES[normalized_mode],
            "public_key_id": user["public_key_id"] or public_key_id,
            "setup_completed": bool(user["setup_completed"]),
            "sync_token": _sync_token_for_user(session.username),
        }
    )


@app.route("/api/auth/user-details", methods=["POST"])
def api_user_details():
    if not request.is_json:
        return _json_error("Content-Type must be application/json", 400, "bad_request")
        
    data = request.get_json() or {}
    dashboard_token = data.get("dashboard_token", "").strip()
    
    _, session = _get_dashboard_session(dashboard_token)
    if session is None:
        return _json_error("Invalid session.", 401, "session_expired")
        
    user = _query_user(session.username)
    if not user:
        return _json_error("User not found.", 404, "not_found")
        
    return jsonify({
        "username": user["username"],
        "privacy_mode": user["privacy_mode"],
        "privacy_mode_label": PRIVACY_MODES.get(user["privacy_mode"], "Public Node"),
        "public_key_id": user["public_key_id"] or "Not Generated",
        "setup_completed": bool(user["setup_completed"])
    })


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


_init_db()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Trust Network App")
    parser.add_argument(
        "--reset-db",
        action="store_true",
        help="Delete all stored users from the local SQLite database and exit.",
    )
    args = parser.parse_args()

    if args.reset_db:
        with _DB_LOCK:
            _USERS.clear()
        print("In-memory user store reset successfully.")
        sys.exit(0)

    app.run(host="127.0.0.1", port=5000, debug=True)
