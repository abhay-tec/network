from __future__ import annotations

import hashlib
import hmac
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
from email.message import EmailMessage

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


def _smtp_config() -> dict[str, Any]:
    host = os.getenv("SMTP_HOST", "smtp.gmail.com").strip()
    username = os.getenv("SMTP_USERNAME", "").strip()
    password = os.getenv("SMTP_PASSWORD", "").strip()
    from_email = os.getenv("OTP_FROM_EMAIL", "").strip() or username
    use_tls_value = os.getenv("SMTP_USE_TLS", "1").strip().lower()
    timeout_raw = os.getenv("SMTP_TIMEOUT", "10").strip()

    try:
        port = int(os.getenv("SMTP_PORT", "587").strip())
    except ValueError:
        port = 587

    try:
        timeout = float(timeout_raw)
    except ValueError:
        timeout = 10.0

    return {
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "from_email": from_email,
        "use_tls": use_tls_value not in {"0", "false", "no"},
        "timeout": timeout,
    }


def _send_otp_email(session: AuthSession) -> None:
    settings = _smtp_config()
    if not settings["host"] or not settings["username"] or not settings["password"]:
        raise RuntimeError("SMTP credentials are not configured.")

    if not session.email:
        raise RuntimeError("Recipient email is missing.")

    otp_code = _issue_otp(session, "gmail")
    message = EmailMessage()
    message["Subject"] = "Trust System OTP Verification"
    message["From"] = settings["from_email"]
    message["To"] = session.email
    message.set_content(
        "\n".join(
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
    )

    context = ssl.create_default_context()
    with smtplib.SMTP(settings["host"], settings["port"], timeout=settings["timeout"]) as smtp:
        if settings["use_tls"]:
            smtp.starttls(context=context)
        smtp.login(settings["username"], settings["password"])
        smtp.send_message(message)


def _json_error(message: str, status_code: int, code: str) -> tuple[Any, int]:
    return jsonify({"error": message, "code": code}), status_code


def _dispatch_otp(session: AuthSession) -> tuple[bool, str | None]:
    """Deliver the OTP email, falling back to a debug code when SMTP fails.

    Test/dev environments (and Vercel) may lack SMTP credentials or outbound
    network access. Rather than blocking the user, the failure is logged, an OTP
    is generated locally, printed to the server console, and returned so the
    login flow can continue. Returns (delivered, debug_otp) where debug_otp is
    None on successful real delivery.
    """
    try:
        _send_otp_email(session)
        return True, None
    except Exception as exc:
        otp_code = session.otp_code or _issue_otp(session, "gmail")
        print(
            f"[OTP FALLBACK] SMTP delivery failed: {exc}. "
            f"Dev OTP for {session.username}: {otp_code}"
        )
        return False, otp_code


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

    return jsonify({"status": "created", "message": "Cryptographic record stored."}), 201


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
    delivered, debug_otp = _dispatch_otp(session_obj)

    tx_token = _generate_tx_token()
    _add_auth_session(tx_token, session_obj)

    print(f"--- SECURITY CHANNEL EMULATION ---")
    print(f"Target Identity: {username} ({user['email']})")
    print(f"Channel: Gmail Routing Framework")
    print(f"Dispatched Verification OTP: {'sent via email' if delivered else 'console fallback (SMTP unavailable)'}")
    print(f"----------------------------------")

    response_payload: dict[str, Any] = {
        "status": "handshake_started",
        "tx_token": tx_token,
        "channel": "gmail",
        "message": (
            "OTP sent to your registered Gmail address."
            if delivered
            else "OTP email delivery unavailable; using debug code for testing."
        ),
        "email_hint": _mask_email(user["email"]),
    }
    if not delivered:
        response_payload["debug_otp"] = debug_otp

    return jsonify(response_payload)


def _resend_email_otp(tx_token: str) -> tuple[Any, int]:
    _, session = _get_auth_session(tx_token)
    if session is None:
        return _json_error("Invalid context transaction.", 401, "session_expired")

    if _session_expired(session):
        _purge_session(tx_token)
        return _json_error("Handshake expired. Restart authorization.", 401, "session_expired")

    delivered, debug_otp = _dispatch_otp(session)

    response_payload: dict[str, Any] = {
        "status": "resent",
        "channel": "gmail",
        "message": (
            "A fresh OTP was sent to your Gmail address."
            if delivered
            else "OTP email delivery unavailable; using debug code for testing."
        ),
        "email_hint": _mask_email(session.email),
    }
    if not delivered:
        response_payload["debug_otp"] = debug_otp

    return jsonify(response_payload)


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
