import base64
import hashlib
import hmac
import io
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from html import escape

import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pwdlib import PasswordHash


DB_PATH = os.getenv("DB_PATH", "otp_auth.db")
FERNET_KEY = os.getenv("FERNET_KEY")

if not FERNET_KEY:
    raise RuntimeError(
        "FERNET_KEY is required. Generate one with:\n"
        "python -c \"from cryptography.fernet import Fernet; "
        "print(Fernet.generate_key().decode())\""
    )

cipher = Fernet(FERNET_KEY.encode())
password_hasher = PasswordHash.recommended()
app = FastAPI(title="OTP Login Demo")

COOKIE_NAME = "otp_session"
SESSION_LIFETIME = 60 * 60 * 24 * 7  # 7 days
OTP_INTERVAL = 30
ISSUER = "Laptop OTP Login"

# Public deployment settings.
# PUBLIC_URL is optional; when set, successful gate verification redirects there.
PUBLIC_URL = os.getenv("PUBLIC_URL", "").rstrip("/")

# Simple in-process rate limiter for development.
# For production/multiple workers, use a shared store such as Redis.
login_attempts = defaultdict(deque)
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 10 * 60


@contextmanager
def db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def initialize_database():
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                encrypted_totp_secret TEXT,
                otp_enabled INTEGER NOT NULL DEFAULT 0,
                last_totp_counter INTEGER NOT NULL DEFAULT -1
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_expiry
                ON sessions(expires_at);
            """
        )


initialize_database()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(user_id=None):
    raw_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(24)
    expires_at = int(time.time()) + SESSION_LIFETIME

    with db() as conn:
        conn.execute(
            """
            INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (hash_token(raw_token), user_id, csrf_token, expires_at),
        )

    return raw_token, csrf_token


def get_session(request: Request):
    raw_token = request.cookies.get(COOKIE_NAME)

    if raw_token:
        with db() as conn:
            row = conn.execute(
                """
                SELECT s.*, u.username, u.otp_enabled
                FROM sessions s
                LEFT JOIN users u ON u.id = s.user_id
                WHERE s.token_hash = ? AND s.expires_at > ?
                """,
                (hash_token(raw_token), int(time.time())),
            ).fetchone()

        if row:
            return dict(row), raw_token, False

    raw_token, csrf_token = create_session()
    return {
        "token_hash": hash_token(raw_token),
        "user_id": None,
        "csrf_token": csrf_token,
        "username": None,
        "otp_enabled": 0,
    }, raw_token, True


def set_session_cookie(response, raw_token):
    response.set_cookie(
        COOKIE_NAME,
        raw_token,
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "0") == "1",
        samesite="strict",
        max_age=SESSION_LIFETIME,
        path="/",
    )


def clear_old_session(session):
    if session and session.get("token_hash"):
        with db() as conn:
            conn.execute(
                "DELETE FROM sessions WHERE token_hash = ?",
                (session["token_hash"],),
            )


def page(title, body):
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 560px; margin: 40px auto;
           padding: 0 18px; line-height: 1.5; }}
    input {{ display: block; box-sizing: border-box; width: 100%; padding: 10px;
             margin: 6px 0 14px; }}
    button {{ padding: 10px 16px; cursor: pointer; }}
    .box {{ border: 1px solid #ddd; border-radius: 8px; padding: 18px; margin: 18px 0; }}
    .error {{ color: #a00; }}
    .muted {{ color: #555; }}
    img {{ max-width: 240px; }}
    code {{ overflow-wrap: anywhere; }}
  </style>
</head>
<body>
  <h1>{escape(title)}</h1>
  {body}
  <footer style="margin-top:32px;padding:16px 0;text-align:center;border-top:1px solid #eee;color:#666;font-size:14px;">Built by <strong>Mohamed Shaheem</strong></footer>
</body>
</html>"""


def response_with_session(html, raw_token, fresh, status_code=200):
    response = HTMLResponse(html, status_code=status_code)
    if fresh:
        set_session_cookie(response, raw_token)
    return response


def redirect_with_cookie(url, raw_token):
    response = RedirectResponse(url, status_code=303)
    set_session_cookie(response, raw_token)
    return response


def csrf_input(session):
    return (
        '<input type="hidden" name="csrf_token" value="'
        + escape(session["csrf_token"])
        + '">'
    )


def valid_csrf(form, session):
    supplied = str(form.get("csrf_token", ""))
    expected = str(session.get("csrf_token", ""))
    return hmac.compare_digest(supplied, expected)


def encrypt_secret(secret: str) -> str:
    return cipher.encrypt(secret.encode()).decode()


def decrypt_secret(encrypted_secret: str) -> str:
    return cipher.decrypt(encrypted_secret.encode()).decode()


def matching_totp_counter(secret: str, code: str, last_counter: int):
    """
    Return the matching TOTP time counter, or None.
    Checks the current 30-second interval and one interval either side.
    """
    if not re.fullmatch(r"\d{6}", code or ""):
        return None

    totp = pyotp.TOTP(secret, interval=OTP_INTERVAL)
    current_counter = int(time.time()) // OTP_INTERVAL

    for counter in (current_counter - 1, current_counter, current_counter + 1):
        if counter <= last_counter:
            continue

        expected = totp.at(counter * OTP_INTERVAL)
        if hmac.compare_digest(expected, code):
            return counter

    return None


def rate_limit_key(request, username):
    client_ip = request.client.host if request.client else "unknown"
    return f"{client_ip}:{username.lower()}"


def login_rate_limited(request, username):
    key = rate_limit_key(request, username)
    now = time.time()
    attempts = login_attempts[key]

    while attempts and now - attempts[0] > LOGIN_WINDOW_SECONDS:
        attempts.popleft()

    return len(attempts) >= MAX_LOGIN_ATTEMPTS


def record_failed_login(request, username):
    login_attempts[rate_limit_key(request, username)].append(time.time())


def login_form(session, error=""):
    error_html = f'<p class="error">{escape(error)}</p>' if error else ""
    body = f"""
      {error_html}
      <div class="box">
        <h2>Sign in</h2>
        <form method="post" action="/login">
          {csrf_input(session)}
          <label>Username
            <input name="username" autocomplete="username" required>
          </label>
          <label>Password
            <input name="password" type="password"
                   autocomplete="current-password" required>
          </label>
          <label>Six-digit OTP
            <input name="otp" inputmode="numeric" pattern="[0-9]{{6}}"
                   maxlength="6" autocomplete="one-time-code" required>
          </label>
          <button type="submit">Sign in</button>
        </form>
        <p class="muted">You need an authenticator app and an enrolled OTP account.</p>
      </div>
      <div class="box">
        <h2>Create an account</h2>
        <p>Create an account, then set up OTP before signing in again.</p>
        <form method="post" action="/register">
          {csrf_input(session)}
          <label>Username
            <input name="username" autocomplete="username" required>
          </label>
          <label>Password (at least 12 characters)
            <input name="password" type="password"
                   autocomplete="new-password" minlength="12" required>
          </label>
          <button type="submit">Register</button>
        </form>
      </div>
    """
    return page("Laptop OTP Login", body)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    session, raw_token, fresh = get_session(request)

    if session.get("user_id"):
        target = "/dashboard" if session.get("otp_enabled") else "/setup"
        response = RedirectResponse(target, status_code=303)
        if fresh:
            set_session_cookie(response, raw_token)
        return response

    return response_with_session(login_form(session), raw_token, fresh)


@app.post("/register")
async def register(request: Request):
    session, raw_token, fresh = get_session(request)
    form = await request.form()

    if not valid_csrf(form, session):
        return response_with_session(
            login_form(session, "Invalid request. Refresh and try again."),
            raw_token,
            fresh,
            403,
        )

    username = str(form.get("username", "")).strip().lower()
    password = str(form.get("password", ""))

    if not re.fullmatch(r"[a-zA-Z0-9_.-]{3,40}", username):
        return response_with_session(
            login_form(session, "Username must be 3–40 letters, numbers, dots, dashes, or underscores."),
            raw_token,
            fresh,
            400,
        )

    if len(password) < 12:
        return response_with_session(
            login_form(session, "Password must be at least 12 characters."),
            raw_token,
            fresh,
            400,
        )

    try:
        password_hash = password_hasher.hash(password)
        with db() as conn:
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        return response_with_session(
            login_form(session, "Unable to create account with those details."),
            raw_token,
            fresh,
            400,
        )

    clear_old_session(session)
    new_token, _ = create_session(user_id)
    return redirect_with_cookie("/setup", new_token)


@app.post("/login")
async def login(request: Request):
    session, raw_token, fresh = get_session(request)
    form = await request.form()

    if not valid_csrf(form, session):
        return response_with_session(
            login_form(session, "Invalid request. Refresh and try again."),
            raw_token,
            fresh,
            403,
        )

    username = str(form.get("username", "")).strip().lower()
    password = str(form.get("password", ""))
    otp = str(form.get("otp", "")).strip()

    if login_rate_limited(request, username):
        return response_with_session(
            login_form(session, "Too many attempts. Try again later."),
            raw_token,
            fresh,
            429,
        )

    with db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    # Use the same generic error for unknown users and incorrect credentials.
    invalid_message = "Sign-in failed. Check your details and try again."

    if not user:
        record_failed_login(request, username)
        return response_with_session(login_form(session, invalid_message), raw_token, fresh, 401)

    try:
        password_ok = password_hasher.verify(password, user["password_hash"])
    except Exception:
        password_ok = False

    if not password_ok or not user["otp_enabled"] or not user["encrypted_totp_secret"]:
        record_failed_login(request, username)
        return response_with_session(login_form(session, invalid_message), raw_token, fresh, 401)

    try:
        secret = decrypt_secret(user["encrypted_totp_secret"])
    except (InvalidToken, ValueError):
        record_failed_login(request, username)
        return response_with_session(login_form(session, invalid_message), raw_token, fresh, 401)

    matched_counter = matching_totp_counter(
        secret,
        otp,
        user["last_totp_counter"],
    )

    if matched_counter is None:
        record_failed_login(request, username)
        return response_with_session(login_form(session, invalid_message), raw_token, fresh, 401)

    # Atomically prevent accepting the same time-step code more than once.
    with db() as conn:
        updated = conn.execute(
            """
            UPDATE users
            SET last_totp_counter = ?
            WHERE id = ? AND last_totp_counter < ? AND otp_enabled = 1
            """,
            (matched_counter, user["id"], matched_counter),
        ).rowcount

    if updated != 1:
        record_failed_login(request, username)
        return response_with_session(login_form(session, invalid_message), raw_token, fresh, 401)

    clear_old_session(session)
    new_token, _ = create_session(user["id"])
    login_attempts.pop(rate_limit_key(request, username), None)
    return redirect_with_cookie("/dashboard", new_token)


@app.get("/setup", response_class=HTMLResponse)
async def setup(request: Request):
    session, raw_token, fresh = get_session(request)

    if not session.get("user_id"):
        return redirect_with_cookie("/", raw_token)

    with db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()

    if user["otp_enabled"]:
        response = RedirectResponse("/dashboard", status_code=303)
        if fresh:
            set_session_cookie(response, raw_token)
        return response

    if not user["encrypted_totp_secret"]:
        secret = pyotp.random_base32()
        with db() as conn:
            conn.execute(
                "UPDATE users SET encrypted_totp_secret = ? WHERE id = ?",
                (encrypt_secret(secret), user["id"]),
            )
    else:
        secret = decrypt_secret(user["encrypted_totp_secret"])

    uri = pyotp.TOTP(secret, interval=OTP_INTERVAL).provisioning_uri(
        name=user["username"],
        issuer_name=ISSUER,
    )

    qr = qrcode.make(uri)
    image_buffer = io.BytesIO()
    qr.save(image_buffer, format="PNG")
    qr_base64 = base64.b64encode(image_buffer.getvalue()).decode()

    body = f"""
      <p>Scan this QR code using an authenticator app. Then enter the current
         six-digit code to confirm setup.</p>
      <div class="box">
        <img src="data:image/png;base64,{qr_base64}" alt="OTP setup QR code">
        <p>If you cannot scan it, enter this setup key manually:</p>
        <code>{escape(secret)}</code>
      </div>
      <form method="post" action="/setup">
        {csrf_input(session)}
        <label>Six-digit OTP
          <input name="otp" inputmode="numeric" pattern="[0-9]{{6}}"
                 maxlength="6" autocomplete="one-time-code" required>
        </label>
        <button type="submit">Confirm OTP setup</button>
      </form>
      <p class="muted">Keep the setup key private. Anyone with it can generate your codes.</p>
    """

    return response_with_session(page("Set up OTP", body), raw_token, fresh)


@app.post("/setup")
async def confirm_setup(request: Request):
    session, raw_token, fresh = get_session(request)

    if not session.get("user_id"):
        return redirect_with_cookie("/", raw_token)

    form = await request.form()
    if not valid_csrf(form, session):
        return response_with_session(
            page("Error", "<p>Invalid request. Refresh and try again.</p>"),
            raw_token,
            fresh,
            403,
        )

    otp = str(form.get("otp", "")).strip()

    with db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()

    if not user or not user["encrypted_totp_secret"]:
        return redirect_with_cookie("/setup", raw_token)

    secret = decrypt_secret(user["encrypted_totp_secret"])
    counter = matching_totp_counter(secret, otp, -1)

    if counter is None:
        body = f"""
          <p class="error">That code was not accepted. Check your phone's clock and try again.</p>
          <p><a href="/setup">Return to OTP setup</a></p>
        """
        return response_with_session(page("OTP setup", body), raw_token, fresh, 400)

    with db() as conn:
        conn.execute(
            """
            UPDATE users
            SET otp_enabled = 1, last_totp_counter = ?
            WHERE id = ?
            """,
            (counter, user["id"]),
        )

    return redirect_with_cookie("/dashboard", raw_token)



@app.post("/local-gate")
async def local_gate(request: Request):
    """
    API used by the Windows gate client.

    For public deployment, call this endpoint only over HTTPS.
    It accepts the same username/password/OTP credentials as the web login
    and returns a safe JSON response for the Windows client.
    """
    form = await request.form()
    username = str(form.get("username", "")).strip().lower()
    password = str(form.get("password", ""))
    otp = str(form.get("otp", "")).strip()

    if not username or not password or len(otp) != 6 or not otp.isdigit():
        return {"success": False, "message": "Invalid authentication details."}

    if login_rate_limited(request, username):
        return {"success": False, "message": "Too many attempts. Try again later."}

    with db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    invalid_message = "Authentication failed. Check your details and try again."

    if not user:
        record_failed_login(request, username)
        return {"success": False, "message": invalid_message}

    try:
        password_ok = password_hasher.verify(password, user["password_hash"])
    except Exception:
        password_ok = False

    if not password_ok or not user["otp_enabled"] or not user["encrypted_totp_secret"]:
        record_failed_login(request, username)
        return {"success": False, "message": invalid_message}

    try:
        secret = decrypt_secret(user["encrypted_totp_secret"])
    except (InvalidToken, ValueError):
        record_failed_login(request, username)
        return {"success": False, "message": invalid_message}

    matched_counter = matching_totp_counter(
        secret,
        otp,
        user["last_totp_counter"],
    )

    if matched_counter is None:
        record_failed_login(request, username)
        return {"success": False, "message": invalid_message}

    # Prevent reusing the same OTP time-step.
    with db() as conn:
        updated = conn.execute(
            """
            UPDATE users
            SET last_totp_counter = ?
            WHERE id = ? AND last_totp_counter < ? AND otp_enabled = 1
            """,
            (matched_counter, user["id"], matched_counter),
        ).rowcount

    if updated != 1:
        record_failed_login(request, username)
        return {"success": False, "message": invalid_message}

    login_attempts.pop(rate_limit_key(request, username), None)

    dashboard_url = (
        f"{PUBLIC_URL}/dashboard"
        if PUBLIC_URL
        else str(request.url_for("dashboard"))
    )

    return {
        "success": True,
        "message": "Authentication successful.",
        "url": dashboard_url,
    }


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    session, raw_token, fresh = get_session(request)

    if not session.get("user_id"):
        return redirect_with_cookie("/", raw_token)

    with db() as conn:
        user = conn.execute(
            "SELECT username, otp_enabled FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()

    if not user:
        return redirect_with_cookie("/", raw_token)

    if not user["otp_enabled"]:
        return redirect_with_cookie("/setup", raw_token)

    body = f"""
      <p>Signed in as <strong>{escape(user["username"])}</strong>.</p>
      <p>OTP authentication is enabled.</p>

      <div class="box">
        <h2>Reset OTP</h2>
        <p>To replace your authenticator setup, verify your password and current OTP.
           You will then need to scan a new QR code.</p>
        <form method="post" action="/reset-otp">
          {csrf_input(session)}
          <label>Password
            <input name="password" type="password"
                   autocomplete="current-password" required>
          </label>
          <label>Current six-digit OTP
            <input name="otp" inputmode="numeric" pattern="[0-9]{{6}}"
                   maxlength="6" autocomplete="one-time-code" required>
          </label>
          <button type="submit">Reset OTP setup</button>
        </form>
      </div>

      <form method="post" action="/logout">
        {csrf_input(session)}
        <button type="submit">Sign out</button>
      </form>
    """

    return response_with_session(page("Dashboard", body), raw_token, fresh)


@app.post("/reset-otp")
async def reset_otp(request: Request):
    session, raw_token, fresh = get_session(request)

    if not session.get("user_id"):
        return redirect_with_cookie("/", raw_token)

    form = await request.form()
    if not valid_csrf(form, session):
        return response_with_session(
            page("Error", "<p>Invalid request. Refresh and try again.</p>"),
            raw_token,
            fresh,
            403,
        )

    password = str(form.get("password", ""))
    otp = str(form.get("otp", "")).strip()

    with db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()

    if not user:
        return redirect_with_cookie("/", raw_token)

    try:
        password_ok = password_hasher.verify(password, user["password_hash"])
        secret = decrypt_secret(user["encrypted_totp_secret"])
    except Exception:
        password_ok = False
        secret = ""

    counter = (
        matching_totp_counter(secret, otp, user["last_totp_counter"])
        if password_ok and secret
        else None
    )

    if not password_ok or counter is None:
        body = '<p class="error">Unable to reset OTP. Check your password and current code.</p><p><a href="/dashboard">Back</a></p>'
        return response_with_session(page("Reset OTP", body), raw_token, fresh, 400)

    new_secret = pyotp.random_base32()

    with db() as conn:
        conn.execute(
            """
            UPDATE users
            SET encrypted_totp_secret = ?, otp_enabled = 0, last_totp_counter = -1
            WHERE id = ?
            """,
            (encrypt_secret(new_secret), user["id"]),
        )

    return redirect_with_cookie("/setup", raw_token)


@app.post("/logout")
async def logout(request: Request):
    session, raw_token, fresh = get_session(request)
    form = await request.form()

    if not valid_csrf(form, session):
        return response_with_session(
            page("Error", "<p>Invalid request. Refresh and try again.</p>"),
            raw_token,
            fresh,
            403,
        )

    clear_old_session(session)
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(COOKIE_NAME, path="/")
    return response
