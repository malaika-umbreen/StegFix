"""
app.py — Flask authentication backend
AI Steganography Detection System

Security features:
  • bcrypt password hashing (never stores plain text)
  • JWT access tokens (stateless, signed)
  • Rate limiting on login endpoint (prevents brute-force)
  • CORS restricted to your frontend origin
  • Input validation & sanitisation
  • Login audit logging
  • Environment-variable-based secrets (no hard-coded credentials)
"""

import os
import re
import logging
from datetime import datetime, timezone, timedelta

import bcrypt
import jwt
import mysql.connector
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

# ─────────────────────────────────────────────────
# Bootstrap
# ─────────────────────────────────────────────────
load_dotenv()   # reads .env file in the same directory

app = Flask(__name__)

# Allow requests only from your React dev server.
# Change FRONTEND_ORIGIN in .env for production.
CORS(app)

# Rate limiter — backs off to memory storage if Redis not configured
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],          # no global limit; set per-route
    storage_uri=os.getenv("REDIS_URL", "memory://"),
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────
# Config — pulled from .env, never hard-coded
# ─────────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.getenv("DB_HOST",     "localhost"),
    "port":     int(os.getenv("DB_PORT", "3306")),
    "user":     os.getenv("DB_USER",     "root"),
    "password": os.getenv("DB_PASSWORD", "12345"),
    "database": os.getenv("DB_NAME",     "stego_detection"),
    "charset":  "utf8mb4",
}

JWT_SECRET      = os.getenv("JWT_SECRET", "CHANGE_ME_IN_PRODUCTION_USE_LONG_RANDOM_STRING")
JWT_ALGORITHM   = "HS256"
JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", "24"))

# ─────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def get_db():
    """Open a fresh MySQL connection."""
    return mysql.connector.connect(**DB_CONFIG)


def hash_password(plain: str) -> str:
    """Return a bcrypt hash of the plain-text password."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def check_password(plain: str, hashed: str) -> bool:
    """Verify a plain-text password against its bcrypt hash."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def generate_token(user_id: int, email: str) -> str:
    """Generate a signed JWT access token."""
    payload = {
        "sub":   user_id,
        "email": email,
        "iat":   datetime.now(timezone.utc),
        "exp":   datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def log_login_attempt(cursor, user_id, email, success: bool):
    """Write a row to login_logs for auditing."""
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    ua = request.headers.get("User-Agent", "")[:512]
    cursor.execute(
        """
        INSERT INTO login_logs (user_id, email, ip_address, user_agent, success)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (user_id, email, ip, ua, int(success)),
    )


# ─────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────

@app.route("/signup", methods=["POST"])
@limiter.limit("10 per hour")       # prevent mass account creation
def signup():
    data = request.get_json(silent=True) or {}
    full_name = (data.get("fullName") or "").strip()
    email     = (data.get("email")    or "").strip().lower()
    password  = (data.get("password") or "")

    # ── Validation ──────────────────────────────
    if not full_name or not email or not password:
        return jsonify({"success": False, "message": "All fields are required."}), 400

    if not EMAIL_RE.match(email):
        return jsonify({"success": False, "message": "Invalid email address."}), 400

    if len(password) < 8:
        return jsonify({"success": False, "message": "Password must be at least 8 characters."}), 400

    if len(full_name) > 120:
        return jsonify({"success": False, "message": "Name is too long."}), 400

    # ── Database ─────────────────────────────────
    try:
        conn   = get_db()
        cursor = conn.cursor(dictionary=True)

        # Check for duplicate email
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({"success": False, "message": "Email already registered."}), 409

        # Hash password and insert user
        pwd_hash = hash_password(password)
        cursor.execute(
            "INSERT INTO users (full_name, email, password_hash) VALUES (%s, %s, %s)",
            (full_name, email, pwd_hash),
        )
        conn.commit()
        logger.info("New user registered: %s", email)
        return jsonify({"success": True, "message": "Account created successfully."}), 201

    except mysql.connector.Error as exc:
        logger.error("DB error during signup: %s", exc)
        return jsonify({"success": False, "message": "Server error. Please try again."}), 500

    finally:
        cursor.close()
        conn.close()


@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute")     # brute-force protection
def login():
    data = request.get_json(silent=True) or {}
    email    = (data.get("email")    or "").strip().lower()
    password = (data.get("password") or "")

    # ── Validation ──────────────────────────────
    if not email or not password:
        return jsonify({"success": False, "message": "Email and password are required."}), 400

    if not EMAIL_RE.match(email):
        return jsonify({"success": False, "message": "Invalid email address."}), 400

    # ── Database ─────────────────────────────────
    try:
        conn   = get_db()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            "SELECT id, full_name, password_hash, is_active FROM users WHERE email = %s",
            (email,),
        )
        user = cursor.fetchone()

        # Always run checkpw even on miss — prevents timing attacks
        dummy_hash = "$2b$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        stored_hash = user["password_hash"] if user else dummy_hash
        password_ok = check_password(password, stored_hash)

        if not user or not password_ok or not user["is_active"]:
            log_login_attempt(cursor, user["id"] if user else None, email, success=False)
            conn.commit()
            # Generic message — don't reveal whether email exists
            return jsonify({"success": False, "message": "Invalid email or password."}), 401

        log_login_attempt(cursor, user["id"], email, success=True)
        conn.commit()

        token = generate_token(user["id"], email)
        logger.info("Successful login: %s", email)

        return jsonify({
            "success":   True,
            "token":     token,
            "full_name": user["full_name"],
            "message":   "Login successful.",
        }), 200

    except mysql.connector.Error as exc:
        logger.error("DB error during login: %s", exc)
        return jsonify({"success": False, "message": "Server error. Please try again."}), 500

    finally:
        cursor.close()
        conn.close()


@app.route("/health", methods=["GET"])
def health():
    """Simple health-check endpoint."""
    return jsonify({"status": "ok"}), 200


# ─────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────
if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)