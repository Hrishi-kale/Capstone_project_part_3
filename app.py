"""
Flask REST API — remediated version.

Fixes applied relative to the original scenario:
- SQL Injection: all queries use parameterized placeholders, no string
  concatenation of user input.
- Broken Access Control: /admin now requires a valid API key via the
  require_auth middleware.
- Password storage: bcrypt with a unique salt per password (see
  hash_password.py), replacing unsalted MD5.
- Secrets: loaded from environment variables via python-dotenv, not
  hardcoded in source.
"""

import os
import sqlite3
from functools import wraps

from flask import Flask, request, jsonify
from dotenv import load_dotenv

from hash_password import hash_password, verify_password

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")

ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY")
DB_PATH = os.environ.get("DB_PATH", "app.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def require_auth(f):
    """Authentication middleware — fixes Broken Access Control on /admin."""

    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key")
        if not api_key or api_key != ADMIN_API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)

    return decorated


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    password_hash = hash_password(password)

    conn = get_db()
    try:
        # Parameterized query — fixes SQL Injection; user input is bound as
        # a value, never interpolated into the query string.
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "username already exists"}), 409
    finally:
        conn.close()

    return jsonify({"message": "user registered"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    conn = get_db()
    # Parameterized query — fixes SQL Injection
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    if row is None or not verify_password(password, row["password_hash"]):
        return jsonify({"error": "invalid credentials"}), 401

    return jsonify({"message": "login successful"}), 200


@app.route("/admin", methods=["GET"])
@require_auth
def admin():
    # Fixes Broken Access Control — unreachable without a valid X-API-Key header
    conn = get_db()
    users = conn.execute("SELECT id, username FROM users").fetchall()
    conn.close()
    return jsonify({"users": [dict(u) for u in users]}), 200


if __name__ == "__main__":
    init_db()
    app.run(debug=False)
