"""
Intentionally vulnerable demo app for testing a vulnerability scanner.

WARNING: This app contains DELIBERATE security vulnerabilities.
Do NOT deploy it anywhere public. Local scanning/testing only.
"""

import os
import re
import secrets
import sqlite3
import subprocess

from flask import Flask, request, render_template_string, g, escape

app = Flask(__name__)

DB_PATH = "users.db"

# FIXED: Load SECRET_KEY from environment variable instead of hardcoding.
# If FLASK_SECRET_KEY is not set, generate a cryptographically secure random key.
# Removed unused ADMIN_PASSWORD (dead hardcoded credential).
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)

app.config["SECRET_KEY"] = SECRET_KEY


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, email TEXT)"
    )
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO users (username, email) VALUES (?, ?)",
            [
                ("alice", "alice@example.com"),
                ("bob", "bob@example.com"),
                ("admin", "admin@example.com"),
            ],
        )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return (
        "<h1>Vulnerable Demo App</h1>"
        "<ul>"
        "<li><a href='/search?username=alice'>User search (SQL injection)</a></li>"
        "<li><a href='/greet?name=World'>Greeting (reflected XSS)</a></li>"
        "<li><a href='/ping?host=127.0.0.1'>Ping (command injection)</a></li>"
        "</ul>"
    )


# FIXED: SQL Injection vulnerability - now using parameterized queries.
@app.route("/search")
def search():
    username = request.args.get("username", "")
    db = get_db()
    cur = db.cursor()
    # SECURITY FIX: Use parameterized query with ? placeholder to prevent SQL injection.
    # This ensures user input is treated as a literal value rather than executable SQL code.
    query = "SELECT id, username, email FROM users WHERE username LIKE ? ORDER BY username"
    try:
        cur.execute(query, (username,))
        rows = cur.fetchall()
    except Exception:
        # SECURITY FIX: Do not expose raw exception messages to prevent information disclosure
        app.logger.exception("Database query failed")
        return {"error": "An internal error occurred."}, 500
    # SECURITY FIX: Remove raw query string from response to prevent query structure exposure
    return {"results": rows}


# FIXED: Pass user input as a template variable so Jinja2 auto-escaping
# treats it as literal text. This prevents both SSTI (template expressions
# are no longer interpreted) and reflected XSS (HTML/JS is escaped).
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string("<h1>Welcome, {{ name }}!</h1>", name=name)


# FIXED: OS Command Injection - replaced shell=True with shell=False and added input validation.
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # SECURITY FIX: Strict validation of host parameter to prevent command injection.
    # Only allows alphanumeric characters, dots, and hyphens (valid hostname characters).
    # RFC 1123 specifies max hostname length of 253 characters.
    if not re.match(r'^[a-zA-Z0-9.\\-]+$', host) or len(host) > 253:
        return "Invalid host", 400
    try:
        # SECURITY FIX: Use shell=False with list argument to prevent shell metacharacter injection.
        # Each argument is passed directly to ping without shell interpretation.
        output = subprocess.check_output(
            ["ping", "-c", "2", host],
            shell=False,
            stderr=subprocess.STDOUT,
            timeout=10
        )
    except subprocess.CalledProcessError as e:
        output = e.output
    except subprocess.TimeoutExpired:
        return "Ping timed out", 504
    # SECURITY FIX: HTML-escape command output to prevent reflected XSS.
    # Even with command injection fixes, error messages might contain
    # user-supplied input that could be interpreted as HTML/JS.
    return "<pre>" + escape(output.decode(errors="replace")) + "</pre>"


# SECURITY FIX: Global error handler to prevent stack trace leakage
@app.errorhandler(500)
def handle_500(e):
    app.logger.exception("Unhandled error")
    return {"error": "Internal server error"}, 500


if __name__ == "__main__":
    init_db()
    # SECURITY FIX: Use environment-based configuration for debug mode and host binding.
    # Defaults to localhost (127.0.0.1) and debug=False to prevent exposure of 
    # Werkzeug debugger and stack traces on all network interfaces.
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    host_addr = os.environ.get("HOST", "127.0.0.1")
    app.run(host=host_addr, port=5000, debug=debug_mode)