"""
Intentionally vulnerable demo app for testing a vulnerability scanner.

WARNING: This app contains DELIBERATE security vulnerabilities.
Do NOT deploy it anywhere public. Local scanning/testing only.
"""

import re
import sqlite3
import subprocess
import functools
import os

from flask import Flask, request, render_template_string, g

app = Flask(__name__)

DB_PATH = "users.db"

# FIXED: Hardcoded secret / credentials (scanners flag hardcoded secrets)
# Secrets are now loaded securely from environment variables.
SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
app.config["SECRET_KEY"] = SECRET_KEY


# Defense-in-depth: set a Content-Security-Policy header on all responses
# to mitigate reflected XSS even if a template escaping issue is reintroduced.
@app.after_request
def set_csp(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    return response


# FIXED: Missing Authentication and Authorization on All Endpoints
# Added an auth_required decorator using HTTP Basic Auth to enforce
# authentication on all routes.
def auth_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != "admin" or auth.password != ADMIN_PASSWORD:
            return ("Unauthorized", 401, {"WWW-Authenticate": "Basic realm='Login Required'"})
        return f(*args, **kwargs)
    return decorated


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
@auth_required
def index():
    return (
        "<h1>Vulnerable Demo App</h1>"
        "<ul>"
        "<li><a href='/search?username=alice'>User search (SQL injection)</a></li>"
        "<li><a href='/greet?name=World'>Greeting (reflected XSS)</a></li>"
        "<li><a href='/ping?host=127.0.0.1'>Ping (command injection)</a></li>"
        "</ul>"
    )


# FIXED: SQL Injection — user input is now passed as a parameterised query
# placeholder instead of being concatenated into the SQL string.
@app.route("/search")
@auth_required
def search():
    username = request.args.get("username", "")
    db = get_db()
    cur = db.cursor()
    # Use a placeholder (?) and pass username as a parameter to prevent SQL injection.
    query = "SELECT id, username, email FROM users WHERE username LIKE ? ORDER BY username"
    try:
        cur.execute(query, (username,))
        rows = cur.fetchall()
    except Exception as e:
        return f"Query error: {e}", 500
    return {"query": query, "results": rows}


# FIXED: Server-Side Template Injection and Reflected XSS — untrusted input is
# now passed as a Jinja2 template variable so that auto-escaping is applied.
# String concatenation into the template source has been removed, preventing
# evaluation of Jinja2 expressions (SSTI) and raw HTML/JS injection (XSS).
# A CSP header (see set_csp above) is added as defense-in-depth.
@app.route("/greet")
@auth_required
def greet():
    name = request.args.get("name", "")
    template = "<h1>Welcome, {{ name }}!</h1>"
    return render_template_string(template, name=name)


# FIXED: OS Command Injection — validate host and use shell=False with list args.
@app.route("/ping")
@auth_required
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Validate host: only alphanumeric, dots, and hyphens allowed; max 255 chars.
    if not re.match(r"^[a-zA-Z0-9.\-]+$", host) or len(host) > 255:
        return "Invalid host", 400
    try:
        output = subprocess.check_output(
            ["ping", "-c", "2", host],
            shell=False,
            stderr=subprocess.STDOUT,
            timeout=5,
        )
        return "<pre>" + output.decode(errors="replace") + "</pre>"
    except subprocess.TimeoutExpired:
        return "Ping timed out", 504
    except subprocess.CalledProcessError as e:
        return "<pre>" + e.output.decode(errors="replace") + "</pre>", 500


if __name__ == "__main__":
    init_db()
    # FIXED: Debug mode disabled by default; only enabled if FLASK_DEBUG=true env var is set.
    # This prevents exposure of the interactive debugger to remote users in production.
    debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    app.config['DEBUG'] = debug_mode
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)
