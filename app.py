"""
Intentionally vulnerable demo app for testing a vulnerability scanner.

WARNING: This app contains DELIBERATE security vulnerabilities.
Do NOT deploy it anywhere public. Local scanning/testing only.
"""

import os
import re
import socket
import sqlite3
import subprocess
import time
import functools

from flask import Flask, request, render_template_string, g, abort, session, redirect
from markupsafe import escape

app = Flask(__name__)

DB_PATH = "users.db"

# FIX #1: Load secrets from environment variables to prevent hardcoded credentials and session forgery.
SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
app.config["SECRET_KEY"] = SECRET_KEY

# FIX #7: Configure secure session cookie attributes.
# SESSION_COOKIE_SECURE ensures the cookie is only sent over HTTPS.
# SESSION_COOKIE_SAMESITE="Lax" mitigates CSRF by restricting cross-site transmission.
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# FIX #4: Whitelist of allowed hosts to prevent SSRF / network scanning.
# Only explicitly permitted external hosts may be pinged.
ALLOWED_PING_HOSTS = {
    "example.com",
    "8.8.8.8",
}

# Minimal in-memory rate limiting for the /ping endpoint.
_PING_RATE_LIMIT = {}
_PING_RATE_WINDOW = 60  # seconds
_PING_RATE_MAX = 10     # max requests per window per client


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# FIX #6: Add authentication / authorization for sensitive endpoints.
# login_required ensures a user is present in the request context (g.user);
# load_user populates g.user from the session on every request.
def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not g.get("user"):
            abort(401)
        return f(*args, **kwargs)
    return wrapper


@app.before_request
def load_user():
    g.user = session.get("user")


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
        "<li><a href='/ping?host=example.com'>Ping (restricted host allowlist)</a></li>"
        "</ul>"
    )


# Minimal login endpoint so the demo can obtain a session for protected routes.
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
            session["user"] = "admin"
            return redirect("/")
        return "Invalid credentials", 401
    return (
        "<form method='post'>"
        "<input name='password' placeholder='password'>"
        "<button type='submit'>Login</button>"
        "</form>"
    )


# FIX #2: SQL Injection mitigated by using parameterized queries instead of string concatenation.
# Additionally, the raw SQL query is no longer exposed in the response to avoid information leakage.
@app.route("/search")
@login_required
def search():
    username = request.args.get("username", "")
    db = get_db()
    cur = db.cursor()
    query = "SELECT id, username, email FROM users WHERE username LIKE ? ORDER BY username"
    try:
        cur.execute(query, (username,))
        rows = cur.fetchall()
    except Exception as e:
        return f"Query error: {e}", 500
    return {"results": rows}


# FIX #3: Reflected XSS and SSTI mitigated by passing user input as a Jinja2 template
# variable rather than concatenating it into the template string. Jinja2 auto-escapes
# template variables ({{ name }}) by default, preventing both HTML/script injection
# and Jinja2 expression evaluation (SSTI).
@app.route("/greet")
@login_required
def greet():
    name = request.args.get("name", "")
    return render_template_string("<h1>Welcome, {{ name }}!</h1>", name=name)


# FIX #4: SSRF / network scanning mitigated by:
#   - Enforcing a strict whitelist of allowed hosts (ALLOWED_PING_HOSTS).
#   - Avoiding system command invocation; using a socket-based check instead.
#   - Adding basic per-client rate limiting and request logging.
@app.route("/ping")
@login_required
def ping():
    host = request.args.get("host", "example.com")
    # Strict allowlist validation: only alphanumeric, dots, and hyphens.
    if not re.match(r'^[a-zA-Z0-9.\-]+$', host) or len(host) > 255:
        return "Invalid host", 400
    # Enforce whitelist to prevent SSRF / internal network scanning.
    if host not in ALLOWED_PING_HOSTS:
        return "Host not allowed", 403

    # Basic rate limiting per client IP to mitigate abuse.
    client_ip = request.remote_addr or "unknown"
    now = time.time()
    entries = _PING_RATE_LIMIT.get(client_ip, [])
    entries = [t for t in entries if now - t < _PING_RATE_WINDOW]
    if len(entries) >= _PING_RATE_MAX:
        return "Rate limit exceeded", 429
    entries.append(now)
    _PING_RATE_LIMIT[client_ip] = entries

    app.logger.info("Ping request for allowed host %s from %s", host, client_ip)

    try:
        # Use a non-privileged socket reachability check instead of invoking
        # the system `ping` binary, avoiding command-execution risks entirely.
        socket.setdefaulttimeout(5)
        addrinfo = socket.getaddrinfo(host, None)
        reachable = False
        resolved = []
        for family, _, _, _, sockaddr in addrinfo:
            ip = sockaddr[0]
            resolved.append(ip)
            try:
                s = socket.socket(family, socket.SOCK_STREAM)
                s.settimeout(3)
                # Attempt a TCP connect to a discarded port (e.g. 9) purely
                # to test reachability without relying on ICMP/system ping.
                s.connect((ip, 9))
                s.close()
                reachable = True
                break
            except OSError:
                continue
        result = {
            "host": host,
            "resolved_addresses": resolved,
            "reachable": reachable,
        }
        return "<pre>" + repr(result) + "</pre>"
    except socket.gaierror as e:
        return f"<pre>DNS resolution failed: {e}</pre>", 500
    except Exception as e:
        return f"<pre>Error: {e}</pre>", 500


if __name__ == "__main__":
    init_db()
    # FIX #5: Debug mode enabled via environment variable, defaulting to False.
    # When debug is True, bind only to 127.0.0.1 to avoid exposing the Werkzeug
    # interactive debugger and its deterministic PIN to external networks.
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="127.0.0.1" if debug else "0.0.0.0", port=5000, debug=debug)
