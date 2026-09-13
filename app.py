"""
Intentionally vulnerable demo app for testing a vulnerability scanner.

WARNING: This app contains DELIBERATE security vulnerabilities.
Do NOT deploy it anywhere public. Local scanning/testing only.
"""

import re
import socket
import sqlite3
import subprocess
import time

from flask import Flask, request, render_template_string, g

app = Flask(__name__)

DB_PATH = "users.db"

# VULN #1: Hardcoded secret / credentials (scanners flag hardcoded secrets)
SECRET_KEY = "super-secret-hardcoded-key-12345"
ADMIN_PASSWORD = "admin123"
app.config["SECRET_KEY"] = SECRET_KEY

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


# VULN #2: SQL Injection — user input concatenated directly into the query.
@app.route("/search")
def search():
    username = request.args.get("username", "")
    db = get_db()
    cur = db.cursor()
    query = "SELECT id, username, email FROM users WHERE username LIKE '" + username + "' ORDER BY username"
    try:
        cur.execute(query)
        rows = cur.fetchall()
    except Exception as e:
        return f"Query error: {e}", 500
    return {"query": query, "results": rows}


# VULN #3: Reflected XSS — untrusted input rendered without escaping.
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    template = "<h1>Welcome, " + name + "!</h1>"
    return render_template_string(template)


# FIX #4: SSRF / network scanning mitigated by:
#   - Enforcing a strict whitelist of allowed hosts (ALLOWED_PING_HOSTS).
#   - Avoiding system command invocation; using a socket-based check instead.
#   - Adding basic per-client rate limiting and request logging.
@app.route("/ping")
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
    # VULN #5: Debug mode enabled in production (exposes interactive debugger).
    app.run(host="0.0.0.0", port=5000, debug=True)
