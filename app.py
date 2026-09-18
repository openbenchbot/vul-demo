"""
Demo app for testing a vulnerability scanner.

Security note: the previously deliberate vulnerabilities in this file
(hardcoded secrets, SQL injection, reflected XSS/template injection,
OS command injection, and production debug mode) have all been fixed.
Local scanning/testing only.
"""

import html
import ipaddress
import os
import re
import secrets
import sqlite3
import subprocess
import threading
import time
from collections import defaultdict, deque

from flask import Flask, request, render_template_string, g

app = Flask(__name__)

DB_PATH = "users.db"

# FIX #1: Hardcoded secrets removed. SECRET_KEY is read from the environment
# with a randomly generated per-process fallback; the unused hardcoded
# ADMIN_PASSWORD was deleted (credentials must come from env/secret store).
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
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
        "<h1>Demo App</h1>"
        "<ul>"
        "<li><a href='/search?username=alice'>User search (parameterized SQL)</a></li>"
        "<li><a href='/greet?name=World'>Greeting (escaped output)</a></li>"
        "<li><a href='/ping?host=127.0.0.1'>Ping (validated, no shell)</a></li>"
        "</ul>"
    )


# FIX #2: SQL Injection — user input is now bound as a query parameter, so it
# can no longer change the structure of the SQL statement.
@app.route("/search")
def search():
    username = request.args.get("username", "")
    db = get_db()
    cur = db.cursor()
    query = "SELECT id, username, email FROM users WHERE username = ?"
    try:
        cur.execute(query, (username,))
        rows = cur.fetchall()
    except Exception as e:
        return f"Query error: {e}", 500
    return {"query": query, "results": rows}


# FIX #3: Reflected XSS (and template injection) — user input is passed as a
# template variable (auto-escaped by Jinja) instead of being concatenated
# into the template source itself.
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)


# FIX #4: OS command injection — the shell is eliminated (argument-list
# subprocess call with shell=False), `host` is strictly validated, the
# subprocess has a timeout, output is HTML-escaped (fixes the reflected XSS
# in the <pre> block), and the endpoint is rate limited (fixes the
# process-exhaustion DoS).
_PING_RATE_LIMIT = 5       # max requests per IP...
_PING_RATE_WINDOW = 60.0   # ...per this many seconds
_ping_hits = defaultdict(deque)  # in-memory, per-process rate-limit state
_ping_lock = threading.Lock()

# Strict FQDN allowlist: letters/digits/hyphen labels separated by dots,
# total length <= 253 — permits no shell metacharacters or whitespace.
_FQDN_RE = re.compile(
    r"^(?=.{1,253}\Z)"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?\Z"
)


def _valid_host(host):
    """Accept only plain IPv4/IPv6 addresses or strict FQDNs; reject all else."""
    if not host or len(host) > 253 or host.startswith("-"):
        # Leading '-' is rejected to block ping option injection (e.g. "--", "-f").
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(_FQDN_RE.match(host))


def _ping_rate_limited(ip):
    now = time.monotonic()
    with _ping_lock:
        hits = _ping_hits[ip]
        while hits and now - hits[0] > _PING_RATE_WINDOW:
            hits.popleft()
        if len(hits) >= _PING_RATE_LIMIT:
            return True
        hits.append(now)
        return False


@app.route("/ping")
def ping():
    if _ping_rate_limited(request.remote_addr or "unknown"):
        return "Too many requests", 429

    host = request.args.get("host", "127.0.0.1")
    if not _valid_host(host):
        return "Invalid host: use an IP address or FQDN.", 400

    try:
        # Argument-list form, no shell: metacharacters are never interpreted.
        result = subprocess.run(
            ["ping", "-c", "1", host],
            shell=False,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "Ping timed out", 504

    output = result.stdout + result.stderr
    # html.escape prevents reflected XSS through ping output.
    return "<pre>" + html.escape(output.decode(errors="replace")) + "</pre>"


if __name__ == "__main__":
    init_db()
    # FIX #5: Debug mode is off by default (the Werkzeug debugger allows
    # arbitrary code execution). Enable only for local development via
    # FLASK_DEBUG=1.
    app.run(host="0.0.0.0", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
