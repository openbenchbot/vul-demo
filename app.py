"""
Demo app for testing a vulnerability scanner.

The deliberate vulnerabilities that used to live here (hardcoded secrets,
SQL injection, reflected XSS, OS command injection, and debug mode in
production) have been fixed. Local scanning/testing only.
"""

import html
import ipaddress
import logging
import os
import re
import secrets
import sqlite3
import subprocess
import time
from collections import defaultdict, deque

from flask import Flask, request, g, render_template_string

app = Flask(__name__)

DB_PATH = "users.db"

# FIX #1: Secrets are no longer hardcoded. They are loaded from the
# environment; SECRET_KEY falls back to a random per-process value.
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
app.config["SECRET_KEY"] = SECRET_KEY

# FIX #2 (hardening): /search now requires bearer-token authentication so the
# users table is not readable by unauthenticated clients. Set SEARCH_API_TOKEN
# in the environment; if unset, a random per-process value is used
# (deny-by-default).
SEARCH_API_TOKEN = os.environ.get("SEARCH_API_TOKEN") or secrets.token_hex(32)

# Server-side logger: database error details go here, never to the client.
logger = logging.getLogger(__name__)

# FIX #4 (secondary): simple in-memory, per-client rate limiter for /ping so
# requests can no longer spawn unbounded OS subprocesses (DoS).
PING_RATE_LIMIT = 5
PING_RATE_WINDOW = 60.0  # seconds
_ping_hits = defaultdict(deque)


def _ping_rate_limited(client_ip):
    now = time.monotonic()
    hits = _ping_hits[client_ip]
    while hits and now - hits[0] > PING_RATE_WINDOW:
        hits.popleft()
    if len(hits) >= PING_RATE_LIMIT:
        return True
    hits.append(now)
    return False


# FIX #4: strict host allowlist - accepts IP addresses (v4/v6) or well-formed
# hostnames/FQDNs only; shell metacharacters, whitespace, and separators are
# all rejected before anything reaches a subprocess.
_HOSTNAME_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?"
)


def _is_valid_host(host):
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return _HOSTNAME_RE.fullmatch(host) is not None


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
        "<li><a href='/search?username=alice'>User search (parameterized query; requires bearer token)</a></li>"
        "<li><a href='/greet?name=World'>Greeting (escaped output)</a></li>"
        "<li><a href='/ping?host=127.0.0.1'>Ping (validated host)</a></li>"
        "</ul>"
    )


# FIX #2: SQL injection - user input is bound as a parameter instead of being
# concatenated into the query string. Additional hardening: raw database
# exception messages are no longer returned to clients (logged server-side,
# generic error returned), the "query"/"params" echo is removed from the JSON
# response, and the endpoint requires bearer-token authentication so user data
# is not exposed to unauthenticated callers.
@app.route("/search")
def search():
    expected = f"Bearer {SEARCH_API_TOKEN}".encode("utf-8")
    provided = request.headers.get("Authorization", "").encode("utf-8", "replace")
    if not secrets.compare_digest(provided, expected):
        logger.warning(
            "Unauthorized /search attempt from %s", request.remote_addr
        )
        return {"error": "Unauthorized"}, 401

    username = request.args.get("username", "")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            "SELECT id, username, email FROM users WHERE username = ?",
            (username,),
        )
        rows = cur.fetchall()
    except Exception:
        logger.exception("Database error while searching users")
        return {"error": "Internal server error"}, 500
    return {"results": rows}


# FIX #3: Reflected XSS/SSTI - the template source is now a static string and
# the user-supplied name is passed as a context variable, so Jinja2 autoescaping
# applies. User input is never compiled as template code, which eliminates the
# server-side template injection (SSTI) to RCE primitive as well as the
# reflected XSS.
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)


# FIX #4: OS command injection - the shell is eliminated (argument-list form
# with shell=False), the host is strictly validated, stderr is still captured,
# a timeout is enforced, and the output is HTML-escaped (which also fixes the
# reflected XSS on this endpoint). The rate limiter above prevents the
# subprocess-exhaustion DoS.
@app.route("/ping")
def ping():
    client_ip = request.remote_addr or "unknown"
    if _ping_rate_limited(client_ip):
        return "Rate limit exceeded", 429

    host = request.args.get("host", "127.0.0.1")
    if not _is_valid_host(host):
        return "Invalid host", 400

    try:
        result = subprocess.run(
            ["ping", "-c", "3", host],
            shell=False,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "Ping timed out", 504

    output = result.stdout + result.stderr
    return "<pre>" + html.escape(output.decode(errors="replace")) + "</pre>"


if __name__ == "__main__":
    init_db()
    # FIX #5: Debug mode disabled - the Werkzeug interactive debugger allows
    # remote code execution when exposed.
    app.run(host="0.0.0.0", port=5000, debug=False)
