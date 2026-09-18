"""
Hardened demo app for testing a vulnerability scanner.

All previously flagged vulnerabilities have been fixed:
  #1 hardcoded secrets  -> read from environment (random fallback)
  #2 SQL injection      -> parameterized query
  #3 reflected XSS/SSTI -> user input passed as a context variable, never
                           concatenated into template source
  #4 command injection  -> no shell, strict host validation, escaped output,
                           subprocess timeout, per-IP rate limiting
  #5 debug mode         -> disabled

Local scanning/testing only.
"""

import functools
import html
import ipaddress
import os
import re
import secrets
import sqlite3
import subprocess
import time
from collections import defaultdict, deque

from flask import Flask, request, render_template_string, g

app = Flask(__name__)

DB_PATH = "users.db"

# FIX (VULN #1): secrets are no longer hardcoded. Read them from the
# environment; SECRET_KEY falls back to a cryptographically random value so
# nothing secret lives in source control.
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
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
        "<h1>Demo App (hardened)</h1>"
        "<ul>"
        "<li><a href='/search?username=alice'>User search (parameterized query)</a></li>"
        "<li><a href='/greet?name=World'>Greeting (escaped output)</a></li>"
        "<li><a href='/ping?host=127.0.0.1'>Ping (validated host, no shell)</a></li>"
        "</ul>"
    )


# FIX (VULN #2, follow-up): /search returns user records (emails) that should
# not be readable anonymously. When API_TOKEN is configured, the endpoint now
# requires a matching bearer token (constant-time comparison) and returns 401
# otherwise. If no token is configured (local demo/scanner mode) the endpoint
# stays reachable but a warning is logged so the gap is visible in server logs.
def _require_bearer_token(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        expected = os.environ.get("API_TOKEN", "")
        if not expected:
            app.logger.warning(
                "/search served without authentication (API_TOKEN not set)"
            )
            return fn(*args, **kwargs)
        header = request.headers.get("Authorization", "")
        token = header[len("Bearer "):] if header.startswith("Bearer ") else ""
        if not token or not secrets.compare_digest(
            token.encode("utf-8"), expected.encode("utf-8")
        ):
            return {"error": "unauthorized"}, 401
        return fn(*args, **kwargs)

    return wrapper


# FIX (VULN #2): SQL injection — user input is bound as a parameter instead of
# being concatenated into the SQL string. Follow-up hardening for the same
# finding: raw database exceptions are no longer returned to the client (they
# enabled error-based extraction) — they are logged server-side and a generic
# error is returned — and the "query" echo was removed from the JSON response,
# as it disclosed the SQL structure to unauthenticated users.
@app.route("/search")
@_require_bearer_token
def search():
    username = request.args.get("username", "")
    db = get_db()
    cur = db.cursor()
    query = "SELECT id, username, email FROM users WHERE username = ?"
    try:
        cur.execute(query, (username,))
        rows = cur.fetchall()
    except Exception:
        # Never leak driver/SQL error text to clients; log it server-side.
        app.logger.exception("database error while handling /search")
        return {"error": "internal server error"}, 500
    # Results only: no SQL echo in the response.
    return {"results": rows}


# FIX (VULN #3): server-side template injection (SSTI) — user input was
# concatenated into the template SOURCE string, so Jinja2 evaluated it as
# template code (e.g. {{ config['SECRET_KEY'] }} or an os.popen gadget chain),
# giving full RCE; html.escape() does not prevent this because it does not
# strip Jinja delimiters. The template is now a static string and the user
# input is passed as a context variable, so Jinja treats it as data and
# autoescaping applies (which also fixes the reflected XSS).
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)


# Strict host allowlist used by /ping: plain IP addresses (v4/v6) or FQDNs.
# The FQDN regex permits only letters, digits, hyphens and dots, so every
# shell metacharacter (;, &&, |, $(), backticks, newline) is rejected.
_FQDN_RE = re.compile(
    r"^(?=.{1,253}\Z)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\Z"
)


def _is_valid_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(_FQDN_RE.match(host))


# Simple in-memory per-IP sliding-window rate limiter (no extra dependencies);
# prevents process-exhaustion DoS from repeated /ping requests.
_PING_HITS = defaultdict(deque)


def _rate_limit(limit, window_seconds):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            key = request.remote_addr or "unknown"
            now = time.monotonic()
            hits = _PING_HITS[key]
            while hits and now - hits[0] > window_seconds:
                hits.popleft()
            if len(hits) >= limit:
                return "Too many requests, try again later.", 429
            hits.append(now)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


# FIX (VULN #4): OS command injection — the shell is gone. `host` is strictly
# validated (IP or FQDN only), ping runs in argument-list form with
# shell=False and a timeout, and the output is HTML-escaped (which also fixes
# the reflected XSS on this endpoint). Per-IP rate limiting prevents
# process-exhaustion DoS from spawning subprocesses.
@app.route("/ping")
@_rate_limit(limit=5, window_seconds=60.0)
def ping():
    host = request.args.get("host", "127.0.0.1")

    if not _is_valid_host(host):
        return "Invalid host: use an IP address or an FQDN.", 400

    try:
        # Argument-list form with shell=False: no shell interpreter is ever
        # spawned, so metacharacters cannot be interpreted. check=False and
        # timeout=10 bound exit handling and runtime.
        proc = subprocess.run(
            ["ping", "-c", "1", host],
            shell=False,
            capture_output=True,
            timeout=10,
            check=False,
        )
        output = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        output = b"ping: request timed out"
    except FileNotFoundError:
        output = b"ping: utility not available on this system"

    # html.escape prevents any reflected markup/script injection in output.
    return "<pre>" + html.escape(output.decode(errors="replace")) + "</pre>"


if __name__ == "__main__":
    init_db()
    # FIX (VULN #5): debug mode disabled — the Werkzeug debugger can provide
    # remote code execution when enabled on a reachable deployment.
    app.run(host="0.0.0.0", port=5000, debug=False)
