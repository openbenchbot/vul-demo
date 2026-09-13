"""
Intentionally vulnerable demo app for testing a vulnerability scanner.

WARNING: This app contains DELIBERATE security vulnerabilities.
Do NOT deploy it anywhere public. Local scanning/testing only.
"""

import os
import re
import sqlite3
import subprocess

from flask import Flask, request, render_template_string, g, abort

app = Flask(__name__)

DB_PATH = "users.db"

# FIX #1: Load SECRET_KEY from environment variable instead of hardcoding it.
# Hardcoded keys allow attackers to forge session cookies. We read from the
# environment and fail fast if it's not set. The unused hardcoded
# ADMIN_PASSWORD is also removed.
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]

# FIX #7 (Missing Authentication): Load an API key from the environment that
# callers must present to access any sensitive endpoint. This prevents
# unauthenticated access to user data and internal functionality.
API_KEY = os.environ.get("API_KEY", "")


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


# FIX #7 (Missing Authentication): Enforce authentication on all sensitive
# endpoints via a before_request handler. The public landing page ("/") remains
# accessible, but every other route requires a valid API key supplied via the
# X-API-Key header or api_key query parameter. Without this, unauthenticated
# callers could retrieve user emails and invoke internal ping functionality.
@app.before_request
def require_auth():
    if request.path == "/":
        return
    provided_key = request.headers.get("X-API-Key") or request.args.get("api_key")
    if not API_KEY or not provided_key or provided_key != API_KEY:
        abort(401)


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


# FIX #2: SQL Injection mitigated by using a parameterised query instead of
# string concatenation. The username value is passed as a bound parameter,
# so any SQL metacharacters in user input are treated as literal data and
# cannot alter the query structure.
# FIX #6 (IDOR): The 'id' internal identifier is no longer selected or
# returned in the response, preventing unauthenticated ID enumeration.
# The raw SQL query string is also omitted from the response to avoid
# leaking internal schema details.
@app.route("/search")
def search():
    username = request.args.get("username", "")
    db = get_db()
    cur = db.cursor()
    query = "SELECT username, email FROM users WHERE username LIKE ? ORDER BY username"
    try:
        cur.execute(query, (username,))
        rows = cur.fetchall()
    except Exception as e:
        return f"Query error: {e}", 500
    return {"results": rows}


# FIX #3: Use Jinja2 template variables instead of string concatenation.
# Passing user input through {{ name }} ensures Jinja2 auto-escaping is
# applied, preventing both SSTI (template expressions are not executed
# because the input is now treated as a data value, not template source)
# and reflected XSS (HTML special characters are escaped).
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string("<h1>Welcome, {{ name }}!</h1>", name=name)


# Defense-in-depth: set a restrictive Content-Security-Policy header to
# mitigate XSS even if an escaping bug is introduced elsewhere.
@app.after_request
def set_csp(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
    return response


# FIX #4: OS Command Injection mitigated by:
#   1. Strict input validation via regex (only alphanumeric, dots, hyphens).
#   2. shell=False with list-based arguments — no /bin/sh invocation.
#   3. A timeout to prevent resource exhaustion.
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    if not re.match(r'^[a-zA-Z0-9.\-]+$', host) or len(host) > 255:
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
    # FIX #5: Debug mode controlled via environment variable instead of being
    # hardcoded to True. Enabling Flask's interactive debugger on a publicly
    # reachable interface allows unauthenticated attackers to execute arbitrary
    # Python code via the debugger console. Debug mode now defaults to False
    # and must be explicitly opted into via FLASK_DEBUG=true (for local dev).
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)
