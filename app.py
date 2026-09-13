"""
Intentionally vulnerable demo app for testing a vulnerability scanner.

WARNING: This app contains DELIBERATE security vulnerabilities.
Do NOT deploy it anywhere public. Local scanning/testing only.
"""

import functools
import os
import re
import sqlite3
import subprocess

from flask import Flask, request, render_template_string, g, Response
from markupsafe import escape

app = Flask(__name__)

DB_PATH = "users.db"

# FIXED #1: Hardcoded secret / credentials - now loaded from environment variables without insecure fallbacks.
SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("FLASK_SECRET_KEY not set")
app.config["SECRET_KEY"] = SECRET_KEY

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD not set")


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


# FIX: Added authentication decorator to enforce authorization on sensitive endpoints.
def require_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if (
            not auth
            or auth.username != "admin"
            or auth.password != ADMIN_PASSWORD
        ):
            return Response(
                "Could not verify your access level for that URL.\n"
                "You have to login with proper credentials",
                401,
                {"WWW-Authenticate": 'Basic realm="Login Required"'},
            )
        return f(*args, **kwargs)

    return decorated


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


# FIXED #2: SQL Injection — using parameterized query with placeholder.
# FIX: Added @require_auth to enforce authentication before accessing user data.
@app.route("/search")
@require_auth
def search():
    username = request.args.get("username", "")
    db = get_db()
    cur = db.cursor()
    # Use parameterized query to prevent SQL injection via username parameter
    query = "SELECT id, username, email FROM users WHERE username LIKE ? ORDER BY username"
    try:
        cur.execute(query, (username,))
        rows = cur.fetchall()
    except Exception as e:
        return f"Query error: {e}", 500
    return {"query": query, "results": rows}


# FIXED #3: Reflected XSS — untrusted input is passed as a variable to the template, relying on Jinja2 auto-escaping.
# FIX: Added @require_auth to enforce authentication before rendering greeting.
@app.route("/greet")
@require_auth
def greet():
    name = request.args.get("name", "")
    return render_template_string("<h1>Welcome, {{ name }}!</h1>", name=name)


# FIXED #4: OS Command Injection — input is now validated and passed as a list without shell=True.
# FIX: Added @require_auth to enforce authentication before executing system commands.
@app.route("/ping")
@require_auth
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Validate the host parameter to prevent shell metacharacters
    if not re.fullmatch(r'[A-Za-z0-9.-]+', host):
        return "Invalid host", 400
    output = subprocess.check_output(
        ["ping", "-c", "2", host], stderr=subprocess.STDOUT
    )
    return "<pre>" + output.decode(errors="replace") + "</pre>"


if __name__ == "__main__":
    init_db()
    # FIXED #5: Debug mode disabled in production to prevent exposure of the interactive debugger.
    # Flask's debug mode exposes the Werkzeug interactive debugger, which allows arbitrary
    # code execution from the browser if an exception occurs. Setting debug=False ensures
    # the debugger is not available to remote users.
    app.run(host="0.0.0.0", port=5000, debug=False)
