"""
Intentionally vulnerable demo app for testing a vulnerability scanner.

WARNING: This app contains DELIBERATE security vulnerabilities.
Do NOT deploy it anywhere public. Local scanning/testing only.
"""

import sqlite3
import subprocess
from functools import wraps

from flask import Flask, request, render_template_string, g, abort

app = Flask(__name__)

DB_PATH = "users.db"

# VULN #1: Hardcoded secret / credentials (scanners flag hardcoded secrets)
SECRET_KEY = "super-secret-hardcoded-key-12345"
ADMIN_PASSWORD = "admin123"
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


# FIX: Added an authentication decorator to protect sensitive endpoints
def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Simple token-based authentication check for demonstration purposes
        if request.headers.get("X-Auth-Token") != "valid-token":
            abort(401, description="Authentication required")
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


# VULN #2: SQL Injection — user input concatenated directly into the query.
@app.route("/search")
@auth_required
def search():
    username = request.args.get("username", "")
    db = get_db()
    cur = db.cursor()
    # FIX: Use a parameterized query with a placeholder to prevent SQL injection.
    query = "SELECT id, username, email FROM users WHERE username LIKE ? ORDER BY username"
    try:
        cur.execute(query, (f"%{username}%",))
        rows = cur.fetchall()
    except Exception as e:
        return f"Query error: {e}", 500
    # FIX: Remove raw query from response to avoid exposing internal queries.
    return {"results": rows}


# VULN #3: Reflected XSS — untrusted input rendered without escaping.
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # FIX: Pass `name` as a template variable with explicit escaping (|e) so
    # untrusted input is HTML-escaped instead of being concatenated directly
    # into the template string. This prevents reflected cross-site scripting.
    return render_template_string("<h1>Welcome, {{ name|e }}!</h1>", name=name)


# VULN #4: OS Command Injection — user input passed to a shell.
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    output = subprocess.check_output(
        "ping -c 2 " + host, shell=True, stderr=subprocess.STDOUT
    )
    return "<pre>" + output.decode(errors="replace") + "</pre>"


if __name__ == "__main__":
    init_db()
    # FIX: Disabled debug mode to prevent exposing the interactive Werkzeug debugger to unauthenticated users.
    app.run(host="0.0.0.0", port=5000, debug=False)