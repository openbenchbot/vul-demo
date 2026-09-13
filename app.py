"""
Intentionally vulnerable demo app for testing a vulnerability scanner.

WARNING: This app contains DELIBERATE security vulnerabilities.
Do NOT deploy it anywhere public. Local scanning/testing only.
"""

import os
import re
import sqlite3
import subprocess

from flask import Flask, request, render_template_string, g, session, abort

app = Flask(__name__)

DB_PATH = "users.db"

# FIXED: Use environment variables for secrets instead of hardcoding them.
SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(32))
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")
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


# FIXED: SQL Injection — using parameterized query instead of string concatenation.
# FIXED: Unauthenticated data exposure — require a logged-in session and omit
# the email field so attackers cannot enumerate sensitive user data.
@app.route("/search")
def search():
    # Require authentication before returning any user data.
    if not session.get("user_id"):
        abort(401)
    username = request.args.get("username", "")
    db = get_db()
    cur = db.cursor()
    # Only select non-sensitive fields (id, username) — omit email.
    query = "SELECT id, username FROM users WHERE username LIKE ? ORDER BY username"
    try:
        cur.execute(query, (f"%{username}%",))
        rows = cur.fetchall()
    except Exception as e:
        return f"Query error: {e}", 500
    return {"results": rows}


# FIXED: Reflected XSS — render user input using Jinja2 template variables which are auto-escaped.
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string("<h1>Welcome, {{ name }}!</h1>", name=name)


# FIXED: OS Command Injection — pass arguments as a list instead of using shell=True,
# preventing shell metacharacter injection.
# FIXED: Validate host input to prevent argument injection into the ping command.
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Allow only hostnames and IPv4/IPv6-ish strings; reject flags/metacharacters.
    if not re.match(r"^[A-Za-z0-9.:-]+$", host):
        abort(400)
    output = subprocess.check_output(
        ["ping", "-c", "2", host], stderr=subprocess.STDOUT
    )
    return "<pre>" + output.decode(errors="replace") + "</pre>"


if __name__ == "__main__":
    init_db()
    # FIXED: Debug mode disabled to prevent exposure of the interactive debugger.
    # FIXED: Bind to localhost (127.0.0.1) instead of 0.0.0.0 to avoid exposing
    # the server on a public interface.
    app.run(host="127.0.0.1", port=5000, debug=False)
