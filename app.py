"""
Intentionally vulnerable demo app for testing a vulnerability scanner.

WARNING: This app contains DELIBERATE security vulnerabilities.
Do NOT deploy it anywhere public. Local scanning/testing only.
"""

import re
import sqlite3
import subprocess

from flask import Flask, request, render_template_string, g

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


# FIXED: Reflected XSS — untrusted input is now rendered using Jinja2's automatic escaping.
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    template = "<h1>Welcome, {{ name }}!</h1>"
    return render_template_string(template, name=name)


# FIXED: OS Command Injection — validate host and use shell=False with list args.
@app.route("/ping")
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
    # VULN #5: Debug mode enabled in production (exposes interactive debugger).
    app.run(host="0.0.0.0", port=5000, debug=True)