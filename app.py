"""
Intentionally vulnerable demo app for testing a vulnerability scanner.

WARNING: This app contains DELIBERATE security vulnerabilities.
Do NOT deploy it anywhere public. Local scanning/testing only.
"""

import sqlite3
import subprocess
from functools import wraps

from flask import Flask, request, render_template_string, g, session, redirect, url_for

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


# FIXED: Added authentication and authorization controls.
# A login_required decorator is used to protect sensitive routes.
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
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
        "<li><a href='/login'>Login</a></li>"
        "<li><a href='/logout'>Logout</a></li>"
        "</ul>"
    )


# FIXED: Added a login route to support session-based authentication.
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
            session["user"] = "admin"
            return redirect(url_for("index"))
        return "Invalid credentials", 401
    return render_template_string(
        """
        <form method="post">
            <input type="password" name="password" placeholder="Admin password">
            <button type="submit">Login</button>
        </form>
        """
    )


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))


# VULN #2: SQL Injection — user input concatenated directly into the query.
# FIXED: Using parameterized query to prevent SQL injection, and removed raw query from response.
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


# FIXED: Reflected XSS — pass user input as a template variable to leverage Jinja2 autoescaping.
@app.route("/greet")
@login_required
def greet():
    name = request.args.get("name", "")
    return render_template_string("<h1>Welcome, {{ name }}!</h1>", name=name)


# VULN #4: OS Command Injection — user input passed to a shell.
@app.route("/ping")
@login_required
def ping():
    host = request.args.get("host", "127.0.0.1")
    output = subprocess.check_output(
        "ping -c 2 " + host, shell=True, stderr=subprocess.STDOUT
    )
    return "<pre>" + output.decode(errors="replace") + "</pre>"


if __name__ == "__main__":
    init_db()
    # FIXED: Debug mode disabled to prevent exposure of the interactive debugger.
    app.run(host="0.0.0.0", port=5000, debug=False)
