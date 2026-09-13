"""
Intentionally vulnerable demo app for testing a vulnerability scanner.

WARNING: This app contains DELIBERATE security vulnerabilities.
Do NOT deploy it anywhere public. Local scanning/testing only.
"""

import os
import re
import sqlite3
import subprocess
from functools import wraps
from urllib.parse import urlparse, urljoin

from flask import Flask, request, render_template_string, g, session, redirect, url_for, Response
from markupsafe import escape

# FIXED: Added Flask-WTF import for CSRF protection on the login form.
from flask_wtf import FlaskForm
from wtforms import PasswordField
from wtforms.validators import DataRequired

app = Flask(__name__)

DB_PATH = "users.db"

# FIXED: Load secret key from environment variable instead of hardcoding it
SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("FLASK_SECRET_KEY environment variable not set")
# FIXED: Remove hardcoded fallback "admin123". Require ADMIN_PASSWORD to be set
# explicitly via environment variable; fail fast if missing to prevent use of
# a known default credential.
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD environment variable not set")
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


# FIXED: Missing Authentication and Authorization — added a login_required
# decorator enforcing session-based authentication, plus /login and /logout
# endpoints so protected routes require a valid session.
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


# FIXED: Open Redirect — added a helper function to validate that a redirect
# target URL is safe (i.e., points to the same host as the application).
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


# FIXED: Login endpoint lacks CSRF protection — added a FlaskForm-based
# LoginForm that includes a CSRF token. The token is rendered in the form
# template and validated automatically by validate_on_submit().
class LoginForm(FlaskForm):
    password = PasswordField("Password", validators=[DataRequired()])


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    error = None
    if form.validate_on_submit():
        if form.password.data == ADMIN_PASSWORD:
            session["authenticated"] = True
            # FIXED: Open Redirect — validate the 'next' parameter before
            # redirecting. If it is missing or points to an external host,
            # fall back to the index route.
            nxt = request.args.get("next")
            if not nxt or not is_safe_url(nxt):
                nxt = url_for("index")
            return redirect(nxt)
        error = "Invalid password"
    return render_template_string(
        "<h1>Login</h1>"
        "{% if error %}<p>{{ error }}</p>{% endif %}"
        "<form method='post'>"
        "{{ form.csrf_token }}"
        "{{ form.password(placeholder='Password') }}"
        "<button type='submit'>Login</button>"
        "</form>",
        form=form,
        error=error,
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return (
        "<h1>Vulnerable Demo App</h1>"
        "<ul>"
        "<li><a href='/search?username=alice'>User search (SQL injection)</a></li>"
        "<li><a href='/greet?name=World'>Greeting (reflected XSS)</a></li>"
        "<li><a href='/ping?host=127.0.0.1'>Ping (command injection)</a></li>"
        "<li><a href='/logout'>Logout</a></li>"
        "</ul>"
    )


# FIXED: SQL Injection — user input is now passed as a parameter to the query.
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
    return {"query": query, "results": rows}


# FIXED: Server-Side Template Injection — the /greet endpoint no longer uses
# render_template_string. Instead it returns a plain response with the user
# input explicitly escaped via markupsafe.escape(). This removes any template
# evaluation path entirely, eliminating the risk of SSTI while preserving
# automatic HTML escaping for reflected XSS protection.
@app.route("/greet")
@login_required
def greet():
    name = request.args.get("name", "")
    # Explicitly escape user input with markupsafe.escape() and return a plain
    # string response. No Jinja2 template rendering is performed, so there is
    # no opportunity for template expressions in user input to be evaluated.
    return f"<h1>Welcome, {escape(name)}!</h1>"


# FIXED: OS Command Injection — the host parameter is now validated against a
# strict allowlist regex and the command is invoked without a shell, using an
# argument list. This prevents shell metacharacters from being interpreted.
@app.route("/ping")
@login_required
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Only allow alphanumerics, dots, and hyphens (valid hostname/IP chars).
    if not re.fullmatch(r"[a-zA-Z0-9.-]+", host):
        return "Invalid host", 400
    output = subprocess.check_output(
        ["ping", "-c", "2", host], stderr=subprocess.STDOUT
    )
    return "<pre>" + output.decode(errors="replace") + "</pre>"


if __name__ == "__main__":
    init_db()
    # FIXED: Debug mode is no longer hard-coded to True. It defaults to off
    # and must be explicitly enabled via the FLASK_DEBUG environment variable.
    # In production, use a WSGI server such as gunicorn instead of app.run().
    debug = os.getenv("FLASK_DEBUG", "false").strip().lower() in ("1", "true", "yes")
    app.run(host="0.0.0.0", port=5000, debug=debug)
