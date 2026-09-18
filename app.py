"""
Intentionally vulnerable demo app for testing a vulnerability scanner.

WARNING: This app contains DELIBERATE security vulnerabilities.
Do NOT deploy it anywhere public. Local scanning/testing only.
"""

import os
import secrets
import sqlite3
import subprocess
import logging
import html
import ipaddress
import re

from flask import Flask, request, render_template_string, g

app = Flask(__name__)

# Configure logging for security events
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DB_PATH = "users.db"

# FIXED #1: Secrets are loaded from environment variables; insecure hardcoded
# fallbacks removed. If SECRET_KEY is unset, a random per-process key is
# generated so a publicly-known secret can never ship by accident.
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
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


# FIXED #2: SQL Injection — fully remediated:
# 1) Parameterized query: user input is bound as a value, never concatenated
#    into the SQL text, so it cannot alter the query structure.
# 2) No information leak: raw database exceptions are logged server-side and a
#    generic error is returned; the constructed SQL is no longer echoed back.
# 3) Authentication: the endpoint requires the admin token (ADMIN_PASSWORD
#    env var) in the X-Admin-Token header and fails closed if it is unset,
#    so user data is no longer readable by unauthenticated callers.
@app.route("/search")
def search():
    provided = request.headers.get("X-Admin-Token", "")
    if not ADMIN_PASSWORD or not secrets.compare_digest(
        provided.encode("utf-8"), ADMIN_PASSWORD.encode("utf-8")
    ):
        return "Unauthorized", 401

    username = request.args.get("username", "")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            "SELECT id, username, email FROM users WHERE username = ?",
            (username,),
        )
        rows = cur.fetchall()
    except sqlite3.Error:
        # Log full details server-side; never return DB errors to clients
        logger.exception("Database error in /search")
        return "Internal Server Error", 500
    return {"results": rows}


# FIXED #3: SSTI — user input is never concatenated into the template SOURCE.
# The template is a static string and `name` is passed as a context variable,
# so Jinja treats it as data and autoescapes it. This prevents template
# injection (e.g. {{7*7}}, {{ config['SECRET_KEY'] }}, or os.popen RCE gadget
# chains) and the reflected XSS it enabled. The previous html.escape() was
# insufficient because it does not neutralize Jinja delimiters like {{ }}.
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)


# FIXED #4: OS Command Injection — input validated, shell=True removed, output escaped
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")

    # Validate host to prevent command injection
    try:
        # Check if it's a valid IP address
        ipaddress.ip_address(host)
    except ValueError:
        # If not an IP, check if it's a valid hostname (alphanumeric, hyphens, dots)
        # Pattern: starts with alphanumeric, contains alphanumeric/hyphens/dots, ends with alphanumeric
        if not re.match(r'^[a-zA-Z0-9]([-a-zA-Z0-9.]*[a-zA-Z0-9])?$', host):
            return "Invalid host format", 400

    # Use shell=False with list of arguments to prevent shell injection
    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            shell=False,
            capture_output=True,
            timeout=10,
            check=False
        )
        output = result.stdout.decode(errors="replace")
        if result.stderr:
            output += result.stderr.decode(errors="replace")
    except Exception as e:
        logger.error(f"Ping execution error: {e}")
        return "Ping execution failed", 500

    # Escape output to prevent reflected XSS in the response
    safe_output = html.escape(output)
    return "<pre>" + safe_output + "</pre>"


# FIX: Global error handler to prevent traceback disclosure
# Ensures unhandled exceptions return generic error without sensitive details
@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {e}", exc_info=True)
    return "Internal Server Error", 500


if __name__ == "__main__":
    init_db()
    # FIX: Disable debug mode by default; gate on FLASK_DEBUG environment variable.
    # Bind to 127.0.0.1 instead of 0.0.0.0 to prevent external exposure.
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="127.0.0.1", port=5000, debug=debug_mode)
