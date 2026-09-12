# Vulnerable Demo App

⚠️ **This app contains DELIBERATE security vulnerabilities.** It exists only to test
a vulnerability scanner locally. Do not deploy it anywhere reachable.

## Run

```bash
pip install -r requirements.txt
python app.py
```

Then open http://localhost:5000

## Intentional vulnerabilities (for the scanner to catch)

| # | Type | Location | Try it |
|---|------|----------|--------|
| 1 | Hardcoded secrets/credentials | `SECRET_KEY`, `ADMIN_PASSWORD` in `app.py` | (static scan) |
| 2 | SQL injection | `/search` | `/search?username=alice' OR '1'='1` |
| 3 | Reflected XSS | `/greet` | `/greet?name=<script>alert(1)</script>` |
| 4 | OS command injection | `/ping` | `/ping?host=127.0.0.1; whoami` |
| 5 | Debug mode enabled | `app.run(debug=True)` | (static scan) |
| 6 | Vulnerable dependency | `flask==2.0.1` in `requirements.txt` | (SCA scan) |
