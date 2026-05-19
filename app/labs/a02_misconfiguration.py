"""
A02:2025 – Security Misconfiguration
Vulnerabilities:
  - DEBUG mode exposes interactive debugger (run.py enables it)
  - /config endpoint leaks all app configuration
  - /backup exposes a sensitive file
  - Default admin:admin credentials
  - Verbose error messages with stack traces
  - Directory listing enabled via /files
"""
import os
from flask import Blueprint, render_template, current_app, request, jsonify, abort

a02 = Blueprint('a02', __name__)

# Simulated "default" credentials never changed
DEFAULT_CREDS = {'admin': 'admin', 'operator': 'operator123'}

# Fake sensitive backup content
BACKUP_CONTENT = """
[database]
host=localhost
port=5432
name=production_db
user=db_admin
password=Pr0d_S3cr3t!

[smtp]
host=smtp.corp.com
user=noreply@corp.com
password=EmailP@ss2024

[api]
stripe_key=sk_live_FAKEFAKEKEY123456789
aws_access_key=AKIAFAKEACCESSKEYHERE
aws_secret=fAkEsEcReTkEyFoReDuCaTiOn
"""


@a02.route('/')
def index():
    return render_template('a02/index.html')


# ── VULNERABLE: exposes all Flask config ─────────────────────────────────────
@a02.route('/config')
def show_config():
    # BUG: dumps entire app config including SECRET_KEY
    config_dump = {k: str(v) for k, v in current_app.config.items()}
    return jsonify(config_dump)


# ── VULNERABLE: exposes backup/credential file ───────────────────────────────
@a02.route('/backup.cfg')
def backup():
    return BACKUP_CONTENT, 200, {'Content-Type': 'text/plain'}


# ── VULNERABLE: login with default credentials, no lockout ───────────────────
@a02.route('/login', methods=['GET', 'POST'])
def login():
    message = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if DEFAULT_CREDS.get(username) == password:
            message = f"LOGIN SUCCESS — Welcome, {username}! (role: admin)"
        else:
            message = "Invalid credentials"
    return render_template('a02/login.html', message=message)


# ── VULNERABLE: headers reveal server details ─────────────────────────────────
@a02.after_request
def add_verbose_headers(response):
    response.headers['X-Powered-By'] = 'Flask/3.0.3 Python/3.11 Werkzeug/3.0.3'
    response.headers['X-Debug-Mode'] = str(current_app.debug)
    response.headers['Server'] = 'Apache/2.4.50 (Ubuntu)'  # spoofed but typical mistake
    return response


# ── VULNERABLE: no CORS restriction ──────────────────────────────────────────
@a02.route('/api/data')
def api_data():
    return jsonify({
        'internal_users': ['alice', 'bob', 'admin'],
        'server_version': '1.4.2-SNAPSHOT',
        'environment': 'production',
        'db_connection': 'sqlite:///lab.db'
    })
