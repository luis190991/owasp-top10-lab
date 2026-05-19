"""
A05:2025 – Injection
Vulnerabilities:
  - SQL Injection in login (bypass auth with ' OR '1'='1)
  - SQL Injection in product search (UNION-based data extraction)
  - OS Command Injection in ping utility (append ; id or && cat /etc/passwd)
"""
import subprocess
from flask import Blueprint, render_template, request, session
from app.database import get_db

a05 = Blueprint('a05', __name__)


@a05.route('/')
def index():
    return render_template('a05/index.html')


# ── VULNERABLE: SQL Injection in login ───────────────────────────────────────
@a05.route('/login', methods=['GET', 'POST'])
def login():
    result = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        db = get_db()
        # BUG: raw string interpolation — injectable
        query = f"SELECT * FROM a05_users WHERE username = '{username}' AND password = '{password}'"
        try:
            user = db.execute(query).fetchone()
            if user:
                result = {
                    'status': 'success',
                    'message': f"Logged in as: {user['username']} (role: {user['role']})",
                    'query': query
                }
            else:
                result = {'status': 'fail', 'message': 'Bad credentials', 'query': query}
        except Exception as e:
            result = {'status': 'error', 'message': str(e), 'query': query}
    return render_template('a05/login.html', result=result)


# ── VULNERABLE: SQL Injection in search (UNION attack) ───────────────────────
@a05.route('/search', methods=['GET', 'POST'])
def search():
    products = []
    query_used = None
    if request.method == 'POST':
        term = request.form.get('term', '')
        db = get_db()
        # BUG: raw interpolation
        query_used = f"SELECT id, name, price, category FROM a05_products WHERE name LIKE '%{term}%'"
        try:
            products = db.execute(query_used).fetchall()
        except Exception as e:
            products = []
            query_used = f"ERROR: {e} | Query was: {query_used}"
    return render_template('a05/search.html', products=products, query=query_used)


# ── VULNERABLE: OS Command Injection ─────────────────────────────────────────
@a05.route('/ping', methods=['GET', 'POST'])
def ping():
    output = None
    host = ''
    if request.method == 'POST':
        host = request.form.get('host', '')
        try:
            # BUG: shell=True with unsanitized input → command injection
            proc = subprocess.run(
                f"ping -c 2 {host}",
                shell=True, capture_output=True, text=True, timeout=10
            )
            output = proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            output = "Timed out"
        except Exception as e:
            output = str(e)
    return render_template('a05/ping.html', output=output, host=host)
