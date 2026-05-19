"""
A10:2025 – Mishandling of Exceptional Conditions
Vulnerabilities:
  - Unhandled exceptions expose full stack traces with internal paths & config
  - Error messages reveal implementation details (DB type, file paths, versions)
  - Path traversal via unhandled exception leaks filesystem info
  - Division by zero / type errors expose query structure
Compare /calculate-bad and /read-bad (leak info) vs *-good (safe error handling).
"""
import os
import traceback
from flask import Blueprint, render_template, request

a10 = Blueprint('a10', __name__)

BASE_DIR = os.path.dirname(__file__)


@a10.route('/')
def index():
    return render_template('a10/index.html')


# ── VULNERABLE: unhandled exception leaks stack trace ────────────────────────
@a10.route('/calculate-bad', methods=['GET', 'POST'])
def calculate_bad():
    result = error = None
    if request.method == 'POST':
        a = request.form.get('a', '')
        b = request.form.get('b', '')
        # BUG: no try/except — ZeroDivisionError leaks at /a10/calculate-bad
        # but here we catch and render the raw traceback (simulating a misconfigured
        # framework that renders tracebacks in HTML responses)
        try:
            result = int(a) / int(b)
        except Exception:
            error = traceback.format_exc()  # BUG: expose raw traceback to user
    return render_template('a10/calculate_bad.html', result=result, error=error)


# ── SECURE: generic error, details logged server-side only ───────────────────
@a10.route('/calculate-good', methods=['GET', 'POST'])
def calculate_good():
    result = error = None
    if request.method == 'POST':
        a = request.form.get('a', '')
        b = request.form.get('b', '')
        try:
            result = int(a) / int(b)
        except ZeroDivisionError:
            error = "Cannot divide by zero."
        except ValueError:
            error = "Please enter valid integers."
        except Exception:
            # FIXED: log internally, show generic message
            error = "An unexpected error occurred. Please try again."
    return render_template('a10/calculate_good.html', result=result, error=error)


# ── VULNERABLE: path traversal + exception reveals filesystem ────────────────
@a10.route('/read-bad')
def read_bad():
    filename = request.args.get('file', 'sample.txt')
    content  = error = None
    # BUG: no sanitization, exception reveals absolute path
    try:
        path = os.path.join(BASE_DIR, '..', '..', 'static', filename)
        with open(path) as f:
            content = f.read()
    except Exception:
        error = traceback.format_exc()  # BUG: shows full path in stack trace
    return render_template('a10/read_bad.html', content=content, error=error,
                           filename=filename)


# ── SECURE: sanitized path, generic error ────────────────────────────────────
@a10.route('/read-good')
def read_good():
    filename = request.args.get('file', 'sample.txt')
    content  = error = None
    try:
        # FIXED: restrict to allowed directory, no path traversal
        safe_dir  = os.path.realpath(os.path.join(BASE_DIR, '..', '..', 'static'))
        safe_path = os.path.realpath(os.path.join(safe_dir, filename))
        if not safe_path.startswith(safe_dir):
            raise ValueError("Access denied")
        with open(safe_path) as f:
            content = f.read()
    except ValueError as e:
        error = str(e)
    except FileNotFoundError:
        error = "File not found."
    except Exception:
        error = "Could not read file."
    return render_template('a10/read_good.html', content=content, error=error,
                           filename=filename)


# ── VULNERABLE: SQL error message exposed ─────────────────────────────────────
@a10.route('/query-bad')
def query_bad():
    from app.database import get_db
    table  = request.args.get('table', 'a05_products')
    result = error = None
    try:
        db = get_db()
        # BUG: reveals table/column structure in SQL error message
        rows   = db.execute(f"SELECT * FROM {table}").fetchall()
        result = [dict(r) for r in rows]
    except Exception as e:
        error = str(e)   # BUG: "no such table: xyz" reveals DB internals
    return render_template('a10/query_bad.html', result=result, error=error, table=table)
