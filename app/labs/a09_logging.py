"""
A09:2025 – Security Logging and Alerting Failures
Demonstrates:
  - Logging sensitive data (passwords, CC numbers) in plaintext
  - No logging of failed auth attempts or suspicious actions
  - Logs stored in world-readable location
  - No alerting on anomalous transactions
Compare /transfer-bad (insecure) vs /transfer-good (fixed) implementations.
"""
import logging
import os
from datetime import datetime
from flask import Blueprint, render_template, request
from app.database import get_db

a09 = Blueprint('a09', __name__)

LOG_DIR  = os.path.join(os.path.dirname(__file__), '..', '..', 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

# ── BAD logger: logs passwords and card numbers in plaintext ──────────────────
bad_logger = logging.getLogger('a09.bad')
bad_handler = logging.FileHandler(os.path.join(LOG_DIR, 'bad_app.log'))
bad_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
bad_logger.addHandler(bad_handler)
bad_logger.setLevel(logging.DEBUG)

# ── GOOD logger: sanitized, structured ───────────────────────────────────────
good_logger = logging.getLogger('a09.good')
good_handler = logging.FileHandler(os.path.join(LOG_DIR, 'good_app.log'))
good_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
good_logger.addHandler(good_handler)
good_logger.setLevel(logging.INFO)


@a09.route('/')
def index():
    return render_template('a09/index.html')


# ── VULNERABLE: logs plaintext password + full card ───────────────────────────
@a09.route('/login-bad', methods=['GET', 'POST'])
def login_bad():
    result = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        # BUG: logs plaintext credentials
        bad_logger.debug(f"LOGIN ATTEMPT user={username} password={password} ip={request.remote_addr}")
        db = get_db()
        user = db.execute(
            "SELECT * FROM a07_users WHERE username=? AND password=?",
            [username, password]
        ).fetchone()
        if user:
            bad_logger.info(f"LOGIN SUCCESS user={username}")
            result = {'status': 'success', 'user': username}
        else:
            # BUG: no logging of failure — silent auth failure
            result = {'status': 'fail'}
    return render_template('a09/login_bad.html', result=result)


# ── SECURE: sanitized logs, failure events recorded ───────────────────────────
@a09.route('/login-good', methods=['GET', 'POST'])
def login_good():
    result = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        db = get_db()
        user = db.execute(
            "SELECT * FROM a07_users WHERE username=? AND password=?",
            [username, password]
        ).fetchone()
        if user:
            good_logger.info(f"AUTH_SUCCESS username={username} ip={request.remote_addr}")
            result = {'status': 'success', 'user': username}
        else:
            # FIXED: log failure without revealing credentials
            good_logger.warning(f"AUTH_FAILURE username={username} ip={request.remote_addr}")
            result = {'status': 'fail'}
    return render_template('a09/login_good.html', result=result)


# ── VULNERABLE: no alerting on suspicious large transaction ───────────────────
@a09.route('/transfer-bad', methods=['GET', 'POST'])
def transfer_bad():
    message = None
    if request.method == 'POST':
        username = request.form.get('username', 'alice')
        amount   = float(request.form.get('amount', 0))
        card     = request.form.get('card', '')
        # BUG: logs full card number, no alert for large/off-hours transfer
        bad_logger.info(f"TRANSFER user={username} amount={amount} card={card}")
        message = f"Transfer of ${amount:.2f} processed."
    db = get_db()
    txns = db.execute("SELECT * FROM a09_transactions").fetchall()
    return render_template('a09/transfer_bad.html', transactions=txns, message=message)


# ── SECURE: masked card, anomaly detection ────────────────────────────────────
@a09.route('/transfer-good', methods=['GET', 'POST'])
def transfer_good():
    message = alert = None
    if request.method == 'POST':
        username = request.form.get('username', 'alice')
        amount   = float(request.form.get('amount', 0))
        card     = request.form.get('card', '')
        masked   = '**** **** **** ' + card[-4:] if len(card) >= 4 else '****'
        hour     = datetime.now().hour

        # FIXED: log masked card only
        good_logger.info(f"TRANSFER user={username} amount={amount} card={masked} ip={request.remote_addr}")

        # FIXED: anomaly detection
        if amount > 5000:
            good_logger.warning(f"LARGE_TRANSFER user={username} amount={amount}")
            alert = f"Alert: large transfer ${amount:.2f} flagged for review."
        if hour < 6 or hour > 22:
            good_logger.warning(f"OFF_HOURS_TRANSFER user={username} hour={hour}")
            alert = (alert or '') + " Alert: off-hours transfer flagged."

        message = f"Transfer of ${amount:.2f} processed (card {masked})."
    db = get_db()
    txns = db.execute("SELECT * FROM a09_transactions").fetchall()
    return render_template('a09/transfer_good.html', transactions=txns,
                           message=message, alert=alert)


@a09.route('/view-logs')
def view_logs():
    logs = {}
    for fname in ('bad_app.log', 'good_app.log'):
        fpath = os.path.join(LOG_DIR, fname)
        try:
            with open(fpath) as f:
                logs[fname] = f.read()
        except FileNotFoundError:
            logs[fname] = '(empty — no events yet)'
    return render_template('a09/view_logs.html', logs=logs)
