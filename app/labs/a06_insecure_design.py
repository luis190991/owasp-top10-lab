"""
A06:2025 – Insecure Design
Vulnerabilities:
  - Password reset via predictable token: MD5(username + static_salt)
  - No rate limiting on any sensitive operation
  - Business logic flaw: negative quantity reduces price (attacker gets credit)
  - Mass assignment: /update-profile accepts any field including 'role'
"""
import hashlib
from flask import Blueprint, render_template, request, session
from app.database import get_db

a06 = Blueprint('a06', __name__)

RESET_SALT = 'corp2024'  # BUG: static, known salt


def make_reset_token(username: str) -> str:
    # BUG: predictable — attacker can compute token for any username
    return hashlib.md5(f"{username}{RESET_SALT}".encode()).hexdigest()


@a06.route('/')
def index():
    return render_template('a06/index.html')


@a06.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        db = get_db()
        user = db.execute(
            "SELECT * FROM a06_users WHERE username=? AND password=?",
            [username, password]
        ).fetchone()
        if user:
            session['a06_user'] = dict(user)
            return render_template('a06/dashboard.html', user=dict(user))
        error = "Invalid credentials"
    return render_template('a06/login.html', error=error)


# ── VULNERABLE: predictable password reset token ─────────────────────────────
@a06.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    token = None
    message = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        db = get_db()
        user = db.execute(
            "SELECT * FROM a06_users WHERE username=?", [username]
        ).fetchone()
        if user:
            token = make_reset_token(username)
            message = f"Reset link sent to {user['email']} (token shown here for demo)"
        else:
            message = "User not found"
    return render_template('a06/forgot_password.html', token=token, message=message)


@a06.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    message = None
    if request.method == 'POST':
        username  = request.form.get('username', '')
        token     = request.form.get('token', '')
        new_pass  = request.form.get('new_password', '')
        expected  = make_reset_token(username)
        if token == expected:
            db = get_db()
            db.execute("UPDATE a06_users SET password=? WHERE username=?",
                       [new_pass, username])
            db.commit()
            message = f"Password for '{username}' reset successfully!"
        else:
            message = "Invalid token."
    return render_template('a06/reset_password.html', message=message)


# ── VULNERABLE: business logic — negative quantity ────────────────────────────
@a06.route('/cart', methods=['GET', 'POST'])
def cart():
    message = None
    items = [
        {'name': 'Laptop', 'price': 999.99},
        {'name': 'Phone',  'price': 499.99},
    ]
    total = None
    if request.method == 'POST':
        item_name = request.form.get('item')
        quantity  = int(request.form.get('quantity', 1))
        price     = next((i['price'] for i in items if i['name'] == item_name), 0)
        # BUG: no validation that quantity > 0
        total   = price * quantity
        message = (f"Added {quantity}× {item_name} @ ${price:.2f} each. "
                   f"Subtotal: ${total:.2f}")
    return render_template('a06/cart.html', items=items, message=message, total=total)


# ── VULNERABLE: mass assignment ───────────────────────────────────────────────
@a06.route('/update-profile', methods=['GET', 'POST'])
def update_profile():
    message = None
    if request.method == 'POST':
        if 'a06_user' not in session:
            return "Not logged in", 401
        db = get_db()
        # BUG: accepts any POST field including 'role' or 'balance'
        allowed_fields = request.form.to_dict()
        for field, value in allowed_fields.items():
            if field != 'username':
                db.execute(
                    f"UPDATE a06_users SET {field}=? WHERE username=?",
                    [value, session['a06_user']['username']]
                )
        db.commit()
        updated = db.execute(
            "SELECT * FROM a06_users WHERE username=?",
            [session['a06_user']['username']]
        ).fetchone()
        session['a06_user'] = dict(updated)
        message = f"Profile updated: {dict(updated)}"
    return render_template('a06/update_profile.html',
                           user=session.get('a06_user'), message=message)
