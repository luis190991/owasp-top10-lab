"""
A01:2025 – Broken Access Control
Vulnerabilities:
  - IDOR: /profile/<id> returns ANY user's data (including credit card)
  - Missing role check: /admin accessible by regular users
  - IDOR on orders: /orders/<id> returns any order
"""
from flask import Blueprint, render_template, session, redirect, url_for, request, jsonify
from app.database import get_db

a01 = Blueprint('a01', __name__)


@a01.route('/')
def index():
    return render_template('a01/index.html')


@a01.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        db = get_db()
        user = db.execute(
            "SELECT * FROM a01_users WHERE username = ?", [username]
        ).fetchone()
        if user:
            session['a01_user'] = dict(user)
            return redirect(url_for('a01.profile', user_id=user['id']))
        error = "User not found"
    return render_template('a01/login.html', error=error)


@a01.route('/logout')
def logout():
    session.pop('a01_user', None)
    return redirect(url_for('a01.index'))


# ── VULNERABLE: no ownership check ──────────────────────────────────────────
@a01.route('/profile/<int:user_id>')
def profile(user_id):
    db = get_db()
    # BUG: fetches ANY user_id without checking session ownership
    user = db.execute(
        "SELECT * FROM a01_users WHERE id = ?", [user_id]
    ).fetchone()
    if not user:
        return "User not found", 404
    return render_template('a01/profile.html', user=user,
                           current_user=session.get('a01_user'))


# ── VULNERABLE: no role check on admin panel ─────────────────────────────────
@a01.route('/admin')
def admin():
    db = get_db()
    # BUG: no check that session user has role='admin'
    if 'a01_user' not in session:
        return redirect(url_for('a01.login'))
    users = db.execute("SELECT * FROM a01_users").fetchall()
    return render_template('a01/admin.html', users=users,
                           current_user=session.get('a01_user'))


# ── VULNERABLE: IDOR on orders ───────────────────────────────────────────────
@a01.route('/orders/<int:order_id>')
def order(order_id):
    db = get_db()
    # BUG: any authenticated user can view any order
    if 'a01_user' not in session:
        return redirect(url_for('a01.login'))
    row = db.execute(
        "SELECT * FROM a01_orders WHERE id = ?", [order_id]
    ).fetchone()
    if not row:
        return "Order not found", 404
    return render_template('a01/order.html', order=row,
                           current_user=session['a01_user'])


@a01.route('/my-orders')
def my_orders():
    if 'a01_user' not in session:
        return redirect(url_for('a01.login'))
    db = get_db()
    uid = session['a01_user']['id']
    orders = db.execute(
        "SELECT * FROM a01_orders WHERE user_id = ?", [uid]
    ).fetchall()
    return render_template('a01/my_orders.html', orders=orders,
                           current_user=session['a01_user'])
