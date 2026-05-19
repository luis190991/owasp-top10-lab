"""
A07:2025 – Authentication Failures
Vulnerabilities:
  - No brute-force / account lockout protection
  - Weak session token: sequential integer stored in cookie
  - "Remember me" stores plaintext password in cookie
  - No MFA, no password complexity enforcement
  - Session not invalidated on logout (old token still works)
"""
from flask import (Blueprint, render_template, request, session,
                   make_response, redirect, url_for)
from app.database import get_db

a07 = Blueprint('a07', __name__)

# In-memory "session store" — id → username. Sequential = predictable.
_sessions: dict[int, str] = {}
_next_sid = 1


def new_session(username: str) -> int:
    global _next_sid
    sid = _next_sid
    _sessions[sid] = username
    _next_sid += 1
    return sid


@a07.route('/')
def index():
    return render_template('a07/index.html', sessions=dict(_sessions))


# ── VULNERABLE: no lockout, no rate limit ────────────────────────────────────
@a07.route('/login', methods=['GET', 'POST'])
def login():
    result = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        remember = request.form.get('remember')
        db = get_db()
        user = db.execute(
            "SELECT * FROM a07_users WHERE username=? AND password=?",
            [username, password]
        ).fetchone()
        if user:
            sid = new_session(username)
            resp = make_response(
                render_template('a07/dashboard.html',
                                user=dict(user), sid=sid,
                                sessions=dict(_sessions))
            )
            resp.set_cookie('session_id', str(sid))
            if remember:
                # BUG: plaintext password in cookie
                resp.set_cookie('remember_me', f"{username}:{password}", max_age=86400*30)
            return resp
        result = {'status': 'fail', 'message': 'Bad credentials'}
    return render_template('a07/login.html', result=result)


# ── VULNERABLE: session token brute-forceable ─────────────────────────────────
@a07.route('/profile')
def profile():
    sid_cookie = request.cookies.get('session_id', '')
    remember   = request.cookies.get('remember_me', '')
    username   = None

    if sid_cookie and sid_cookie.isdigit():
        username = _sessions.get(int(sid_cookie))

    if not username and remember:
        # BUG: auto-login from plaintext cookie
        parts = remember.split(':', 1)
        if len(parts) == 2:
            uname, pwd = parts
            db = get_db()
            user = db.execute(
                "SELECT * FROM a07_users WHERE username=? AND password=?",
                [uname, pwd]
            ).fetchone()
            if user:
                username = uname

    if not username:
        return redirect(url_for('a07.login'))

    db = get_db()
    user = db.execute("SELECT * FROM a07_users WHERE username=?", [username]).fetchone()
    return render_template('a07/profile.html', user=dict(user) if user else {},
                           sid=sid_cookie, sessions=dict(_sessions))


# ── VULNERABLE: logout doesn't invalidate token ───────────────────────────────
@a07.route('/logout')
def logout():
    # BUG: doesn't remove sid from _sessions — old token still works
    resp = make_response(redirect(url_for('a07.index')))
    resp.delete_cookie('session_id')
    return resp
