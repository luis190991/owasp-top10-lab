"""
A04:2025 – Cryptographic Failures
Vulnerabilities:
  - Passwords stored as unsalted MD5 hashes (trivially crackable)
  - Sensitive data "encrypted" with base64 (not encryption)
  - Weak JWT-like token using MD5
  - Hardcoded encryption key
"""
import hashlib
import base64
import json
import time
from flask import Blueprint, render_template, request, jsonify
from app.database import get_db

a04 = Blueprint('a04', __name__)

# BUG: hardcoded key
HARDCODED_KEY = b'SuperSecret1234!'


def md5_hash(value: str) -> str:
    return hashlib.md5(value.encode()).hexdigest()


def fake_encrypt(data: str) -> str:
    """BUG: base64 is encoding, not encryption."""
    return base64.b64encode(data.encode()).decode()


def fake_decrypt(token: str) -> str:
    return base64.b64decode(token.encode()).decode()


def weak_token(username: str) -> str:
    """BUG: token is MD5 of username + static string — predictable."""
    return hashlib.md5(f"{username}:static_salt_2024".encode()).hexdigest()


@a04.route('/')
def index():
    return render_template('a04/index.html')


# ── Shows stored MD5 hashes directly ─────────────────────────────────────────
@a04.route('/hashes')
def show_hashes():
    db = get_db()
    users = db.execute("SELECT id, username, password_hash FROM a04_users").fetchall()
    return render_template('a04/hashes.html', users=users)


# ── Login with MD5 comparison ─────────────────────────────────────────────────
@a04.route('/login', methods=['GET', 'POST'])
def login():
    result = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        db = get_db()
        # BUG: unsalted MD5
        h = md5_hash(password)
        user = db.execute(
            "SELECT * FROM a04_users WHERE username=? AND password_hash=?",
            [username, h]
        ).fetchone()
        if user:
            token = weak_token(username)
            result = {
                'status': 'success',
                'user': username,
                'secret_note': user['secret_note'],
                'session_token': token,
                'token_note': 'Token = MD5(username + static_salt)'
            }
        else:
            result = {'status': 'fail', 'message': 'Bad credentials'}
    return render_template('a04/login.html', result=result)


# ── "Secure" storage using base64 ────────────────────────────────────────────
@a04.route('/store', methods=['GET', 'POST'])
def store():
    encoded = decoded = None
    if request.method == 'POST':
        action = request.form.get('action')
        data   = request.form.get('data', '')
        if action == 'encode':
            encoded = fake_encrypt(data)
        elif action == 'decode':
            try:
                decoded = fake_decrypt(data)
            except Exception:
                decoded = 'Invalid base64'
    return render_template('a04/store.html', encoded=encoded, decoded=decoded)


# ── MD5 hash tool ─────────────────────────────────────────────────────────────
@a04.route('/hash-tool', methods=['GET', 'POST'])
def hash_tool():
    result = None
    if request.method == 'POST':
        value = request.form.get('value', '')
        result = {
            'input': value,
            'md5':    hashlib.md5(value.encode()).hexdigest(),
            'sha1':   hashlib.sha1(value.encode()).hexdigest(),
            'sha256': hashlib.sha256(value.encode()).hexdigest(),
        }
    return render_template('a04/hash_tool.html', result=result)
