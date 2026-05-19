import sqlite3
import hashlib
import os
from flask import g, current_app

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'lab.db')


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row

    # ── A01 tables ──────────────────────────────────────────────────────────
    db.execute("DROP TABLE IF EXISTS a01_users")
    db.execute("DROP TABLE IF EXISTS a01_orders")
    db.execute("""
        CREATE TABLE a01_users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT,
            role TEXT DEFAULT 'user',
            credit_card TEXT
        )
    """)
    db.execute("""
        CREATE TABLE a01_orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            item TEXT,
            amount REAL
        )
    """)
    db.executemany("INSERT INTO a01_users VALUES (?,?,?,?,?)", [
        (1, 'alice',  'alice@corp.com',  'user',  '4111-1111-1111-1111'),
        (2, 'bob',    'bob@corp.com',    'user',  '4222-2222-2222-2222'),
        (3, 'admin',  'admin@corp.com',  'admin', '4333-3333-3333-3333'),
    ])
    db.executemany("INSERT INTO a01_orders VALUES (?,?,?,?)", [
        (1, 1, 'Laptop',   999.99),
        (2, 2, 'Phone',    499.99),
        (3, 3, 'Server', 4999.99),
    ])

    # ── A04 / A07 shared users (MD5 passwords) ──────────────────────────────
    db.execute("DROP TABLE IF EXISTS a04_users")
    db.execute("""
        CREATE TABLE a04_users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT,
            secret_note TEXT
        )
    """)
    db.executemany("INSERT INTO a04_users VALUES (?,?,?,?)", [
        (1, 'alice', hashlib.md5(b'password123').hexdigest(), 'My dog name is Rex'),
        (2, 'bob',   hashlib.md5(b'bob123').hexdigest(),      'Server root pw: toor'),
        (3, 'carol', hashlib.md5(b'123456').hexdigest(),      'API key: sk-abc123xyz'),
    ])

    # ── A05 tables (injection) ───────────────────────────────────────────────
    db.execute("DROP TABLE IF EXISTS a05_users")
    db.execute("DROP TABLE IF EXISTS a05_products")
    db.execute("""
        CREATE TABLE a05_users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        )
    """)
    db.execute("""
        CREATE TABLE a05_products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL,
            category TEXT
        )
    """)
    db.executemany("INSERT INTO a05_users VALUES (?,?,?,?)", [
        (1, 'alice', 'alice_pass', 'user'),
        (2, 'admin', 'sup3r_s3cr3t', 'admin'),
    ])
    db.executemany("INSERT INTO a05_products VALUES (?,?,?,?)", [
        (1, 'Laptop',  999.99, 'Electronics'),
        (2, 'Phone',   499.99, 'Electronics'),
        (3, 'Desk',    299.99, 'Furniture'),
        (4, 'Chair',   199.99, 'Furniture'),
    ])

    # ── A06 tables (insecure design) ─────────────────────────────────────────
    db.execute("DROP TABLE IF EXISTS a06_users")
    db.execute("DROP TABLE IF EXISTS a06_reset_tokens")
    db.execute("DROP TABLE IF EXISTS a06_cart")
    db.execute("""
        CREATE TABLE a06_users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            balance REAL DEFAULT 100.0
        )
    """)
    db.execute("""
        CREATE TABLE a06_reset_tokens (
            token TEXT PRIMARY KEY,
            username TEXT,
            expires_at TEXT
        )
    """)
    db.execute("""
        CREATE TABLE a06_cart (
            id INTEGER PRIMARY KEY,
            username TEXT,
            item TEXT,
            quantity INTEGER,
            price REAL
        )
    """)
    db.executemany("INSERT INTO a06_users VALUES (?,?,?,?,?)", [
        (1, 'alice', 'alicepass', 'alice@corp.com', 100.0),
        (2, 'admin', 'adminpass', 'admin@corp.com', 9999.0),
    ])

    # ── A07 tables (auth failures) ───────────────────────────────────────────
    db.execute("DROP TABLE IF EXISTS a07_users")
    db.execute("""
        CREATE TABLE a07_users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user'
        )
    """)
    db.executemany("INSERT INTO a07_users VALUES (?,?,?,?)", [
        (1, 'alice', 'sunshine',   'user'),
        (2, 'admin', 'admin123',   'admin'),
        (3, 'bob',   'password',   'user'),
    ])

    # ── A09 tables (logging) ─────────────────────────────────────────────────
    db.execute("DROP TABLE IF EXISTS a09_transactions")
    db.execute("""
        CREATE TABLE a09_transactions (
            id INTEGER PRIMARY KEY,
            username TEXT,
            amount REAL,
            type TEXT,
            timestamp TEXT
        )
    """)
    db.executemany("INSERT INTO a09_transactions VALUES (?,?,?,?,?)", [
        (1, 'alice', 500.0,  'transfer', '2025-01-10 09:00:00'),
        (2, 'bob',   1200.0, 'deposit',  '2025-01-11 10:30:00'),
        (3, 'alice', 9999.0, 'transfer', '2025-01-12 03:17:00'),
    ])

    db.commit()
    db.close()
