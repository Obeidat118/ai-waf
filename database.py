"""
database.py
------------
Implements the schema with 6-digit OTP verification support.
"""
import hashlib
import hmac
import os
import random
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aiwaf.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS companies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    website_url TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id INTEGER NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    is_verified INTEGER NOT NULL DEFAULT 0,
    otp_code TEXT,
    otp_expires TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (company_id) REFERENCES companies(id)
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id INTEGER NOT NULL,
    source_ip TEXT,
    method TEXT,
    url TEXT,
    layer1_result TEXT,       -- Normal / Malicious
    layer2_result TEXT,       -- attack type, NULL if Normal
    status TEXT,              -- allowed / blocked / flagged
    created_at TEXT NOT NULL,
    FOREIGN KEY (company_id) REFERENCES companies(id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id INTEGER NOT NULL,
    log_id INTEGER,
    attack_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (company_id) REFERENCES companies(id),
    FOREIGN KEY (log_id) REFERENCES logs(id)
);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


# ---------- password hashing (PBKDF2-HMAC-SHA256, stdlib only) ----------

def hash_password(password: str, salt: bytes = None):
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return digest.hex(), salt.hex()


def verify_password(password: str, password_hash: str, salt_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    digest, _ = hash_password(password, salt)
    return hmac.compare_digest(digest, password_hash)


# ---------- companies / admins with OTP ----------

def create_company_and_admin(company_name, website_url, email, password):
    now = datetime.utcnow().isoformat()
    pw_hash, pw_salt = hash_password(password)
    # توليد رمز OTP مكون من 6 أرقام عند التسجيل
    otp = f"{random.randint(0, 999999):06d}"
    expires = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
    
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO companies (name, website_url, created_at) VALUES (?, ?, ?)",
            (company_name, website_url, now),
        )
        company_id = cur.lastrowid
        conn.execute(
            """INSERT INTO admins (company_id, email, password_hash, password_salt, is_verified,
                                   otp_code, otp_expires, created_at)
                VALUES (?, ?, ?, ?, 0, ?, ?, ?)""",
            (company_id, email, pw_hash, pw_salt, otp, expires, now),
        )
        return company_id, otp


def get_admin_by_email(email):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM admins WHERE email = ?", (email,)).fetchone()
        return dict(row) if row else None


def get_admin_by_otp(otp_code):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM admins WHERE otp_code = ?", (otp_code,)).fetchone()
        return dict(row) if row else None


def mark_admin_verified(admin_id):
    with get_conn() as conn:
        conn.execute(
            "UPDATE admins SET is_verified = 1, otp_code = NULL, otp_expires = NULL WHERE id = ?",
            (admin_id,),
        )


def set_new_verification_token(admin_id):
    # تحديث وتوليد OTP جديد من 6 أرقام في حال طلب إعادة إرسال الرمز
    otp = f"{random.randint(0, 999999):06d}"
    expires = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
    with get_conn() as conn:
        conn.execute(
            "UPDATE admins SET otp_code = ?, otp_expires = ? WHERE id = ?",
            (otp, expires, admin_id),
        )
    return otp


def get_company(company_id):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM companies WHERE id = ?", (company_id,)).fetchone()
        return dict(row) if row else None


# ---------- logs / alerts (As is, perfectly preserved) ----------

def insert_log(company_id, source_ip, method, url, layer1_result, layer2_result, status):
    now = datetime.utcnow().isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO logs (company_id, source_ip, method, url, layer1_result, layer2_result, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (company_id, source_ip, method, url, layer1_result, layer2_result, status, now),
        )
        return cur.lastrowid


def insert_alert(company_id, log_id, attack_type, severity, message):
    now = datetime.utcnow().isoformat()
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO alerts (company_id, log_id, attack_type, severity, message, created_at)
                VALUES (?, ?, ?, ?, ?, ?)""",
            (company_id, log_id, attack_type, severity, message, now),
        )


def get_logs(company_id, limit=100):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM logs WHERE company_id = ? ORDER BY id DESC LIMIT ?",
            (company_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_alerts(company_id, limit=100):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE company_id = ? ORDER BY id DESC LIMIT ?",
            (company_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_dashboard_stats(company_id):
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM logs WHERE company_id=?", (company_id,)).fetchone()["c"]
        blocked = conn.execute(
            "SELECT COUNT(*) c FROM logs WHERE company_id=? AND status='blocked'", (company_id,)
        ).fetchone()["c"]
        alerts = conn.execute("SELECT COUNT(*) c FROM alerts WHERE company_id=?", (company_id,)).fetchone()["c"]
        by_type = conn.execute(
            """SELECT COALESCE(layer2_result,'Normal') AS attack_type, COUNT(*) c
                FROM logs WHERE company_id=? GROUP BY attack_type""",
            (company_id,),
        ).fetchall()
        return {
            "total_requests": total,
            "blocked_attacks": blocked,
            "alerts": alerts,
            "by_type": {r["attack_type"]: r["c"] for r in by_type},
        }


def get_report_data(company_id):
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT COALESCE(layer2_result,'Normal') AS attack_type, status, COUNT(*) c
                FROM logs WHERE company_id=? GROUP BY attack_type, status""",
            (company_id,),
        ).fetchall()
        return [dict(r) for r in rows]