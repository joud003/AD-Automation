"""
سكربت لإنشاء (أو تحديث كلمة مرور) حساب HR لتسجيل الدخول بالواجهة.
يشتغل مرة وحدة يدويًا من الـ terminal، مش endpoint بالـ API —
هيك ما في تسجيل حسابات عشوائي مفتوح لأي حد يوصل للسيرفر.

الاستخدام:
    python create_user.py
"""

import base64
import getpass
import hashlib
import secrets
import sqlite3
from datetime import datetime

DB_PATH = "audit.db"


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return base64.b64encode(salt).decode() + ":" + base64.b64encode(dk).decode()


def main():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()

    username = input("Username: ").strip()
    if not username:
        print("Username can't be empty.")
        return

    password = getpass.getpass("Password: ")
    if len(password) < 8:
        print("Password must be at least 8 characters.")
        return
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords don't match.")
        return

    password_hash = hash_password(password)
    existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()

    if existing:
        conn.execute("UPDATE users SET password_hash = ? WHERE username = ?", (password_hash, username))
        print(f"Password updated for existing user '{username}'.")
    else:
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, password_hash, datetime.now().isoformat())
        )
        print(f"User '{username}' created.")

    conn.commit()
    conn.close()


if __name__ == "__main__":
    main()
