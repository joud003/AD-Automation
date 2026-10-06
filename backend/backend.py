"""
Backend — AD Onboarding & Offboarding Automation
FastAPI server يستقبل طلبات تزويد/تعطيل/إعادة تفعيل الموظفين من واجهة الويب،
ويخزّنها بقاعدة بيانات SQLite دائمة (audit.db) بحيث ما تضيع عند إعادة تشغيل السيرفر.
الوكيل (على الـ VM) ياخذ الطلبات المعلقة وينفذها على Active Directory.
"""

import base64
import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import Response
from pydantic import BaseModel

app = FastAPI(title="AD Onboarding Backend")

# ---------------------------------------------------------------
# CORS Middleware — لازم يكون قبل أي endpoint
# ---------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # لاحقًا، بعد الإطلاق، حددي النطاق الحقيقي بدل *
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "audit.db"

# ---------------------------------------------------------------
# مفتاح التوقيع السري للـ JWT — يتولد مرة وحدة ويُحفظ بملف محلي
# (بدل ما يكون ثابت بالكود، وبدل ما يتغير كل إعادة تشغيل ويلغي كل الجلسات)
# ---------------------------------------------------------------
SECRET_KEY_PATH = "secret.key"

if os.path.exists(SECRET_KEY_PATH):
    with open(SECRET_KEY_PATH, "r") as f:
        SECRET_KEY = f.read().strip()
else:
    SECRET_KEY = secrets.token_hex(32)
    with open(SECRET_KEY_PATH, "w") as f:
        f.write(SECRET_KEY)


# ---------------------------------------------------------------
# الاتصال بقاعدة البيانات + إنشاء الجدول لو ما كان موجود
# ---------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            username TEXT,
            department TEXT,
            password TEXT,
            reason TEXT,
            status TEXT NOT NULL,
            error TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            api_key TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            last_seen TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


init_db()


# ---------------------------------------------------------------
# نماذج البيانات
# ---------------------------------------------------------------
class UserRequest(BaseModel):
    first_name: str
    last_name: str
    username: str
    department: str
    password: str


class BulkUserRequest(BaseModel):
    employees: List[UserRequest]


class OffboardRequest(BaseModel):
    username: str
    reason: Optional[str] = None


class ReactivateRequest(BaseModel):
    username: str
    reason: Optional[str] = None


class RequestResult(BaseModel):
    status: str                    # "done" أو "failed"
    username: Optional[str] = None
    error: Optional[str] = None


class AgentRegister(BaseModel):
    name: str


class LoginRequest(BaseModel):
    username: str
    password: str


# ---------------------------------------------------------------
# تجزئة كلمات المرور (PBKDF2 — من مكتبة Python القياسية، بدون أي مكتبة خارجية)
# ---------------------------------------------------------------
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return base64.b64encode(salt).decode() + ":" + base64.b64encode(dk).decode()


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_b64, dk_b64 = stored_hash.split(":")
        salt = base64.b64decode(salt_b64)
        expected_dk = base64.b64decode(dk_b64)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return hmac.compare_digest(dk, expected_dk)


# =================================================================
# DEMO MODE — للعرض العام (زي رابط تحطيه بمنشور LinkedIn)
# فعّليه بمتغير بيئة: DEMO_MODE=1
#
# ما بيتصل بأي Active Directory حقيقي. بدل ما ينتظر وكيل PowerShell
# فعلي، خيط بالخلفية "يتظاهر" إنه الوكيل: ياخذ الطلبات المعلّقة
# ويكملها لوحده بعد ثواني، بس عشان الزوار يشوفوا الفلو كامل يشتغل
# بدون ما يكون عندك VM أو AD حقيقي شغالين ٢٤/٧ لأجل زوار LinkedIn.
# =================================================================
DEMO_MODE = os.getenv("DEMO_MODE") == "1"
DEMO_USERNAME = "demo"
DEMO_PASSWORD = "demo1234"


def seed_demo_user():
    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE username = ?", (DEMO_USERNAME,)).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (DEMO_USERNAME, hash_password(DEMO_PASSWORD), datetime.now().isoformat())
        )
        conn.commit()
    conn.close()


def demo_agent_loop():
    """يشتغل بالخلفية بس بوضع الديمو. كل بضع ثواني يفحص الطلبات
    المعلّقة ويكملها هو نفسه (بدل الوكيل الحقيقي على الـ VM)."""
    while True:
        try:
            conn = get_db()
            pending = conn.execute(
                "SELECT id, action, username FROM requests WHERE status = 'pending'"
            ).fetchall()
            conn.close()

            for r in pending:
                time.sleep(3)   # تأخير بسيط يحاكي وقت استجابة وكيل حقيقي
                conn = get_db()
                conn.execute("UPDATE requests SET status = 'done' WHERE id = ?", (r["id"],))
                conn.commit()
                conn.close()
        except Exception:
            pass
        time.sleep(2)


if DEMO_MODE:
    seed_demo_user()
    threading.Thread(target=demo_agent_loop, daemon=True).start()


# ---------------------------------------------------------------
# JWT بسيط (HS256) — منفّذ يدويًا بمكتبات Python القياسية فقط
# (مافي حاجة نثبّت PyJWT أو أي مكتبة خارجية إضافية)
# ---------------------------------------------------------------
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_token(payload: dict, expires_in_seconds: int = 8 * 3600) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    body = dict(payload)
    body["exp"] = int(time.time()) + expires_in_seconds
    header_b64 = _b64url_encode(json.dumps(header).encode())
    payload_b64 = _b64url_encode(json.dumps(body).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(SECRET_KEY.encode(), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def decode_token(token: str) -> dict:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError:
        raise HTTPException(status_code=401, detail="Malformed token")

    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected_signature = hmac.new(SECRET_KEY.encode(), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(_b64url_encode(expected_signature), signature_b64):
        raise HTTPException(status_code=401, detail="Invalid token signature")

    payload = json.loads(_b64url_decode(payload_b64))
    if payload.get("exp", 0) < time.time():
        raise HTTPException(status_code=401, detail="Token expired, please log in again")
    return payload


# ---------------------------------------------------------------
# Dependency: تتحقق من هيدر Authorization: Bearer <token>
# تُستخدم لحماية كل الـ endpoints اللي مدير HR يستخدمها من الواجهة
# ---------------------------------------------------------------
def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization[len("Bearer "):]
    payload = decode_token(token)
    return {"id": payload.get("user_id"), "username": payload.get("sub")}


# ---------------------------------------------------------------
# التحقق من API Key — يُستخدم كـ Dependency على الـ endpoints
# اللي الوكيل (مش الواجهة) هو اللي يناديها: /api/pending و /api/result
# الوكيل لازم يرسل الهيدر: X-API-Key: <المفتاح>
# ---------------------------------------------------------------
def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    conn = get_db()
    row = conn.execute(
        "SELECT id, name FROM agents WHERE api_key = ?", (x_api_key,)
    ).fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid API key")

    conn.execute(
        "UPDATE agents SET last_seen = ? WHERE id = ?",
        (datetime.now().isoformat(), row["id"])
    )
    conn.commit()
    conn.close()
    return {"id": row["id"], "name": row["name"]}


# ---------------------------------------------------------------
# GET /api/health — فحص إن السيرفر شغال
# (لازم يكون على مسار غير "/" وإلا يمنع StaticFiles من تقديم index.html
#  لأن FastAPI بيطابق "/" مع هالراوت مباشرة قبل ما يوصل للـ mount بالأسفل)
# ---------------------------------------------------------------
@app.get("/api/health")
def read_root():
    return {"message": "Backend is running", "demo_mode": DEMO_MODE}


# ---------------------------------------------------------------
# Authentication — تسجيل دخول مدير HR
# ---------------------------------------------------------------

@app.post("/api/auth/login")
def login(req: LoginRequest):
    conn = get_db()
    row = conn.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?", (req.username,)
    ).fetchone()
    conn.close()

    if not row or not verify_password(req.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    token = create_token({"sub": row["username"], "user_id": row["id"]})
    return {"access_token": token, "token_type": "bearer", "username": row["username"]}


# JWT عديم الحالة (stateless) — ما في "إبطال" فعلي للتوكن من طرف السيرفر.
# هالـ endpoint موجود لشكل الـ API متكامل، بس تسجيل الخروج الحقيقي
# بيصير بحذف التوكن من المتصفح (localStorage) من طرف الواجهة.
@app.post("/api/auth/logout")
def logout(user: dict = Depends(get_current_user)):
    return {"message": "Logged out"}


@app.get("/api/auth/me")
def get_me(user: dict = Depends(get_current_user)):
    return user


# ---------------------------------------------------------------
# إدارة الوكلاء (Agents) و API Keys
# ---------------------------------------------------------------

# تسجيل وكيل جديد، وإنشاء API Key له. 🔒 يحتاج تسجيل دخول
# ⚠️ المفتاح الكامل يظهر مرة واحدة بس بهاد الرد — احفظيه فورًا بإعدادات الوكيل.
@app.post("/api/agents/register")
def register_agent(agent: AgentRegister, user: dict = Depends(get_current_user)):
    new_key = secrets.token_hex(24)   # 48-character random hex key
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO agents (name, api_key, created_at) VALUES (?, ?, ?)",
        (agent.name, new_key, datetime.now().isoformat())
    )
    conn.commit()
    agent_id = cur.lastrowid
    conn.close()
    return {"id": agent_id, "name": agent.name, "api_key": new_key}


# قائمة الوكلاء المسجّلين — المفتاح يظهر مقنّع (آخر 4 خانات بس). 🔒 يحتاج تسجيل دخول
@app.get("/api/agents")
def list_agents(user: dict = Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM agents ORDER BY id DESC").fetchall()
    conn.close()
    return [
        {
            "id": r["id"],
            "name": r["name"],
            "api_key_preview": "..." + r["api_key"][-4:],
            "created_at": r["created_at"],
            "last_seen": r["last_seen"],
        }
        for r in rows
    ]


# توليد مفتاح جديد لوكيل موجود (يلغي المفتاح القديم فورًا). 🔒 يحتاج تسجيل دخول
@app.post("/api/agents/{agent_id}/regenerate-key")
def regenerate_key(agent_id: int, user: dict = Depends(get_current_user)):
    conn = get_db()
    existing = conn.execute("SELECT id FROM agents WHERE id = ?", (agent_id,)).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Agent not found")

    new_key = secrets.token_hex(24)
    conn.execute("UPDATE agents SET api_key = ? WHERE id = ?", (new_key, agent_id))
    conn.commit()
    conn.close()
    return {"id": agent_id, "api_key": new_key}


# ---------------------------------------------------------------
# POST /api/request — مدير HR يرسل طلب موظف جديد
# 🔒 يحتاج تسجيل دخول
# ---------------------------------------------------------------
def insert_onboard_request(req: UserRequest) -> int:
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO requests
           (action, first_name, last_name, username, department, password, status, created_at)
           VALUES ('onboard', ?, ?, ?, ?, ?, 'pending', ?)""",
        (req.first_name, req.last_name, req.username, req.department,
         req.password, datetime.now().isoformat())
    )
    conn.commit()
    request_id = cur.lastrowid
    conn.close()
    return request_id


@app.post("/api/request")
def create_request(req: UserRequest, user: dict = Depends(get_current_user)):
    request_id = insert_onboard_request(req)
    return {"id": request_id, "status": "pending"}


# ---------------------------------------------------------------
# POST /api/request/bulk — مدير HR يضيف عدة موظفين دفعة وحدة
# (نفس منطق /api/request، بس بيكرر العملية لكل موظف بالقائمة
#  ويرجّع نتيجة كل واحد لحاله — لو واحد فشل، الباقي بضلوا يكملوا)
# 🔒 يحتاج تسجيل دخول
# ---------------------------------------------------------------
@app.post("/api/request/bulk")
def create_bulk_request(bulk: BulkUserRequest, user: dict = Depends(get_current_user)):
    if not bulk.employees:
        raise HTTPException(status_code=400, detail="employees list is empty")

    results = []
    for emp in bulk.employees:
        try:
            request_id = insert_onboard_request(emp)
            results.append({
                "id": request_id,
                "first_name": emp.first_name,
                "last_name": emp.last_name,
                "username": emp.username,
                "status": "pending",
            })
        except Exception as e:
            results.append({
                "id": None,
                "first_name": emp.first_name,
                "last_name": emp.last_name,
                "username": emp.username,
                "status": "failed",
                "error": str(e),
            })

    return {"count": len(results), "requests": results}


# ---------------------------------------------------------------
# POST /api/offboard — مدير HR يطلب تعطيل حساب موظف
# 🔒 يحتاج تسجيل دخول
# ---------------------------------------------------------------
@app.post("/api/offboard")
def create_offboard_request(req: OffboardRequest, user: dict = Depends(get_current_user)):
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO requests (action, username, reason, status, created_at)
           VALUES ('offboard', ?, ?, 'pending', ?)""",
        (req.username, req.reason, datetime.now().isoformat())
    )
    conn.commit()
    request_id = cur.lastrowid
    conn.close()
    return {"id": request_id, "status": "pending"}


# ---------------------------------------------------------------
# POST /api/reactivate — إعادة تفعيل حساب موظف رجع للشركة
# نفس منطق /api/offboard بالضبط، بس action مختلف.
# الوكيل لازم يستخدم Enable-ADAccount لما يشوف action == "reactivate"
# 🔒 يحتاج تسجيل دخول
# ---------------------------------------------------------------
@app.post("/api/reactivate")
def create_reactivate_request(req: ReactivateRequest, user: dict = Depends(get_current_user)):
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO requests (action, username, reason, status, created_at)
           VALUES ('reactivate', ?, ?, 'pending', ?)""",
        (req.username, req.reason, datetime.now().isoformat())
    )
    conn.commit()
    request_id = cur.lastrowid
    conn.close()
    return {"id": request_id, "status": "pending"}


# ---------------------------------------------------------------
# GET /api/pending — الوكيل يسأل: في طلبات جديدة؟
# 🔒 محمي بـ API Key — لازم هيدر X-API-Key صحيح
# ---------------------------------------------------------------
@app.get("/api/pending")
def get_pending(agent: dict = Depends(verify_api_key)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM requests WHERE status = 'pending'").fetchall()
    conn.close()
    pending = [dict(r) for r in rows]
    return {"count": len(pending), "requests": pending}


# ---------------------------------------------------------------
# POST /api/result/{id} — الوكيل يرد بنتيجة التنفيذ
# 🔒 محمي بـ API Key — لازم هيدر X-API-Key صحيح
# ---------------------------------------------------------------
@app.post("/api/result/{request_id}")
def post_result(request_id: int, result: RequestResult, agent: dict = Depends(verify_api_key)):
    conn = get_db()
    existing = conn.execute("SELECT id FROM requests WHERE id = ?", (request_id,)).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Request not found")

    if result.username:
        conn.execute(
            "UPDATE requests SET status = ?, username = ?, error = ? WHERE id = ?",
            (result.status, result.username, result.error, request_id)
        )
    else:
        conn.execute(
            "UPDATE requests SET status = ?, error = ? WHERE id = ?",
            (result.status, result.error, request_id)
        )
    conn.commit()
    conn.close()
    return {"message": f"Result saved for request #{request_id}"}


# ---------------------------------------------------------------
# GET /api/status/{id} — مدير HR يتابع حالة الطلب من الواجهة
# 🔒 يحتاج تسجيل دخول
# ---------------------------------------------------------------
@app.get("/api/status/{request_id}")
def get_status(request_id: int, user: dict = Depends(get_current_user)):
    conn = get_db()
    r = conn.execute("SELECT * FROM requests WHERE id = ?", (request_id,)).fetchone()
    conn.close()
    if not r:
        raise HTTPException(status_code=404, detail="Request not found")

    return {
        "id": r["id"],
        "action": r["action"],
        "status": r["status"],
        "username": r["username"],
        "error": r["error"],
    }


# ---------------------------------------------------------------
# دالة مشتركة: تجيب سجلات التدقيق (مع فلترة اختيارية) بدون كلمة المرور
# ---------------------------------------------------------------
def fetch_audit_records(status: Optional[str] = None):
    conn = get_db()
    if status:
        rows = conn.execute(
            "SELECT * FROM requests WHERE status = ? ORDER BY id DESC", (status,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM requests ORDER BY id DESC").fetchall()
    conn.close()

    records = []
    for r in rows:
        d = dict(r)
        d.pop("password", None)   # لا نرجّع كلمة المرور بسجل التدقيق
        records.append(d)
    return records


# ---------------------------------------------------------------
# GET /api/audit — سجل التدقيق الكامل (كل الطلبات، مع فلترة اختيارية بالحالة)
# 🔒 يحتاج تسجيل دخول
# ---------------------------------------------------------------
@app.get("/api/audit")
def get_audit(status: Optional[str] = None, user: dict = Depends(get_current_user)):
    records = fetch_audit_records(status)
    return {"count": len(records), "requests": records}


# ---------------------------------------------------------------
# GET /api/audit/export — تصدير سجل التدقيق كملف CSV أو JSON للتحميل
# 🔒 يحتاج تسجيل دخول (تمرَّر كـ query param ?token=... لأن رابط التحميل
# المباشر ما بيقدر يرسل هيدر Authorization)
# ---------------------------------------------------------------
@app.get("/api/audit/export")
def export_audit(format: str = "csv", status: Optional[str] = None, token: Optional[str] = None):
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")
    decode_token(token)   # يرمي 401 تلقائيًا لو غير صالح أو منتهي

    records = fetch_audit_records(status)

    if format == "json":
        content = json.dumps(records, ensure_ascii=False, indent=2)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=audit_log.json"},
        )

    if format == "csv":
        buffer = io.StringIO()
        columns = ["id", "action", "first_name", "last_name", "username",
                   "department", "reason", "status", "error", "created_at"]
        writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for r in records:
            writer.writerow(r)
        return Response(
            content=buffer.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_log.csv"},
        )

    raise HTTPException(status_code=400, detail="format must be 'csv' or 'json'")


# ---------------------------------------------------------------
# تقديم واجهة الويب (index.html) من مجلد static
# لازم يكون هذا السطر آخر شي بالملف، بعد كل الـ endpoints فوق
# ---------------------------------------------------------------
app.mount("/", StaticFiles(directory="static", html=True), name="static")
