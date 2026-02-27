import sqlite3
import bcrypt
import random
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

verification_codes = {}


def init_db():
    conn = sqlite3.connect("vienna_users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            is_banned INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


init_db()


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class VerifyRequest(BaseModel):
    email: str
    code: str


class LoginRequest(BaseModel):
    username: str
    password: str


class AdminRequest(BaseModel):
    requester: str


class AdminAction(BaseModel):
    requester: str
    target: str
    action: str


def is_admin(username: str) -> bool:
    conn = sqlite3.connect("vienna_users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
    res = cursor.fetchone()
    conn.close()
    return res is not None and res[0] == "admin"


@app.post("/api/request_code")
def request_code(user: RegisterRequest):
    conn = sqlite3.connect("vienna_users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (user.username, user.email))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Логин или Email уже занят!")
    conn.close()

    code = str(random.randint(100000, 999999))
    verification_codes[user.email] = {"code": code, "username": user.username, "password": user.password}

    print(f"\n{'=' * 40}\n📧 [EMAIL SIMULATOR]\nКому: {user.email}\nКод подтверждения: {code}\n{'=' * 40}\n")
    return {"message": "Код отправлен!"}


@app.post("/api/verify_code")
def verify_code(data: VerifyRequest):
    if data.email not in verification_codes or verification_codes[data.email]["code"] != data.code:
        raise HTTPException(status_code=400, detail="Неверный код!")

    saved_data = verification_codes[data.email]
    conn = sqlite3.connect("vienna_users.db")
    cursor = conn.cursor()

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(saved_data["password"].encode('utf-8'), salt)
    role = 'admin' if saved_data["username"].lower() == 'admin' else 'user'

    cursor.execute("INSERT INTO users (username, email, password, role, is_banned) VALUES (?, ?, ?, ?, 0)",
                   (saved_data["username"], data.email, hashed_password, role))
    conn.commit()
    conn.close()
    del verification_codes[data.email]
    return {"message": "Успех!"}


@app.post("/api/login")
def login_user(user: LoginRequest):
    conn = sqlite3.connect("vienna_users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password, role, is_banned FROM users WHERE username = ?", (user.username,))
    result = cursor.fetchone()
    conn.close()

    if result is None: raise HTTPException(status_code=400, detail="Ошибка входа")
    stored_password, role, is_banned = result

    if is_banned == 1: raise HTTPException(status_code=403, detail="Banned!")

    if bcrypt.checkpw(user.password.encode('utf-8'), stored_password):
        return {"message": "Успех!", "role": role, "username": user.username}
    else:
        raise HTTPException(status_code=400, detail="Ошибка входа")


@app.post("/api/admin/users")
def get_all_users(req: AdminRequest):
    if not is_admin(req.requester): raise HTTPException(status_code=403, detail="No access")
    conn = sqlite3.connect("vienna_users.db")
    cur = conn.cursor()
    cur.execute("SELECT username, role, is_banned FROM users")
    users = [{"username": r[0], "role": r[1], "is_banned": bool(r[2])} for r in cur.fetchall()]
    conn.close()
    return {"users": users}


@app.post("/api/admin/action")
def admin_action(req: AdminAction):
    if not is_admin(req.requester) or req.requester == req.target: raise HTTPException(status_code=400)
    conn = sqlite3.connect("vienna_users.db")
    cur = conn.cursor()
    if req.action == "ban":
        cur.execute("UPDATE users SET is_banned = 1 WHERE username = ?", (req.target,))
    elif req.action == "unban":
        cur.execute("UPDATE users SET is_banned = 0 WHERE username = ?", (req.target,))
    elif req.action == "promote":
        cur.execute("UPDATE users SET role = 'admin' WHERE username = ?", (req.target,))
    elif req.action == "demote":
        cur.execute("UPDATE users SET role = 'user' WHERE username = ?", (req.target,))
    conn.commit()
    conn.close()
    return {"message": "Success"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
