from fastapi import FastAPI, HTTPException, Depends, Header, status
from pydantic import BaseModel, EmailStr, constr
import bcrypt, secrets, sqlite3
from typing import Optional, Dict
from uuid import uuid4
app = FastAPI(title="Signup / Login with SQLite")

# ------------------ دیتابیس SQLite ------------------
def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


with get_db() as db:
    db.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL
    )
    """)
    db.commit()
# ------------------ مدل‌های Pydantic ------------------
class UserCreate(BaseModel):
    first_name: str
    last_name: str
    username: constr(min_length=3, max_length=50, strip_whitespace=True)
    email: EmailStr
    password: constr(min_length=8)
    role: Optional[str] = "user"

class UserLogin(BaseModel):
    username_or_email: str
    password: str
class UserPublic(BaseModel):
    id: str
    first_name: str
    last_name: str
    username: str
    email: EmailStr
    role: str

class SignupResponse(BaseModel):
    user: UserPublic
class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublic

def hash_password(plain_password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))

sessions: Dict[str, str] = {}   # token -> user_id

def get_current_user(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing or invalid authorization header")
    token = authorization.split(" ", 1)[1]
    user_id = sessions.get(token)
    if not user_id:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="user not found")
        return dict(row)

@app.post("/signup", response_model=SignupResponse, status_code=status.HTTP_201_CREATED)
def signup(payload: UserCreate):
    with get_db() as db:
        if db.execute("SELECT 1 FROM users WHERE username = ?", (payload.username,)).fetchone():
            raise HTTPException(status_code=400, detail="username already exists")
        if db.execute("SELECT 1 FROM users WHERE email = ?", (payload.email,)).fetchone():
            raise HTTPException(status_code=400, detail="email already exists")

        user_id = str(uuid4())
        pwd_hash = hash_password(payload.password)

        db.execute("""
        INSERT INTO users (id, first_name, last_name, username, email, password_hash, role)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, payload.first_name, payload.last_name, payload.username,
              payload.email, pwd_hash, payload.role))
        db.commit()

        return {"user": UserPublic(
            id=user_id,
            first_name=payload.first_name,
            last_name=payload.last_name,
            username=payload.username,
            email=payload.email,
            role=payload.role
        )}


@app.post("/login", response_model=LoginResponse)
def login(payload: UserLogin):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (payload.username_or_email, payload.username_or_email)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="invalid credentials")

        user = dict(row)
        if not verify_password(payload.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="invalid credentials")

        # توکن ساده (نه JWT)
        token = secrets.token_urlsafe(32)
        sessions[token] = user["id"]

        return {"access_token": token, "token_type": "bearer",
                "user": UserPublic(
                    id=user["id"],
                    first_name=user["first_name"],
                    last_name=user["last_name"],
                    username=user["username"],
                    email=user["email"],
                    role=user["role"]
                )}

@app.get("/me", response_model=UserPublic)
def me(current=Depends(get_current_user)):
    return UserPublic(**current)
