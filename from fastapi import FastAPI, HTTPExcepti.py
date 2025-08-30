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
