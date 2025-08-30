from fastapi import FastAPI, HTTPException, Depends, Header, status
from pydantic import BaseModel, EmailStr, constr
import bcrypt, secrets, sqlite3
from typing import Optional, Dict
from uuid import uuid4