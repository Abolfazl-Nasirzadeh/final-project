from fastapi import FastAPI, HTTPException, Depends, Header, status
from pydantic import BaseModel, EmailStr, constr
import bcrypt, secrets, sqlite3
from typing import Optional, Dict, List
from uuid import uuid4

app = FastAPI(title="Inventory Management Project")

# ------------------ دیتابیس SQLite ------------------
def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

with get_db() as db:
    # جدول کاربران (بخش نفر A)
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

    # جدول تأمین‌کنندگان (بخش نفر C)
    db.execute("""
    CREATE TABLE IF NOT EXISTS suppliers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT,
        delivery_time INTEGER,
        is_active BOOLEAN DEFAULT 1
    )
    """)

    # جدول محصولات (بخش نفر B)
    db.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        sku TEXT UNIQUE NOT NULL,
        price REAL NOT NULL,
        quantity INTEGER NOT NULL DEFAULT 0
    )
    """)

    # جدول سفارش‌های خرید (بخش نفر C)
    db.execute("""
    CREATE TABLE IF NOT EXISTS purchase_orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        supplier_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'draft',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (supplier_id) REFERENCES suppliers (id)
    )
    """)

    # جدول آیتم‌های سفارش خرید (بخش نفر C)
    db.execute("""
    CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        FOREIGN KEY (order_id) REFERENCES purchase_orders (id),
        FOREIGN KEY (product_id) REFERENCES products (id)
    )
    """)
    db.commit()

# ------------------ مدل‌های Pydantic ------------------
# ---- بخش Auth (نفر A) ----
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

# ---- بخش Supplier (نفر C) ----
class SupplierBase(BaseModel):
    name: str
    email: EmailStr
    phone: Optional[str] = None
    delivery_time: Optional[int] = None
    is_active: bool = True

class SupplierCreate(SupplierBase):
    pass

class SupplierUpdate(BaseModel):
    name: Optional[str]
    email: Optional[EmailStr]
    phone: Optional[str]
    delivery_time: Optional[int]
    is_active: Optional[bool]

class SupplierOut(SupplierBase):
    id: int

# ---- بخش PurchaseOrder (نفر C) ----
class OrderItemIn(BaseModel):
    product_id: int
    quantity: int

class PurchaseOrderCreate(BaseModel):
    supplier_id: int
    items: List[OrderItemIn]

class OrderItemOut(OrderItemIn):
    id: int

class PurchaseOrderOut(BaseModel):
    id: int
    supplier_id: int
    status: str
    created_at: str
    items: List[OrderItemOut]

class OrderStatusUpdate(BaseModel):
    new_status: str  # draft -> sent -> received -> closed

# ------------------ توابع امنیتی ------------------
def hash_password(plain_password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))

# ذخیره‌ی توکن‌ها
sessions: Dict[str, str] = {}

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

# ------------------ مسیرهای Auth (بخش نفر A) ------------------
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

# ------------------ مسیرهای Supplier (بخش نفر C) ------------------
@app.post("/suppliers", response_model=SupplierOut, status_code=201)
def create_supplier(payload: SupplierCreate):
    with get_db() as db:
        row = db.execute("SELECT 1 FROM suppliers WHERE email = ?", (payload.email,)).fetchone()
        if row:
            raise HTTPException(status_code=400, detail="supplier with this email exists")

        cur = db.execute("""
            INSERT INTO suppliers (name, email, phone, delivery_time, is_active)
            VALUES (?, ?, ?, ?, ?)
        """, (payload.name, payload.email, payload.phone, payload.delivery_time, payload.is_active))
        db.commit()
        supplier_id = cur.lastrowid
        return {**payload.dict(), "id": supplier_id}

@app.get("/suppliers", response_model=List[SupplierOut])
def get_suppliers():
    with get_db() as db:
        rows = db.execute("SELECT * FROM suppliers").fetchall()
        return [dict(row) for row in rows]

# ------------------ مسیرهای PurchaseOrder (بخش نفر C) ------------------
@app.post("/purchase-orders", response_model=PurchaseOrderOut, status_code=201)
def create_order(payload: PurchaseOrderCreate):
    with get_db() as db:
        supplier = db.execute("SELECT * FROM suppliers WHERE id = ?", (payload.supplier_id,)).fetchone()
        if not supplier:
            raise HTTPException(status_code=404, detail="supplier not found")

        cur = db.execute("INSERT INTO purchase_orders (supplier_id, status) VALUES (?, 'draft')",
                         (payload.supplier_id,))
        order_id = cur.lastrowid

        items_out = []
        for item in payload.items:
            product = db.execute("SELECT * FROM products WHERE id = ?", (item.product_id,)).fetchone()
            if not product:
                raise HTTPException(status_code=404, detail=f"product {item.product_id} not found")

            cur_item = db.execute("INSERT INTO order_items (order_id, product_id, quantity) VALUES (?, ?, ?)",
                                  (order_id, item.product_id, item.quantity))
            items_out.append({"id": cur_item.lastrowid, "product_id": item.product_id, "quantity": item.quantity})

        db.commit()

        return {
            "id": order_id,
            "supplier_id": payload.supplier_id,
            "status": "draft",
            "created_at": "NOW",
            "items": items_out
        }

@app.put("/purchase-orders/{order_id}/status")
def update_order_status(order_id: int, payload: OrderStatusUpdate):
    valid_statuses = ["draft", "sent", "received", "closed"]

    if payload.new_status not in valid_statuses:
        raise HTTPException(status_code=400, detail="invalid status")

    with get_db() as db:
        order = db.execute("SELECT * FROM purchase_orders WHERE id = ?", (order_id,)).fetchone()
        if not order:
            raise HTTPException(status_code=404, detail="order not found")

        current_status = order["status"]
        order_flow = ["draft", "sent", "received", "closed"]

        if order_flow.index(payload.new_status) <= order_flow.index(current_status):
            raise HTTPException(status_code=400, detail="cannot go back in status flow")

        db.execute("UPDATE purchase_orders SET status = ? WHERE id = ?", (payload.new_status, order_id))

        if payload.new_status == "received":
            items = db.execute("SELECT * FROM order_items WHERE order_id = ?", (order_id,)).fetchall()
            for item in items:
                db.execute("UPDATE products SET quantity = quantity + ? WHERE id = ?",
                           (item["quantity"], item["product_id"]))

        db.commit()
        return {"detail": f"order status updated to {payload.new_status}"}
