from fastapi import FastAPI, HTTPException, Depends, Header, status, Query, Body
from pydantic import BaseModel, EmailStr, constr, Field
import bcrypt, secrets, sqlite3
from typing import Optional, Dict, List, Annotated
from uuid import uuid4
import re
import string

app = FastAPI(title="Inventory Management Project")

DB_PATH = "users.db"

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
    db.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        sku TEXT UNIQUE NOT NULL,
        price REAL NOT NULL,
        quantity INTEGER NOT NULL DEFAULT 0,
        min_threshold INTEGER NOT NULL DEFAULT 0,
        category TEXT DEFAULT ''
    )
    """)
    db.execute("""
    CREATE TABLE IF NOT EXISTS purchase_orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        supplier_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'draft',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (supplier_id) REFERENCES suppliers (id)
    )
    """)
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

with get_db() as db:
        info = {row["name"] for row in db.execute("PRAGMA table_info(products)").fetchall()}
        if "min_threshold" not in info:
            db.execute("ALTER TABLE products ADD COLUMN min_threshold INTEGER NOT NULL DEFAULT 0")
        if "category" not in info:
            db.execute("ALTER TABLE products ADD COLUMN category TEXT DEFAULT ''")
        if "sku" not in info:
            raise RuntimeError("products table missing 'sku' column after migration attempt")
        db.commit()

class UserCreate(BaseModel):
    first_name: str
    last_name: str
    username: Annotated[str, Field (min_length=3, max_length=50, strip_whitespace=True) ]
    email: EmailStr
    password: Annotated[str, Field (min_length=8) ]
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

class ProductBase(BaseModel):
    name: str
    sku: str
    price: float
    quantity: Optional[int] = 0
    min_threshold: int = Field(..., ge=0)
    category: Optional[str] = ""

class ProductCreate(ProductBase):
    pass

class ProductUpdate(BaseModel):
    name: Optional[str]
    sku: Optional[str]
    price: Optional[float]
    quantity: Optional[int]
    min_threshold: Optional[int]
    category: Optional[str]

class ProductOut(BaseModel):
    id: int
    name: str
    sku: str
    price: float
    quantity: int
    min_threshold: int
    category: Optional[str]
    low_stock: bool

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
    new_status: str

def hash_password(plain_password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))

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

def require_admin(current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="admin privileges required")
    return current

def generate_sku(name: str, tries: int = 6) -> str:
    base = "".join(ch for ch in name.upper() if ch.isalnum())[:6]
    if not base:
        base = "ITEM"
    with get_db() as db:
        for _ in range(tries):
            suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
            sku = f"{base[:6]}-{suffix}"
            if not db.execute("SELECT 1 FROM products WHERE sku = ?", (sku,)).fetchone():
                return sku
    raise HTTPException(status_code=500, detail="unable to generate unique SKU, try again")

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


@app.post("/suppliers", response_model=SupplierOut, status_code=201)
def create_supplier(payload: SupplierCreate):
    with get_db() as db:
        if db.execute("SELECT 1 FROM suppliers WHERE email = ?", (payload.email,)).fetchone():
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

@app.put("/suppliers/{supplier_id}", response_model=SupplierOut)
def update_supplier(supplier_id: int, payload: SupplierUpdate):
    with get_db() as db:
        row = db.execute("SELECT * FROM suppliers WHERE id = ?", (supplier_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="supplier not found")
        update_data = payload.dict(exclude_unset=True)
        set_clause = ", ".join([f"{k} = ?" for k in update_data.keys()])
        db.execute(f"UPDATE suppliers SET {set_clause} WHERE id = ?", (*update_data.values(), supplier_id))
        db.commit()
        updated = db.execute("SELECT * FROM suppliers WHERE id = ?", (supplier_id,)).fetchone()
        return dict(updated)

@app.delete("/suppliers/{supplier_id}")
def delete_supplier(supplier_id: int):
    with get_db() as db:
        row = db.execute("SELECT * FROM suppliers WHERE id = ?", (supplier_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="supplier not found")
        db.execute("DELETE FROM suppliers WHERE id = ?", (supplier_id,))
        db.commit()
        return {"detail": f"Supplier {supplier_id} deleted"}

@app.put("/suppliers/{supplier_id}/activate")
def activate_supplier(supplier_id: int):
    with get_db() as db:
        db.execute("UPDATE suppliers SET is_active = 1 WHERE id = ?", (supplier_id,))
        db.commit()
        return {"detail": f"Supplier {supplier_id} activated"}

@app.put("/suppliers/{supplier_id}/deactivate")
def deactivate_supplier(supplier_id: int):
    with get_db() as db:
        db.execute("UPDATE suppliers SET is_active = 0 WHERE id = ?", (supplier_id,))
        db.commit()
        return {"detail": f"Supplier {supplier_id} deactivated"}


@app.post("/products", response_model=ProductOut, status_code=201)
def create_product(payload: ProductCreate, current=Depends(get_current_user)):
    with get_db() as db:
        sku = payload.sku.strip() if payload.sku else None
        if not sku:
            sku = generate_sku(payload.name)
        else:
            if db.execute("SELECT 1 FROM products WHERE sku = ?", (sku,)).fetchone():
                raise HTTPException(status_code=400, detail="product with this SKU exists")
        cur = db.execute("""
            INSERT INTO products (name, sku, price, quantity, min_threshold, category)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (payload.name, sku, payload.price, payload.quantity or 0, payload.min_threshold, payload.category or ""))
        db.commit()
        product_id = cur.lastrowid
        low_stock = (payload.quantity or 0) < payload.min_threshold
        return ProductOut(
            id=product_id,
            name=payload.name,
            sku=sku,
            price=payload.price,
            quantity=payload.quantity or 0,
            min_threshold=payload.min_threshold,
            category=payload.category or "",
            low_stock=low_stock
        )

@app.get("/products", response_model=List[ProductOut])
def get_products(
    q: Optional[str] = Query(None, description="search name or sku"),
    category: Optional[str] = Query(None),
    min_price: Optional[float] = Query(None),
    max_price: Optional[float] = Query(None),
    below_threshold: Optional[bool] = Query(False, description="only products below min_threshold"),
    sort_by: Optional[str] = Query("name", regex="^(name|price)$"),
    order: Optional[str] = Query("asc", regex="^(asc|desc)$"),
    limit: int = Query(10, ge=1, le=500),
    page: int = Query(1, ge=1)
):
    offset = (page - 1) * limit
    where_clauses = []
    params = []

    if q:
        where_clauses.append("(name LIKE ? OR sku LIKE ?)")
        q_like = f"%{q}%"
        params.extend([q_like, q_like])
    if category:
        where_clauses.append("category = ?")
        params.append(category)
    if min_price is not None:
        where_clauses.append("price >= ?")
        params.append(min_price)
    if max_price is not None:
        where_clauses.append("price <= ?")
        params.append(max_price)
    if below_threshold:
        where_clauses.append("quantity < min_threshold")

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    order_sql = f"ORDER BY {sort_by} {order.upper()}"
    sql = f"SELECT * FROM products {where_sql} {order_sql} LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_db() as db:
        rows = db.execute(sql, tuple(params)).fetchall()
        result = []
        for r in rows:
            low_stock = r["quantity"] < r["min_threshold"]
            result.append(ProductOut(
                id=r["id"],
                name=r["name"],
                sku=r["sku"],
                price=r["price"],
                quantity=r["quantity"],
                min_threshold=r["min_threshold"],
                category=r["category"],
                low_stock=low_stock
            ))
        return result

@app.get("/products/{product_id}", response_model=ProductOut)
def get_product(product_id: int):
    with get_db() as db:
        r = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        if not r:
            raise HTTPException(status_code=404, detail="product not found")
        low_stock = r["quantity"] < r["min_threshold"]
        return ProductOut(
            id=r["id"],
            name=r["name"],
            sku=r["sku"],
            price=r["price"],
            quantity=r["quantity"],
            min_threshold=r["min_threshold"],
            category=r["category"],
            low_stock=low_stock
        )

@app.put("/products/{product_id}", response_model=ProductOut)
def update_product(product_id: int, payload: ProductUpdate, current=Depends(get_current_user)):
    with get_db() as db:
        row = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="product not found")
        update_data = payload.dict(exclude_unset=True)
        if "sku" in update_data and update_data["sku"]:
            exists = db.execute("SELECT 1 FROM products WHERE sku = ? AND id != ?", (update_data["sku"], product_id)).fetchone()
            if exists:
                raise HTTPException(status_code=400, detail="another product with this SKU exists")
        if update_data:
            set_clause = ", ".join([f"{k} = ?" for k in update_data.keys()])
            db.execute(f"UPDATE products SET {set_clause} WHERE id = ?", (*update_data.values(), product_id))
            db.commit()
        updated = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        return ProductOut(
            id=updated["id"],
            name=updated["name"],
            sku=updated["sku"],
            price=updated["price"],
            quantity=updated["quantity"],
            min_threshold=updated["min_threshold"],
            category=updated["category"],
            low_stock=low_stock
        )

@app.delete("/products/{product_id}")
def delete_product(product_id: int, current=Depends(require_admin)):
    with get_db() as db:
        row = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="product not found")
        db.execute("DELETE FROM products WHERE id = ?", (product_id,))
        db.commit()
        return {"detail": f"Product {product_id} deleted"}

@app.post("/products/{product_id}/add-stock")
def add_stock(product_id: int, amount: int = Body(..., embed=True, ge=1), current=Depends(require_admin)):
    with get_db() as db:
        row = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="product not found")
        new_qty = row["quantity"] + amount
        db.execute("UPDATE products SET quantity = ? WHERE id = ?", (new_qty, product_id))
        db.commit()
        low_stock = new_qty < row["min_threshold"]
        return {"detail": f"Added {amount} units", "product_id": product_id, "new_quantity": new_qty, "low_stock": low_stock}

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
        return {"id": order_id, "supplier_id": payload.supplier_id, "status": "draft", "created_at": "NOW", "items": items_out}

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
    

@app.get("/suppliers/{supplier_id}/orders", response_model=List[PurchaseOrderOut])
def get_supplier_orders(supplier_id: int):
    with get_db() as db:
        orders = db.execute("SELECT * FROM purchase_orders WHERE supplier_id = ?", (supplier_id,)).fetchall()
        result = []
        for order in orders:
            items = db.execute("SELECT * FROM order_items WHERE order_id = ?", (order["id"],)).fetchall()
            result.append({
                "id": order["id"],
                "supplier_id": order["supplier_id"],
                "status": order["status"],
                "created_at": order["created_at"],
                "items": [dict(i) for i in items]
            })
        return result
