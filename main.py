import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from bson import ObjectId
import hashlib, secrets

from database import db, create_document, get_documents
from schemas import User as UserSchema, Game as GameSchema, Order as OrderSchema

app = FastAPI(title="Game Store API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------- Utils -----------------------

def oid(oid_str: str) -> ObjectId:
    try:
        return ObjectId(oid_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")

def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${h}"

def verify_password(password: str, hashed: str) -> bool:
    try:
        salt, h = hashed.split("$")
    except ValueError:
        return False
    return hash_password(password, salt) == hashed

# Session handling (simple token store)
SESSION_TTL_MIN = 24 * 60

def create_session(user_id: str) -> str:
    token = secrets.token_hex(32)
    db["session"].insert_one({
        "user_id": user_id,
        "token": token,
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=SESSION_TTL_MIN),
        "created_at": datetime.now(timezone.utc)
    })
    return token

def get_user_by_token(token: str):
    if not token:
        return None
    s = db["session"].find_one({"token": token})
    if not s:
        return None
    if s.get("expires_at") and s["expires_at"] < datetime.now(timezone.utc):
        db["session"].delete_one({"_id": s["_id"]})
        return None
    user = db["user"].find_one({"_id": s["user_id"] if isinstance(s["user_id"], ObjectId) else oid(s["user_id"])})
    return user

async def get_current_user(authorization: Optional[str] = Header(None)):
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user

async def admin_required(user=Depends(get_current_user)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    return user

# ----------------------- Models -----------------------
class RegisterInput(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginInput(BaseModel):
    email: EmailStr
    password: str

class LoginResponse(BaseModel):
    token: str
    name: str
    email: EmailStr
    is_admin: bool

class CreateGameInput(BaseModel):
    title: str
    description: Optional[str] = None
    price: float
    platform: str
    category: Optional[str] = None
    images: List[str] = []
    is_active: bool = True

class UpdateGameInput(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    platform: Optional[str] = None
    category: Optional[str] = None
    images: Optional[List[str]] = None
    is_active: Optional[bool] = None

class CreateOrderInput(BaseModel):
    game_id: str
    email_for_delivery: EmailStr
    nagad_number: str
    transaction_id: str

class UpdateOrderStatus(BaseModel):
    status: str

# ----------------------- Routes -----------------------
@app.get("/")
def root():
    return {"message": "Game Store API running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_name"] = getattr(db, "name", "✅ Connected")
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response

# Auth
@app.post("/auth/register", response_model=LoginResponse)
def register(payload: RegisterInput):
    existing = db["user"].find_one({"email": payload.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = hash_password(payload.password)
    user_doc = {
        "name": payload.name,
        "email": payload.email.lower(),
        "hashed_password": hashed,
        "is_admin": False,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["user"].insert_one(user_doc)
    token = create_session(str(res.inserted_id))
    return LoginResponse(token=token, name=user_doc["name"], email=user_doc["email"], is_admin=user_doc["is_admin"])

@app.post("/auth/login", response_model=LoginResponse)
def login(payload: LoginInput):
    user = db["user"].find_one({"email": payload.email.lower()})
    if not user or not verify_password(payload.password, user.get("hashed_password", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_session(str(user["_id"]))
    return LoginResponse(token=token, name=user["name"], email=user["email"], is_admin=bool(user.get("is_admin", False)))

# Games
@app.get("/games")
def list_games():
    games = list(db["game"].find({"is_active": True}).sort("created_at", -1))
    for g in games:
        g["id"] = str(g.pop("_id"))
    return games

@app.get("/games/all")
def list_all_games(user=Depends(admin_required)):
    games = list(db["game"].find({}).sort("created_at", -1))
    for g in games:
        g["id"] = str(g.pop("_id"))
    return games

@app.post("/games")
def create_game(payload: CreateGameInput, user=Depends(admin_required)):
    doc = {
        **payload.model_dump(),
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }
    res = db["game"].insert_one(doc)
    return {"id": str(res.inserted_id)}

@app.put("/games/{game_id}")
def update_game(game_id: str, payload: UpdateGameInput, user=Depends(admin_required)):
    update = {k: v for k, v in payload.model_dump(exclude_none=True).items()}
    update["updated_at"] = datetime.now(timezone.utc)
    r = db["game"].update_one({"_id": oid(game_id)}, {"$set": update})
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="Game not found")
    return {"success": True}

@app.delete("/games/{game_id}")
def delete_game(game_id: str, user=Depends(admin_required)):
    r = db["game"].delete_one({"_id": oid(game_id)})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Game not found")
    return {"success": True}

# Orders
@app.post("/orders")
def create_order(payload: CreateOrderInput, authorization: Optional[str] = Header(None)):
    # Optional user
    user = None
    if authorization and authorization.lower().startswith("bearer "):
        user = get_user_by_token(authorization.split(" ", 1)[1])
    game = db["game"].find_one({"_id": oid(payload.game_id)})
    if not game or not game.get("is_active", True):
        raise HTTPException(status_code=400, detail="Invalid game")
    order_doc = {
        "user_id": str(user["_id"]) if user else None,
        "game_id": payload.game_id,
        "email_for_delivery": payload.email_for_delivery,
        "nagad_number": payload.nagad_number,
        "transaction_id": payload.transaction_id,
        "status": "pending",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }
    res = db["order"].insert_one(order_doc)
    return {"id": str(res.inserted_id), "message": "Order placed. You will receive your game within 2 hours."}

@app.get("/orders")
def list_orders(user=Depends(admin_required)):
    orders = list(db["order"].find({}).sort("created_at", -1))
    for o in orders:
        o["id"] = str(o.pop("_id"))
    return orders

@app.put("/orders/{order_id}/status")
def update_order_status(order_id: str, payload: UpdateOrderStatus, user=Depends(admin_required)):
    if payload.status not in ["pending", "completed", "canceled"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    r = db["order"].update_one({"_id": oid(order_id)}, {"$set": {"status": payload.status, "updated_at": datetime.now(timezone.utc)}})
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="Order not found")
    return {"success": True}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
