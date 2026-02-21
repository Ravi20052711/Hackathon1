"""
=============================================================
API ROUTER - Authentication (Local SQLite, no Supabase)
=============================================================
Uses bcrypt for password hashing and JWT for tokens.
All data stored in local threat_intel.db file.

Routes:
  POST /api/auth/signup  - Create account
  POST /api/auth/login   - Login, get JWT token
  POST /api/auth/logout  - Logout
  GET  /api/auth/me      - Get current user
=============================================================
"""

from fastapi import APIRouter, HTTPException, Header
from app.models.schemas import UserSignup, UserLogin
from app.core.database import get_db
from app.core.config import settings
from typing import Optional
from datetime import datetime, timedelta
import uuid
import json
import logging

# JWT and password hashing
from jose import jwt, JWTError
from passlib.context import CryptContext

logger = logging.getLogger(__name__)
router = APIRouter()

# bcrypt password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a plain password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Check plain password against bcrypt hash."""
    return pwd_context.verify(plain, hashed)


def create_token(user_id: str, email: str) -> str:
    """
    Create a JWT token.
    Token expires after ACCESS_TOKEN_EXPIRE_MINUTES (default 24h).
    """
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,       # Subject (user ID)
        "email": email,
        "exp": expire          # Expiry time
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and verify a JWT token. Returns payload dict."""
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


@router.post("/signup")
async def signup(user_data: UserSignup):
    """
    Create a new user account.
    Stores hashed password in local SQLite database.
    """
    db = get_db()
    try:
        # Check if email already exists
        existing = db.execute(
            "SELECT id FROM users WHERE email = ?", (user_data.email,)
        ).fetchone()

        if existing:
            raise HTTPException(status_code=400, detail="Email already registered")

        # Create user with hashed password
        user_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO users (id, email, password_hash, full_name) VALUES (?, ?, ?, ?)",
            (user_id, user_data.email, hash_password(user_data.password), user_data.full_name)
        )
        db.commit()

        logger.info(f"✅ New user created: {user_data.email}")
        return {"message": "Account created successfully! You can now login.", "user_id": user_id}

    finally:
        db.close()


@router.post("/login")
async def login(credentials: UserLogin):
    """
    Login with email and password.
    Returns JWT token to use in Authorization header.
    Also accepts demo@example.com / demo1234 always.
    """

    # --- Demo login (always works) ---
    if credentials.email == "demo@example.com" and credentials.password == "demo1234":
        token = create_token("demo-user-123", "demo@example.com")
        return {
            "access_token": token,
            "token_type": "bearer",
            "user_id": "demo-user-123",
            "email": "demo@example.com"
        }

    # --- Real login from SQLite ---
    db = get_db()
    try:
        user = db.execute(
            "SELECT * FROM users WHERE email = ?", (credentials.email,)
        ).fetchone()

        if not user or not verify_password(credentials.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        token = create_token(user["id"], user["email"])
        logger.info(f"✅ User logged in: {credentials.email}")

        return {
            "access_token": token,
            "token_type": "bearer",
            "user_id": user["id"],
            "email": user["email"]
        }

    finally:
        db.close()


@router.post("/logout")
async def logout():
    """Logout - client should delete the token from localStorage."""
    return {"message": "Logged out successfully"}


@router.get("/me")
async def get_current_user(authorization: Optional[str] = Header(None)):
    """Get current user info from JWT token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = authorization.replace("Bearer ", "")
    payload = decode_token(token)  # Raises 401 if invalid

    # Demo user
    if payload.get("sub") == "demo-user-123":
        return {"user_id": "demo-user-123", "email": "demo@example.com", "role": "analyst"}

    # Real user from SQLite
    db = get_db()
    try:
        user = db.execute(
            "SELECT id, email, full_name, role FROM users WHERE id = ?",
            (payload["sub"],)
        ).fetchone()

        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        return {"user_id": user["id"], "email": user["email"], "role": user["role"]}
    finally:
        db.close()