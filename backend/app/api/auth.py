"""
AUTH ROUTER - Local SQLite authentication
"""

from fastapi import APIRouter, HTTPException, Header
from app.core.database import get_db
from app.core.config import settings
from typing import Optional
from datetime import datetime, timedelta
import uuid
import traceback
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

try:
    from jose import jwt, JWTError
    HAS_JOSE = True
except ImportError:
    HAS_JOSE = False

HAS_PASSLIB = False  # Using simple hash to avoid bcrypt issues


def hash_password(password: str) -> str:
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(plain: str, hashed: str) -> bool:
    import hashlib
    return hashlib.sha256(plain.encode()).hexdigest() == hashed


def create_token(user_id: str, email: str) -> str:
    if not HAS_JOSE:
        return f"local-token-{user_id}"
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": user_id, "email": email, "exp": expire},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )


def decode_token(token: str) -> dict:
    if token.startswith("local-token-"):
        user_id = token.replace("local-token-", "")
        return {"sub": user_id}
    if token == "demo-token-12345":
        return {"sub": "demo-user-123", "email": "demo@example.com"}
    if not HAS_JOSE:
        raise HTTPException(status_code=401, detail="Invalid token")
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


@router.post("/signup")
async def signup(user_data: dict):
    try:
        email = user_data.get("email", "").strip()
        password = user_data.get("password", "")
        full_name = user_data.get("full_name", "")

        if not email:
            raise HTTPException(status_code=400, detail="Email is required")
        if not password:
            raise HTTPException(status_code=400, detail="Password is required")
        if len(password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

        db = get_db()
        try:
            existing = db.execute(
                "SELECT id FROM users WHERE email = ?", (email,)
            ).fetchone()

            if existing:
                raise HTTPException(status_code=400, detail="Email already registered. Please login.")

            user_id = str(uuid.uuid4())
            db.execute(
                "INSERT INTO users (id, email, password_hash, full_name) VALUES (?, ?, ?, ?)",
                (user_id, email, hash_password(password), full_name)
            )
            db.commit()
            logger.info(f"✅ New user created: {email}")
            return {"message": "Account created successfully!", "user_id": user_id}

        finally:
            db.close()

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Signup error: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Signup failed: {str(e)}")


@router.post("/login")
async def login(credentials: dict):
    try:
        email = credentials.get("email", "").strip()
        password = credentials.get("password", "")

        if not email or not password:
            raise HTTPException(status_code=400, detail="Email and password required")

        # Demo login
        if email == "demo@example.com" and password == "demo1234":
            token = create_token("demo-user-123", "demo@example.com")
            return {
                "access_token": token,
                "token_type": "bearer",
                "user_id": "demo-user-123",
                "email": "demo@example.com"
            }

        db = get_db()
        try:
            user = db.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()

            if not user:
                raise HTTPException(status_code=401, detail="No account found. Please sign up first.")

            if not verify_password(password, user["password_hash"]):
                raise HTTPException(status_code=401, detail="Wrong password. Please try again.")

            token = create_token(user["id"], user["email"])
            logger.info(f"✅ Login: {email}")
            return {
                "access_token": token,
                "token_type": "bearer",
                "user_id": user["id"],
                "email": user["email"]
            }

        finally:
            db.close()

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")


@router.post("/logout")
async def logout():
    return {"message": "Logged out successfully"}


@router.get("/me")
async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = authorization.replace("Bearer ", "")
    payload = decode_token(token)

    if payload.get("sub") == "demo-user-123":
        return {"user_id": "demo-user-123", "email": "demo@example.com", "role": "analyst"}

    db = get_db()
    try:
        user = db.execute(
            "SELECT id, email, full_name, role FROM users WHERE id = ?",
            (payload["sub"],)
        ).fetchone()

        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        return {"user_id": user["id"], "email": user["email"], "role": user["role"]}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()