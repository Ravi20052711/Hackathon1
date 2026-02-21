"""
=============================================================
MODELS - Pydantic schemas for request/response validation
=============================================================
"""

from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from enum import Enum


class UserSignup(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None   # Optional - won't crash if missing


class UserLogin(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    email: str


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"


class IOCCreate(BaseModel):
    value: str
    ioc_type: str
    source: str = "manual"
    tags: List[str] = []
    notes: Optional[str] = None


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertCreate(BaseModel):
    raw_log: str
    source_system: str = "manual"
    severity: str = "medium"