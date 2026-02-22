"""
CORE CONFIG - Settings
"""

from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    APP_NAME: str = "ThreatIntelFusion"
    DEBUG: bool = True
    SECRET_KEY: str = "threatintel-local-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    # Optional API keys
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    OTX_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""   # Claude AI  - get from console.anthropic.com
    GEMINI_API_KEY: str = ""      # Google Gemini - FREE at aistudio.google.com/app/apikey
    GROQ_API_KEY: str = ""        # Groq - FREE no credit card at console.groq.com

    # Email alert settings (add to .env)
    SMTP_HOST:     str = "smtp.gmail.com"
    SMTP_PORT:     int = 587
    SMTP_USER:     str = ""
    SMTP_PASSWORD: str = ""
    ALERT_EMAIL:   str = "klu2300030288@outlook.com"

    REDIS_URL: str = "redis://localhost:6379"
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()