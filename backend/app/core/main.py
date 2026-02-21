"""
=============================================================
MAIN - FastAPI Application Entry Point (No Supabase)
=============================================================
Uses local SQLite database instead of Supabase.
Database file created automatically on first run.
=============================================================
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from app.api import auth, ioc, alerts, graph, hunt, feed, reports
from app.core.config import settings
from app.core.database import init_db  # Local SQLite init

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Starting Threat Intel Fusion Engine...")
    init_db()  # Creates SQLite tables if they don't exist
    yield
    logger.info("🛑 Shutting down...")


app = FastAPI(
    title="Threat Intel Fusion Engine",
    description="Unified threat intelligence platform - Local SQLite mode",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(ioc.router, prefix="/api/ioc", tags=["IOC Management"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(graph.router, prefix="/api/graph", tags=["Graph"])
app.include_router(hunt.router, prefix="/api/hunt", tags=["Hunt"])
app.include_router(feed.router, prefix="/api/feed", tags=["Feed"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])


@app.get("/api/health")
async def health():
    return {"status": "ok", "mode": "local-sqlite", "version": "1.0.0"}