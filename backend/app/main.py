"""
=============================================================
THREAT INTEL FUSION ENGINE - Main Application Entry Point
=============================================================
This file bootstraps the FastAPI app, registers all routers,
sets up CORS, and initializes the Supabase client.

Run with: uvicorn app.main:app --reload --port 8000
=============================================================
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

# Import all API routers
from app.api import auth, ioc, alerts, graph, hunt, feed, reports
from app.core.config import settings  # Loads all env vars
from app.core.supabase_client import init_supabase  # Supabase singleton

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Runs on app startup and shutdown.
    - Startup: Initialize DB connections, start background feed poller
    - Shutdown: Clean up connections gracefully
    """
    logger.info("🚀 Starting Threat Intel Fusion Engine...")
    init_supabase()  # Initialize Supabase connection on startup
    yield
    logger.info("🛑 Shutting down Threat Intel Fusion Engine...")


# Create FastAPI app instance with metadata for Swagger docs
app = FastAPI(
    title="Threat Intel Fusion Engine",
    description="Unified threat intelligence platform with SIEM integration",
    version="1.0.0",
    docs_url="/api/docs",        # Swagger UI available at /api/docs
    redoc_url="/api/redoc",      # ReDoc UI at /api/redoc
    lifespan=lifespan,
)

# -------------------------------------------------------
# CORS Middleware
# Allows the React frontend (running on :5173) to call the
# FastAPI backend (running on :8000) without browser blocks
# -------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,  # From .env
    allow_credentials=True,               # Needed for auth cookies
    allow_methods=["*"],                  # Allow GET, POST, PUT, DELETE etc.
    allow_headers=["*"],                  # Allow Authorization header etc.
)

# -------------------------------------------------------
# Register API Routers
# Each router handles a specific feature domain
# -------------------------------------------------------
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(ioc.router, prefix="/api/ioc", tags=["IOC Management"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["SIEM Alerts"])
app.include_router(graph.router, prefix="/api/graph", tags=["Graph Analysis"])
app.include_router(hunt.router, prefix="/api/hunt", tags=["Threat Hunting"])
app.include_router(feed.router, prefix="/api/feed", tags=["Threat Feed"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])


@app.get("/api/health")
async def health_check():
    """Health check endpoint - confirms the API is running."""
    return {"status": "ok", "service": "Threat Intel Fusion Engine", "version": "1.0.0"}
