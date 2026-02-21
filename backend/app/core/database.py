"""
=============================================================
LOCAL DATABASE - SQLite (No Supabase needed)
=============================================================
Uses SQLite which is built into Python - zero installation.
Database file is created automatically at first run.
Location: backend/threat_intel.db
=============================================================
"""

import sqlite3
import os
from pathlib import Path

# Database file location - created automatically
DB_PATH = Path(__file__).parent.parent.parent / "threat_intel.db"


def get_db():
    """Get a database connection. Creates DB and tables if they don't exist."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row  # Returns rows as dicts instead of tuples
    conn.execute("PRAGMA journal_mode=WAL")  # Better concurrent access
    return conn


def init_db():
    """
    Create all tables on first run.
    Called from main.py startup.
    Safe to call multiple times - uses IF NOT EXISTS.
    """
    conn = get_db()
    cursor = conn.cursor()

    # Users table (replaces Supabase Auth)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            role TEXT DEFAULT 'analyst',
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # IOCs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            ioc_type TEXT NOT NULL,
            source TEXT DEFAULT 'manual',
            tags TEXT DEFAULT '[]',
            notes TEXT,
            risk_score INTEGER DEFAULT 0,
            vt_detections INTEGER,
            vt_total INTEGER,
            abuse_confidence INTEGER,
            country TEXT,
            city TEXT,
            latitude REAL,
            longitude REAL,
            asn TEXT,
            whois_registrar TEXT,
            first_seen TEXT DEFAULT (datetime('now')),
            last_seen TEXT DEFAULT (datetime('now')),
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # Alerts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            raw_log TEXT NOT NULL,
            source_system TEXT DEFAULT 'manual',
            severity TEXT DEFAULT 'medium',
            risk_score INTEGER DEFAULT 0,
            extracted_iocs TEXT DEFAULT '[]',
            llm_summary TEXT,
            recommended_actions TEXT DEFAULT '[]',
            mitre_techniques TEXT DEFAULT '[]',
            created_at TEXT DEFAULT (datetime('now')),
            enriched_at TEXT
        )
    """)

    # Feed items table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS feed_items (
            id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            severity TEXT DEFAULT 'medium',
            title TEXT NOT NULL,
            description TEXT,
            ioc_value TEXT,
            risk_score INTEGER,
            source TEXT DEFAULT 'system',
            tags TEXT DEFAULT '[]',
            timestamp TEXT DEFAULT (datetime('now'))
        )
    """)

    # Hunt queries table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hunt_queries (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            hypothesis TEXT,
            query_splunk TEXT,
            query_elastic TEXT,
            query_sigma TEXT,
            data_sources TEXT DEFAULT '[]',
            triggered_by_ioc TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # Insert demo IOC data if table is empty
    count = cursor.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    if count == 0:
        cursor.executemany("""
            INSERT INTO iocs (id, value, ioc_type, risk_score, source, country, city, latitude, longitude, vt_detections, vt_total, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            ('1', '192.168.1.100', 'ip', 95, 'AlienVault OTX', 'Russia', 'Moscow', 55.75, 37.62, 45, 70, '["c2","botnet"]'),
            ('2', 'evil-domain.xyz', 'domain', 88, 'URLhaus', 'China', 'Beijing', 39.90, 116.40, 32, 70, '["phishing","malware"]'),
            ('3', '185.220.101.45', 'ip', 61, 'AbuseIPDB', 'Germany', 'Frankfurt', 50.11, 8.68, 15, 70, '["scanner","tor-exit"]'),
            ('4', 'a3f5d8e9b2c1f0a7deadbeef12345678', 'hash', 72, 'MalwareBazaar', None, None, None, None, 28, 70, '["ransomware"]'),
            ('5', 'http://malware.download/payload.exe', 'url', 99, 'VirusTotal', 'Netherlands', 'Amsterdam', 52.37, 4.90, 68, 70, '["dropper","critical"]'),
        ])

    conn.commit()
    conn.close()
    print("✅ Local SQLite database initialized successfully")
    print(f"📁 Database location: {DB_PATH}")