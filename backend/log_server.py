"""
=============================================================
LOG VIEWER SERVER
=============================================================
Reads your local log file and serves it to a web browser.
Auto-updates every 3 seconds via WebSocket.

HOW TO RUN:
  pip install fastapi uvicorn websockets

  python log_server.py

Then open: http://localhost:8080

CHANGE THIS to your actual log file path:
  LOG_FILE = "C:/path/to/your/logfile.log"
=============================================================
"""

import os
import time
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uvicorn

# ─── CONFIGURE YOUR LOG FILE PATH HERE ───────────────────────────────────────
LOG_FILE = "backend/threat_intel.log"   # Change this to your actual log file path
                        # Examples:
                        # Windows: "C:/Users/YourName/logs/app.log"
                        # Or just "app.log" to use the demo log in same folder
MAX_LINES = 500         # How many recent lines to show
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI()

# Generate demo log if no log file exists
def ensure_demo_log():
    if not os.path.exists(LOG_FILE):
        print(f"⚠️  Log file '{LOG_FILE}' not found — creating demo log...")
        with open(LOG_FILE, 'w') as f:
            levels = ['INFO', 'WARNING', 'ERROR', 'DEBUG', 'CRITICAL']
            messages = [
                "Application started successfully",
                "User login: ravi.santosh@email.com",
                "Database connection established",
                "API request: GET /api/data — 200 OK",
                "Cache miss — fetching from database",
                "User session expired: session_id=abc123",
                "File uploaded: report_2026.pdf (2.3MB)",
                "Email sent to: admin@company.com",
                "Scheduled task completed: backup_db",
                "WARNING: High memory usage detected 85%",
                "ERROR: Connection timeout to 192.168.1.100",
                "New user registered: john.doe@email.com",
                "API request: POST /api/alerts — 201 Created",
                "CRITICAL: Disk space low — 95% used",
                "System health check passed",
            ]
            import random
            for i in range(50):
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                level = random.choice(levels)
                msg = random.choice(messages)
                f.write(f"[{ts}] [{level}] {msg}\n")
        print(f"✅ Demo log created at: {LOG_FILE}")

def read_log_file() -> list:
    """Read the log file and return last MAX_LINES lines."""
    try:
        if not os.path.exists(LOG_FILE):
            return [{"timestamp": datetime.now().isoformat(), 
                    "level": "ERROR", 
                    "message": f"Log file not found: {LOG_FILE}",
                    "raw": f"[ERROR] Log file not found: {LOG_FILE}"}]
        
        with open(LOG_FILE, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
        
        # Get last MAX_LINES lines
        lines = lines[-MAX_LINES:]
        
        parsed = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            parsed.append(parse_log_line(line))
        
        return list(reversed(parsed))  # newest first
    
    except Exception as e:
        return [{"timestamp": datetime.now().isoformat(),
                "level": "ERROR",
                "message": f"Error reading log: {str(e)}",
                "raw": str(e)}]

def parse_log_line(line: str) -> dict:
    """Parse a log line and extract timestamp, level, message."""
    import re
    
    result = {
        "raw": line,
        "timestamp": "",
        "level": "INFO",
        "message": line,
    }
    
    # Try common log formats
    patterns = [
        # [2026-02-21 14:22:11] [LEVEL] message
        r'\[(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\]]*)\]\s*\[?(\w+)\]?\s*(.*)',
        # 2026-02-21 14:22:11 LEVEL message
        r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\s+(\w+)\s+(.*)',
        # 2026-02-21T14:22:11 - LEVEL - message
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s*[-|]\s*(\w+)\s*[-|]\s*(.*)',
        # LEVEL: message (no timestamp)
        r'^(DEBUG|INFO|WARNING|ERROR|CRITICAL|WARN):\s*(.*)',
    ]
    
    for pattern in patterns:
        m = re.match(pattern, line, re.IGNORECASE)
        if m:
            groups = m.groups()
            if len(groups) == 3:
                result["timestamp"] = groups[0]
                result["level"] = groups[1].upper()
                result["message"] = groups[2]
            elif len(groups) == 2:
                result["level"] = groups[0].upper()
                result["message"] = groups[1]
            break
    
    # Detect level from keywords if not parsed
    if result["level"] == "INFO":
        line_lower = line.lower()
        if any(w in line_lower for w in ['critical', 'fatal']):
            result["level"] = "CRITICAL"
        elif any(w in line_lower for w in ['error', 'err', 'exception', 'traceback']):
            result["level"] = "ERROR"
        elif any(w in line_lower for w in ['warning', 'warn']):
            result["level"] = "WARNING"
        elif any(w in line_lower for w in ['debug']):
            result["level"] = "DEBUG"
    
    return result

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.connections = []
    
    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.append(ws)
    
    def disconnect(self, ws: WebSocket):
        if ws in self.connections:
            self.connections.remove(ws)
    
    async def broadcast(self, data):
        for conn in self.connections[:]:
            try:
                await conn.send_json(data)
            except:
                self.connections.remove(conn)

manager = ConnectionManager()

@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the log viewer web page."""
    return HTMLResponse(HTML_PAGE)

@app.get("/api/logs")
async def get_logs():
    """REST endpoint to get current logs."""
    return {
        "logs": read_log_file(),
        "file": LOG_FILE,
        "total": len(read_log_file()),
        "last_updated": datetime.now().isoformat()
    }

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """WebSocket — pushes new log lines automatically every 3 seconds."""
    await manager.connect(ws)
    last_size = 0
    try:
        while True:
            await asyncio.sleep(3)
            try:
                current_size = os.path.getsize(LOG_FILE) if os.path.exists(LOG_FILE) else 0
                if current_size != last_size:
                    last_size = current_size
                    logs = read_log_file()
                    await ws.send_json({
                        "type": "update",
                        "logs": logs,
                        "last_updated": datetime.now().strftime("%H:%M:%S")
                    })
            except:
                pass
    except WebSocketDisconnect:
        manager.disconnect(ws)

# ─── HTML PAGE ────────────────────────────────────────────────────────────────
HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Log Viewer</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Orbitron:wght@700&display=swap');
*{margin:0;padding:0;box-sizing:border-box;}
body{
  background:#030712;
  font-family:'JetBrains Mono',monospace;
  color:#e2e8f0;
  height:100vh;
  display:flex;
  flex-direction:column;
  overflow:hidden;
}
body::before{
  content:'';position:fixed;inset:0;
  background-image:
    linear-gradient(rgba(6,182,212,0.03) 1px,transparent 1px),
    linear-gradient(90deg,rgba(6,182,212,0.03) 1px,transparent 1px);
  background-size:40px 40px;pointer-events:none;
}

/* Header */
.header{
  padding:14px 20px;
  background:rgba(0,0,0,0.4);
  border-bottom:1px solid rgba(255,255,255,0.06);
  display:flex;align-items:center;gap:16px;
  flex-wrap:wrap;
  position:relative;z-index:1;
}
.title{
  font-family:'Orbitron',monospace;
  font-size:16px;color:#06b6d4;
  letter-spacing:3px;
}
.file-path{
  font-size:10px;color:#4b5563;
  background:rgba(0,0,0,0.3);
  padding:4px 10px;border-radius:4px;
  border:1px solid rgba(255,255,255,0.05);
}
.live-dot{
  width:8px;height:8px;border-radius:50%;
  background:#10b981;
  animation:blink 1.5s infinite;
  display:inline-block;
}
.live-dot.disconnected{background:#ef4444;animation:none;}
@keyframes blink{0%,100%{opacity:1;}50%{opacity:0.3;}}
.status{font-size:10px;color:#6b7280;display:flex;align-items:center;gap:6px;}

/* Controls */
.controls{
  display:flex;gap:8px;align-items:center;margin-left:auto;flex-wrap:wrap;
}
.search-wrap{position:relative;}
.search{
  background:rgba(0,0,0,0.4);
  border:1px solid rgba(255,255,255,0.08);
  border-radius:6px;
  padding:6px 10px 6px 32px;
  color:#e2e8f0;font-family:'JetBrains Mono',monospace;font-size:11px;
  width:220px;
  transition:border-color 0.2s;
}
.search:focus{outline:none;border-color:rgba(6,182,212,0.4);}
.search::placeholder{color:#374151;}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:#374151;font-size:12px;}

.btn{
  padding:6px 12px;border-radius:6px;font-size:10px;
  font-family:'JetBrains Mono',monospace;letter-spacing:1px;
  border:1px solid;cursor:pointer;transition:all 0.2s;
}
.btn-cyan{background:rgba(6,182,212,0.1);color:#06b6d4;border-color:rgba(6,182,212,0.3);}
.btn-cyan:hover{background:rgba(6,182,212,0.2);}
.btn-gray{background:rgba(255,255,255,0.04);color:#6b7280;border-color:rgba(255,255,255,0.08);}
.btn-gray:hover{background:rgba(255,255,255,0.08);color:#9ca3af;}

/* Level filter pills */
.filters{display:flex;gap:4px;}
.pill{
  padding:4px 10px;border-radius:12px;font-size:9px;
  font-family:'JetBrains Mono',monospace;
  border:1px solid;cursor:pointer;
  letter-spacing:1px;text-transform:uppercase;
  transition:all 0.2s;opacity:0.5;
}
.pill.active{opacity:1;}
.pill-all{color:#94a3b8;border-color:rgba(148,163,184,0.3);background:rgba(148,163,184,0.05);}
.pill-all.active{background:rgba(148,163,184,0.15);}
.pill-info{color:#06b6d4;border-color:rgba(6,182,212,0.3);background:rgba(6,182,212,0.05);}
.pill-info.active{background:rgba(6,182,212,0.15);}
.pill-warning{color:#f59e0b;border-color:rgba(245,158,11,0.3);background:rgba(245,158,11,0.05);}
.pill-warning.active{background:rgba(245,158,11,0.15);}
.pill-error{color:#ef4444;border-color:rgba(239,68,68,0.3);background:rgba(239,68,68,0.05);}
.pill-error.active{background:rgba(239,68,68,0.15);}
.pill-critical{color:#a855f7;border-color:rgba(168,85,247,0.3);background:rgba(168,85,247,0.05);}
.pill-critical.active{background:rgba(168,85,247,0.15);}
.pill-debug{color:#6b7280;border-color:rgba(107,114,128,0.3);background:rgba(107,114,128,0.05);}
.pill-debug.active{background:rgba(107,114,128,0.15);}

/* Stats bar */
.stats{
  padding:8px 20px;
  background:rgba(0,0,0,0.2);
  border-bottom:1px solid rgba(255,255,255,0.04);
  display:flex;gap:20px;align-items:center;
  font-size:10px;color:#4b5563;
  position:relative;z-index:1;
}
.stat-item{display:flex;align-items:center;gap:5px;}
.stat-val{font-weight:600;}

/* Log container */
.log-container{
  flex:1;overflow-y:auto;
  padding:10px 16px;
  position:relative;z-index:1;
}
.log-container::-webkit-scrollbar{width:4px;}
.log-container::-webkit-scrollbar-track{background:transparent;}
.log-container::-webkit-scrollbar-thumb{background:#1f2937;border-radius:2px;}

/* Log entry */
.log-entry{
  display:grid;
  grid-template-columns:160px 80px 1fr;
  gap:10px;
  padding:5px 10px;
  border-radius:4px;
  border-left:2px solid transparent;
  font-size:11px;
  line-height:1.5;
  margin-bottom:2px;
  transition:background 0.1s;
  align-items:start;
}
.log-entry:hover{background:rgba(255,255,255,0.02);}
.log-entry.new-entry{animation:fadeIn 0.3s ease;}
@keyframes fadeIn{from{opacity:0;transform:translateX(-4px);}to{opacity:1;}}

.log-time{color:#374151;font-size:10px;white-space:nowrap;}
.log-level{font-size:9px;font-weight:600;letter-spacing:1px;text-align:center;padding:1px 4px;border-radius:3px;white-space:nowrap;}
.log-msg{color:#94a3b8;word-break:break-all;}

/* Level colors */
.level-INFO    {color:#06b6d4;border-left-color:#06b6d4;}
.level-INFO .log-level{background:rgba(6,182,212,0.1);color:#06b6d4;}
.level-WARNING {color:#f59e0b;border-left-color:#f59e0b;}
.level-WARNING .log-level{background:rgba(245,158,11,0.1);color:#f59e0b;}
.level-WARN    {color:#f59e0b;border-left-color:#f59e0b;}
.level-WARN .log-level{background:rgba(245,158,11,0.1);color:#f59e0b;}
.level-ERROR   {color:#ef4444;border-left-color:#ef4444;}
.level-ERROR .log-level{background:rgba(239,68,68,0.1);color:#ef4444;}
.level-CRITICAL{color:#a855f7;border-left-color:#a855f7;}
.level-CRITICAL .log-level{background:rgba(168,85,247,0.1);color:#a855f7;}
.level-DEBUG   {color:#6b7280;border-left-color:#374151;}
.level-DEBUG .log-level{background:rgba(107,114,128,0.1);color:#6b7280;}

.log-msg .highlight{background:rgba(251,191,36,0.2);color:#fbbf24;border-radius:2px;padding:0 2px;}

/* Empty state */
.empty{
  display:flex;flex-direction:column;
  align-items:center;justify-content:center;
  height:100%;color:#374151;gap:8px;
}
.empty-icon{font-size:32px;}

/* Footer */
.footer{
  padding:6px 20px;
  background:rgba(0,0,0,0.3);
  border-top:1px solid rgba(255,255,255,0.04);
  font-size:9px;color:#374151;
  display:flex;justify-content:space-between;
  align-items:center;
  position:relative;z-index:1;
}
</style>
</head>
<body>

<div class="header">
  <div class="title">📋 LOG VIEWER</div>
  <div class="file-path" id="filePath">Loading...</div>
  <div class="status">
    <span class="live-dot" id="liveDot"></span>
    <span id="liveStatus">Connecting...</span>
  </div>

  <div class="controls">
    <!-- Search -->
    <div class="search-wrap">
      <span class="search-icon">🔍</span>
      <input type="text" class="search" id="searchInput" placeholder="Search logs...">
    </div>

    <!-- Level filters -->
    <div class="filters">
      <div class="pill pill-all active" onclick="setFilter('ALL')">ALL</div>
      <div class="pill pill-info" onclick="setFilter('INFO')">INFO</div>
      <div class="pill pill-warning" onclick="setFilter('WARNING')">WARN</div>
      <div class="pill pill-error" onclick="setFilter('ERROR')">ERROR</div>
      <div class="pill pill-critical" onclick="setFilter('CRITICAL')">CRIT</div>
      <div class="pill pill-debug" onclick="setFilter('DEBUG')">DEBUG</div>
    </div>

    <button class="btn btn-cyan" onclick="scrollToTop()">⬆ TOP</button>
    <button class="btn btn-gray" onclick="refreshLogs()">↺ REFRESH</button>
    <button class="btn btn-gray" id="autoScrollBtn" onclick="toggleAutoScroll()">📌 AUTO</button>
  </div>
</div>

<!-- Stats bar -->
<div class="stats">
  <div class="stat-item">Total: <span class="stat-val" id="totalCount">0</span></div>
  <div class="stat-item" style="color:#ef4444">Errors: <span class="stat-val" id="errorCount">0</span></div>
  <div class="stat-item" style="color:#f59e0b">Warnings: <span class="stat-val" id="warnCount">0</span></div>
  <div class="stat-item" style="color:#a855f7">Critical: <span class="stat-val" id="critCount">0</span></div>
  <div class="stat-item" style="color:#06b6d4">Info: <span class="stat-val" id="infoCount">0</span></div>
  <div class="stat-item" style="margin-left:auto">Last updated: <span class="stat-val" id="lastUpdated">—</span></div>
  <div class="stat-item">Showing: <span class="stat-val" id="showingCount">0</span></div>
</div>

<!-- Log display -->
<div class="log-container" id="logContainer">
  <div class="empty">
    <div class="empty-icon">⏳</div>
    <div>Loading logs...</div>
  </div>
</div>

<div class="footer">
  <span>Auto-updates every 3 seconds via WebSocket</span>
  <span id="wsState">●  WebSocket</span>
</div>

<script>
let allLogs = []
let currentFilter = 'ALL'
let searchQuery = ''
let autoScroll = false
let ws = null

// ── Load logs via REST on page load
async function loadLogs() {
  try {
    const res = await fetch('/api/logs')
    const data = await res.json()
    document.getElementById('filePath').textContent = data.file
    allLogs = data.logs
    renderLogs()
    updateStats()
  } catch(e) {
    console.error('Load error:', e)
  }
}

// ── WebSocket for live updates
function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  ws = new WebSocket(`${proto}//${location.host}/ws`)

  ws.onopen = () => {
    document.getElementById('liveDot').className = 'live-dot'
    document.getElementById('liveStatus').textContent = 'LIVE'
    document.getElementById('wsState').textContent = '● Connected'
    document.getElementById('wsState').style.color = '#10b981'
  }

  ws.onmessage = (e) => {
    const data = JSON.parse(e.data)
    if (data.type === 'update') {
      allLogs = data.logs
      document.getElementById('lastUpdated').textContent = data.last_updated
      renderLogs()
      updateStats()
    }
  }

  ws.onclose = () => {
    document.getElementById('liveDot').className = 'live-dot disconnected'
    document.getElementById('liveStatus').textContent = 'Disconnected — retrying...'
    document.getElementById('wsState').textContent = '● Disconnected'
    document.getElementById('wsState').style.color = '#ef4444'
    setTimeout(connectWS, 3000) // auto reconnect
  }
}

// ── Render filtered logs
function renderLogs() {
  const container = document.getElementById('logContainer')
  const query = searchQuery.toLowerCase()

  const filtered = allLogs.filter(log => {
    const matchLevel = currentFilter === 'ALL' ||
      log.level === currentFilter ||
      (currentFilter === 'WARNING' && (log.level === 'WARNING' || log.level === 'WARN'))
    const matchSearch = !query ||
      log.raw?.toLowerCase().includes(query) ||
      log.message?.toLowerCase().includes(query) ||
      log.level?.toLowerCase().includes(query) ||
      log.timestamp?.toLowerCase().includes(query)
    return matchLevel && matchSearch
  })

  document.getElementById('showingCount').textContent = filtered.length

  if (filtered.length === 0) {
    container.innerHTML = `<div class="empty"><div class="empty-icon">🔍</div><div>No logs match your filter</div></div>`
    return
  }

  const html = filtered.map((log, i) => {
    const level = log.level || 'INFO'
    const msg = highlight(escapeHtml(log.message || log.raw || ''), query)
    const time = log.timestamp || ''
    return `<div class="log-entry level-${level} ${i === 0 ? 'new-entry' : ''}">
      <span class="log-time">${escapeHtml(time)}</span>
      <span class="log-level">${level}</span>
      <span class="log-msg">${msg}</span>
    </div>`
  }).join('')

  container.innerHTML = html

  if (autoScroll) {
    container.scrollTop = 0
  }
}

function updateStats() {
  const counts = { ERROR: 0, WARNING: 0, CRITICAL: 0, INFO: 0 }
  allLogs.forEach(l => {
    const lv = l.level || 'INFO'
    if (lv === 'WARN') counts.WARNING++
    else if (counts[lv] !== undefined) counts[lv]++
  })
  document.getElementById('totalCount').textContent = allLogs.length
  document.getElementById('errorCount').textContent = counts.ERROR
  document.getElementById('warnCount').textContent = counts.WARNING
  document.getElementById('critCount').textContent = counts.CRITICAL
  document.getElementById('infoCount').textContent = counts.INFO
  document.getElementById('lastUpdated').textContent = new Date().toLocaleTimeString()
}

function highlight(text, query) {
  if (!query) return text
  const re = new RegExp(`(${escapeRegex(query)})`, 'gi')
  return text.replace(re, '<span class="highlight">$1</span>')
}

function escapeHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')
}

function setFilter(level) {
  currentFilter = level
  document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'))
  const map = { ALL:'pill-all', INFO:'pill-info', WARNING:'pill-warning', ERROR:'pill-error', CRITICAL:'pill-critical', DEBUG:'pill-debug' }
  document.querySelector('.' + (map[level] || 'pill-all'))?.classList.add('active')
  renderLogs()
}

function scrollToTop() {
  document.getElementById('logContainer').scrollTop = 0
}

function refreshLogs() { loadLogs() }

function toggleAutoScroll() {
  autoScroll = !autoScroll
  const btn = document.getElementById('autoScrollBtn')
  btn.textContent = autoScroll ? '📌 AUTO ON' : '📌 AUTO'
  btn.className = autoScroll ? 'btn btn-cyan' : 'btn btn-gray'
}

// Search input
document.getElementById('searchInput').addEventListener('input', e => {
  searchQuery = e.target.value
  renderLogs()
})

// Init
loadLogs()
connectWS()
</script>
</body>
</html>"""

# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    ensure_demo_log()
    print(f"""
╔══════════════════════════════════════════╗
║          LOG VIEWER SERVER               ║
╠══════════════════════════════════════════╣
║  Log file : {LOG_FILE:<28} ║
║  URL      : http://localhost:8080        ║
║  Updates  : Every 3 seconds (WebSocket)  ║
╚══════════════════════════════════════════╝
    """)
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="warning")