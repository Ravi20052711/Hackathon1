# 🛡️ Threat Intel Fusion Engine

A full-stack, production-grade Threat Intelligence & SIEM platform with:
- Real-time WebSocket live feed
- AI-powered alert enrichment (OpenAI GPT-4)
- Interactive threat infrastructure graph (Cytoscape.js)
- IOC enrichment via VirusTotal, AbuseIPDB, GeoIP
- Auto-generated hunt queries (Splunk, Elastic, Sigma)
- Supabase authentication + database

---

## 📋 REQUIREMENTS

### Software to Install
| Software | Version | Download |
|----------|---------|----------|
| Node.js | 18+ | https://nodejs.org |
| Python | 3.11+ | https://python.org |
| Redis | 7+ | https://redis.io/download |
| Git | any | https://git-scm.com |

### API Keys (All Free Tiers Available)
| Service | Purpose | Get Key |
|---------|---------|---------|
| **Supabase** | Auth + Database | https://supabase.com |
| VirusTotal | IOC reputation | https://virustotal.com |
| AbuseIPDB | IP abuse check | https://abuseipdb.com |
| AlienVault OTX | OSINT feed | https://otx.alienvault.com |
| OpenAI | AI summaries | https://platform.openai.com |

> **Note:** The app works in **demo mode** without any API keys. Just use the "Demo Access" button on the login page.

---

## 🚀 QUICK START (No Docker)

### Step 1: Install Redis

**Windows:**
```
# Option 1: WSL (recommended)
wsl --install
# Then in WSL terminal:
sudo apt install redis-server
sudo service redis-server start

# Option 2: Download from https://github.com/microsoftarchive/redis/releases
```

**macOS:**
```bash
brew install redis
brew services start redis
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update && sudo apt install redis-server -y
sudo systemctl start redis-server
sudo systemctl enable redis-server
```

**Verify Redis:**
```bash
redis-cli ping
# Should return: PONG
```

---

### Step 2: Set Up Supabase (Database & Auth)

1. Go to **https://supabase.com** → Sign up (free)
2. Click **"New Project"** → Name it `threat-intel-fusion`
3. Choose a region near you → Click **"Create Project"** (wait ~2 minutes)
4. Go to **Settings → API** and copy:
   - `Project URL` → this is your `SUPABASE_URL`
   - `anon public` key → this is your `SUPABASE_ANON_KEY`
   - `service_role` key → this is your `SUPABASE_SERVICE_ROLE_KEY`

5. **Run the database schema:**
   - In Supabase, go to **SQL Editor** → **New Query**
   - Open the file `scripts/supabase_schema.sql` from this project
   - Paste all the SQL into the editor
   - Click **"Run"** (should see "Schema created successfully!")

6. **Enable Email Auth (for login to work):**
   - Go to **Authentication → Providers → Email**
   - Toggle it ON
   - For testing: disable "Confirm email" so you can login instantly

---

### Step 3: Configure Environment Variables

**Backend:**
```bash
cd backend
cp .env.example .env
# Edit .env with your keys:
nano .env    # or use any text editor
```

Fill in:
```env
SUPABASE_URL=https://xxxxxxxxxxxx.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1...
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1...
VIRUSTOTAL_API_KEY=your_key_here    # Optional
ABUSEIPDB_API_KEY=your_key_here     # Optional
OPENAI_API_KEY=your_key_here        # Optional
REDIS_URL=redis://localhost:6379
```

**Frontend:**
```bash
cd frontend
cp .env.example .env
# Edit .env:
```

Fill in:
```env
VITE_SUPABASE_URL=https://xxxxxxxxxxxx.supabase.co
VITE_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1...
```

---

### Step 4: Install & Run Backend

```bash
cd backend

# Create virtual environment (recommended)
python -m venv venv

# Activate it:
# Windows: venv\Scripts\activate
# Mac/Linux: source venv/bin/activate

# Install all packages
pip install -r requirements.txt

# Start FastAPI server
uvicorn app.main:app --reload --port 8000
```

✅ Backend running at: **http://localhost:8000**
📚 API docs at: **http://localhost:8000/api/docs**

---

### Step 5: Install & Run Frontend

Open a **new terminal window** (keep backend running):

```bash
cd frontend

# Install Node packages
npm install

# Start React dev server
npm run dev
```

✅ Frontend running at: **http://localhost:5173**

---

### Step 6: Open the App

1. Go to **http://localhost:5173**
2. Click **"DEMO ACCESS"** to login without setup
   - OR create an account with any email/password

---

## 🐳 DOCKER SETUP (Alternative)

If you have Docker installed, this is the easiest way:

```bash
# Clone/extract the project
cd threat-intel-fusion

# Configure env files first (same as Step 3 above)
cp .env.example .env
cp frontend/.env.example frontend/.env
# Edit both .env files with your keys

# Start everything
docker-compose up --build

# Access:
# Frontend: http://localhost:5173
# Backend: http://localhost:8000
# API Docs: http://localhost:8000/api/docs
```

---

## 🧪 DEMO MODE (No API Keys)

The app is fully functional without any API keys using **demo mode**:

- **Login:** Click "DEMO ACCESS" button → auto-login as `demo@example.com`
- **IOC Data:** Pre-populated with realistic demo IOC data
- **Live Feed:** Simulated threat events via WebSocket every 3-8 seconds
- **Graph:** Pre-built threat actor graph (Lazarus Group, APT-29)
- **Alerts:** Demo enriched alerts with AI summaries
- **Hunt Queries:** Pre-built Splunk/Elastic/Sigma templates

---

## 📁 PROJECT STRUCTURE

```
threat-intel-fusion/
├── backend/
│   ├── app/
│   │   ├── api/                    ← FastAPI route handlers
│   │   │   ├── auth.py             ← Login, signup, logout
│   │   │   ├── ioc.py              ← IOC CRUD + enrichment
│   │   │   ├── alerts.py           ← SIEM alerts + WebSocket
│   │   │   ├── graph.py            ← Graph data API
│   │   │   ├── hunt.py             ← Hunt query generation
│   │   │   ├── feed.py             ← Threat feed
│   │   │   └── reports.py          ← Report generation
│   │   ├── core/
│   │   │   ├── config.py           ← Settings from .env
│   │   │   └── supabase_client.py  ← Supabase singleton
│   │   ├── models/
│   │   │   └── schemas.py          ← Pydantic data models
│   │   ├── services/
│   │   │   ├── enrichment/
│   │   │   │   └── enrichment_pipeline.py  ← VT, AbuseIPDB, GeoIP
│   │   │   ├── graph/
│   │   │   │   └── graph_analyzer.py       ← NetworkX analysis
│   │   │   ├── llm/
│   │   │   │   └── llm_analyzer.py         ← OpenAI integration
│   │   │   ├── siem/
│   │   │   │   └── alert_enricher.py       ← SIEM alert processing
│   │   │   └── hunting/
│   │   │       └── hunt_engine.py          ← Query generation
│   │   └── main.py                 ← FastAPI app bootstrap
│   ├── requirements.txt            ← Python dependencies
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Dashboard/
│   │   │   │   ├── Layout.jsx      ← Sidebar + header wrapper
│   │   │   │   ├── MetricCard.jsx  ← Glassmorphism stat cards
│   │   │   │   └── RiskChart.jsx   ← Recharts pie chart
│   │   │   └── ThreatFeed/
│   │   │       └── ThreatFeed.jsx  ← Live WebSocket feed
│   │   ├── hooks/
│   │   │   ├── useAuth.jsx         ← Global auth state
│   │   │   └── useWebSocket.js     ← WS connection manager
│   │   ├── pages/
│   │   │   ├── LoginPage.jsx       ← Cyberpunk login
│   │   │   ├── SignupPage.jsx      ← Registration
│   │   │   ├── DashboardPage.jsx   ← Main overview
│   │   │   ├── IOCExplorerPage.jsx ← Browse/add IOCs
│   │   │   ├── AlertsPage.jsx      ← SIEM alerts
│   │   │   ├── GraphViewPage.jsx   ← Cytoscape.js graph
│   │   │   └── HuntPage.jsx        ← Hunt queries
│   │   ├── utils/
│   │   │   ├── api.js              ← Axios HTTP client
│   │   │   └── supabaseClient.js   ← Supabase frontend client
│   │   ├── App.jsx                 ← Routes + auth guards
│   │   ├── main.jsx                ← React entry point
│   │   └── index.css               ← Tailwind + custom styles
│   └── package.json
├── scripts/
│   └── supabase_schema.sql         ← DB setup script
├── docker-compose.yml
└── README.md
```

---

## 🔧 COMMON ISSUES

### "Connection refused" on port 8000
```bash
# Make sure Redis is running first
redis-cli ping  # Should return PONG
# Then restart backend
```

### "Module not found" in backend
```bash
cd backend
pip install -r requirements.txt
# Make sure your virtual environment is activated!
```

### Frontend won't connect to backend
Check `vite.config.js` proxy is pointing to `http://localhost:8000`

### Supabase auth not working
- Check your `.env` and `frontend/.env` have the correct keys
- Make sure Email provider is enabled in Supabase Auth settings
- Try the Demo login button first to verify the app works

### Graph page is empty
The graph page loads Cytoscape.js dynamically. If nothing shows:
1. Check browser console for errors
2. Make sure `cytoscape` package is installed: `npm install cytoscape`

---

## 🎮 FEATURES WALKTHROUGH

| Feature | Where | What it does |
|---------|-------|-------------|
| Live Feed | Dashboard | WebSocket streams threat events every 3-8s |
| IOC Explorer | /iocs | Browse, search, and add IOCs with auto-enrichment |
| Alert Enrichment | /alerts → Submit Log | Paste raw log → AI extracts IOCs + risk score + recommendations |
| Threat Graph | /graph | Click nodes to see details, zoom with buttons |
| Hunt Queries | /hunt | Generate Splunk/Elastic/Sigma queries, copy with one click |
| Demo Mode | Login page | Works with zero configuration |

---

## 📡 API ENDPOINTS

Once backend is running, visit: **http://localhost:8000/api/docs**

Key endpoints:
- `POST /api/auth/login` - Login
- `GET /api/ioc/` - List IOCs
- `POST /api/ioc/` - Add + enrich IOC
- `GET /api/ioc/stats` - Dashboard stats
- `POST /api/alerts/` - Submit alert for enrichment
- `WS /api/alerts/ws/live` - WebSocket live feed
- `GET /api/graph/` - Threat graph data
- `POST /api/hunt/generate` - Generate hunt queries
