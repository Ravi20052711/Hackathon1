-- ============================================================
-- SUPABASE DATABASE SCHEMA
-- Threat Intel Fusion Engine
-- ============================================================
-- Run this in: Supabase Dashboard → SQL Editor → New Query
-- Then click "Run" to create all tables.
-- ============================================================


-- -------------------------------------------------------
-- TABLE: iocs (Indicators of Compromise)
-- Stores all threat indicators with enrichment data
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS iocs (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    
    -- Core IOC data
    value TEXT NOT NULL,                              -- The actual IOC (IP, domain, hash, etc.)
    ioc_type TEXT NOT NULL,                           -- ip | domain | hash | url | email
    source TEXT DEFAULT 'manual',                     -- Where this IOC came from
    tags TEXT[] DEFAULT '{}',                         -- Array of tags for filtering
    notes TEXT,                                       -- Analyst notes
    
    -- Risk scoring
    risk_score INTEGER DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    
    -- VirusTotal enrichment
    vt_detections INTEGER,                            -- Number of AV engines that flagged it
    vt_total INTEGER,                                 -- Total engines checked
    
    -- AbuseIPDB enrichment
    abuse_confidence INTEGER,                         -- Abuse confidence score 0-100
    
    -- Geolocation
    country TEXT,
    city TEXT,
    latitude FLOAT,
    longitude FLOAT,
    asn TEXT,                                         -- Autonomous System Number
    
    -- WHOIS
    whois_registrar TEXT,
    
    -- Timestamps
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for fast lookups by type and risk score (used in list queries)
CREATE INDEX idx_iocs_type ON iocs(ioc_type);
CREATE INDEX idx_iocs_risk_score ON iocs(risk_score DESC);
CREATE INDEX idx_iocs_created_at ON iocs(created_at DESC);

-- -------------------------------------------------------
-- TABLE: alerts (SIEM Alerts)
-- Stores enriched alerts from SIEM systems
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    
    raw_log TEXT NOT NULL,                            -- Original log line
    source_system TEXT DEFAULT 'manual',              -- Splunk | Elastic | Sentinel | Manual
    severity TEXT DEFAULT 'medium',                   -- critical | high | medium | low | info
    
    -- Enrichment results
    risk_score INTEGER DEFAULT 0,
    extracted_iocs TEXT[] DEFAULT '{}',               -- IOCs found in the log
    llm_summary TEXT,                                 -- AI-generated threat analysis
    recommended_actions TEXT[] DEFAULT '{}',          -- Remediation steps
    mitre_techniques TEXT[] DEFAULT '{}',             -- MITRE ATT&CK technique IDs
    
    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    enriched_at TIMESTAMPTZ
);

CREATE INDEX idx_alerts_risk_score ON alerts(risk_score DESC);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_created_at ON alerts(created_at DESC);

-- -------------------------------------------------------
-- TABLE: feed_items (Threat Intelligence Feed)
-- Live feed of threat events from OSINT sources
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS feed_items (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    
    event_type TEXT NOT NULL,                         -- new_ioc | alert_triggered | hunt_result
    severity TEXT DEFAULT 'medium',
    title TEXT NOT NULL,
    description TEXT,
    ioc_value TEXT,                                   -- Related IOC if applicable
    risk_score INTEGER,
    source TEXT DEFAULT 'system',
    tags TEXT[] DEFAULT '{}',
    
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_feed_items_timestamp ON feed_items(timestamp DESC);

-- -------------------------------------------------------
-- TABLE: hunt_queries (Threat Hunt Results)
-- Auto-generated and saved hunt queries
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS hunt_queries (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    
    name TEXT NOT NULL,
    hypothesis TEXT,
    query_splunk TEXT,
    query_elastic TEXT,
    query_sigma TEXT,
    data_sources TEXT[] DEFAULT '{}',
    triggered_by_ioc TEXT,
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- -------------------------------------------------------
-- ROW LEVEL SECURITY (RLS)
-- Ensures users can only see their own data
-- Enable in Supabase → Authentication → Policies
-- -------------------------------------------------------

-- Enable RLS on all tables
ALTER TABLE iocs ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE feed_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE hunt_queries ENABLE ROW LEVEL SECURITY;

-- Policy: Allow authenticated users to read all data
-- (In production, add user_id column and filter by auth.uid())
CREATE POLICY "Allow authenticated read" ON iocs
    FOR SELECT TO authenticated USING (true);

CREATE POLICY "Allow authenticated insert" ON iocs
    FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "Allow authenticated delete" ON iocs
    FOR DELETE TO authenticated USING (true);

CREATE POLICY "Allow authenticated read" ON alerts
    FOR SELECT TO authenticated USING (true);

CREATE POLICY "Allow authenticated insert" ON alerts
    FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "Allow authenticated read" ON feed_items
    FOR SELECT TO authenticated USING (true);

CREATE POLICY "Allow authenticated insert" ON feed_items
    FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "Allow authenticated read" ON hunt_queries
    FOR SELECT TO authenticated USING (true);

CREATE POLICY "Allow authenticated insert" ON hunt_queries
    FOR INSERT TO authenticated WITH CHECK (true);

-- -------------------------------------------------------
-- SAMPLE DATA (Optional - for testing)
-- -------------------------------------------------------
INSERT INTO iocs (value, ioc_type, risk_score, source, country, city, latitude, longitude, vt_detections, vt_total, tags)
VALUES
    ('192.168.1.100', 'ip', 95, 'AlienVault OTX', 'Russia', 'Moscow', 55.75, 37.62, 45, 70, ARRAY['c2', 'botnet']),
    ('evil-domain.xyz', 'domain', 88, 'URLhaus', 'China', 'Beijing', 39.90, 116.40, 32, 70, ARRAY['phishing', 'malware']),
    ('a3f5d8e9b2c1f0a7deadbeef12345678', 'hash', 72, 'MalwareBazaar', NULL, NULL, NULL, NULL, 28, 70, ARRAY['ransomware']);

-- Confirm setup
SELECT 'Schema created successfully!' as status;
SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';
