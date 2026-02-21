import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { AlertTriangle, ChevronDown, ChevronUp, Send, Shield, RefreshCw } from 'lucide-react'
import axios from 'axios'
import toast from 'react-hot-toast'

const SEVERITY_COLORS = {
  critical: 'border-red-500/40 bg-red-500/5 text-red-400',
  high: 'border-amber-500/40 bg-amber-500/5 text-amber-400',
  medium: 'border-blue-500/40 bg-blue-500/5 text-blue-400',
  low: 'border-green-500/40 bg-green-500/5 text-green-400',
}

const SEVERITY_BADGE = {
  critical: 'bg-red-500/20 text-red-400 border border-red-500/40',
  high: 'bg-amber-500/20 text-amber-400 border border-amber-500/40',
  medium: 'bg-blue-500/20 text-blue-400 border border-blue-500/40',
  low: 'bg-green-500/20 text-green-400 border border-green-500/40',
}

// Real example logs for quick testing
const EXAMPLE_LOGS = [
  {
    label: '🔴 Botnet C2 Beacon',
    log: `2026-02-21 14:22:11 CRITICAL EDR blocked process C:\\Users\\Admin\\AppData\\Local\\Temp\\svchost32.exe attempting outbound connection to 185.220.101.45:4444 - Parent: powershell.exe - Hash: a3f5d8e9b2c1f0a7deadbeef12345678 - Bytes: 4829`
  },
  {
    label: '🟡 Phishing Domain',
    log: `2026-02-21 09:15:44 WARN proxy blocked request to evil-domain.xyz from HOST-PC22 user: jsmith - Category: Malware - URL: http://evil-domain.xyz/login.php - UA: Chrome/98`
  },
  {
    label: '🔴 Ransomware Activity',
    log: `2026-02-21 03:44:02 CRITICAL ransomware detected on FILE-SERVER-01 - 4821 files encrypted in 90 seconds - extension: .locked - process: mimikatz.exe - lateral movement detected via psexec`
  },
  {
    label: '🟡 PowerShell Suspicious',
    log: `2026-02-21 11:30:55 HIGH suspicious powershell execution on WORKSTATION-14 - encoded command detected - spawned by outlook.exe - persistence via scheduled task created`
  },
]

function AlertCard({ alert }) {
  const [expanded, setExpanded] = useState(false)
  const color = SEVERITY_COLORS[alert.severity] || SEVERITY_COLORS.medium
  const badge = SEVERITY_BADGE[alert.severity] || SEVERITY_BADGE.medium

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={`glass-card border ${color} overflow-hidden`}
    >
      {/* Header */}
      <div className="p-4 flex items-center justify-between cursor-pointer"
        onClick={() => setExpanded(!expanded)}>
        <div className="flex items-center gap-3 flex-1 min-w-0">
          <AlertTriangle size={16} className="shrink-0" />
          <div className="min-w-0">
            <p className="text-white font-mono text-sm truncate">
              {alert.raw_log?.slice(0, 80)}...
            </p>
            <p className="text-gray-500 text-xs font-mono mt-0.5">
              {alert.source_system} · {new Date(alert.created_at).toLocaleString()}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3 shrink-0 ml-3">
          <span className={`px-2 py-1 rounded text-xs font-mono font-bold uppercase ${badge}`}>
            {alert.severity}
          </span>
          <span className="text-white font-mono font-bold">{alert.risk_score}</span>
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </div>
      </div>

      {/* Expanded Details */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="border-t border-gray-800/50"
          >
            <div className="p-4 space-y-4">

              {/* Raw Log */}
              <div>
                <p className="text-xs font-mono text-gray-500 uppercase mb-2">Raw Log</p>
                <pre className="bg-black/40 rounded-lg p-3 text-xs font-mono text-gray-300 whitespace-pre-wrap break-all border border-gray-800">
                  {alert.raw_log}
                </pre>
              </div>

              {/* DB Matches - THE KEY FEATURE */}
              {alert.db_matches?.length > 0 && (
                <div>
                  <p className="text-xs font-mono text-red-400 uppercase mb-2">
                    ⚠️ {alert.db_matches.length} Known Threat Match(es) in Database
                  </p>
                  <div className="space-y-1">
                    {alert.db_matches.map((m, i) => (
                      <div key={i} className="flex items-center gap-2 bg-red-500/5 border border-red-500/20 rounded p-2 text-xs font-mono">
                        <span className="text-red-400 font-bold uppercase">{m.ioc_type}</span>
                        <span className="text-gray-300 flex-1 truncate">{m.value}</span>
                        <span className="text-red-400">Risk: {m.risk_score}/100</span>
                        <span className="text-gray-500">{m.source}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Extracted IOCs */}
              {alert.extracted_iocs?.length > 0 && (
                <div>
                  <p className="text-xs font-mono text-gray-500 uppercase mb-2">Extracted IOCs</p>
                  <div className="flex flex-wrap gap-1">
                    {alert.extracted_iocs.slice(0, 10).map((ioc, i) => (
                      <span key={i} className="px-2 py-0.5 bg-gray-800 rounded text-xs font-mono text-cyan-400 border border-gray-700">
                        {ioc.length > 40 ? ioc.slice(0, 40) + '...' : ioc}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* MITRE Techniques */}
              {alert.mitre_techniques?.length > 0 && (
                <div>
                  <p className="text-xs font-mono text-gray-500 uppercase mb-2">MITRE ATT&CK</p>
                  <div className="flex flex-wrap gap-1">
                    {alert.mitre_techniques.map((t, i) => (
                      <span key={i} className="px-2 py-0.5 bg-purple-500/10 border border-purple-500/30 rounded text-xs font-mono text-purple-400">
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* AI Summary */}
              {alert.llm_summary && (
                <div>
                  <p className="text-xs font-mono text-gray-500 uppercase mb-2">Threat Analysis</p>
                  <pre className="bg-black/20 rounded-lg p-3 text-xs font-mono text-gray-300 whitespace-pre-wrap border border-gray-800/50">
                    {alert.llm_summary}
                  </pre>
                </div>
              )}

              {/* Recommendations */}
              {alert.recommended_actions?.length > 0 && (
                <div>
                  <p className="text-xs font-mono text-gray-500 uppercase mb-2">Recommended Actions</p>
                  <div className="space-y-1">
                    {alert.recommended_actions.map((rec, i) => (
                      <p key={i} className="text-xs font-mono text-gray-300 flex items-start gap-2">
                        <span className="text-cyan-500 mt-0.5">→</span> {rec}
                      </p>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [rawLog, setRawLog] = useState('')
  const [source, setSource] = useState('manual')

  const token = localStorage.getItem('access_token')
  const headers = { Authorization: `Bearer ${token}` }

  const loadAlerts = async () => {
    try {
      const res = await axios.get('/api/alerts/', { headers })
      setAlerts(res.data)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadAlerts() }, [])

  const submitAlert = async () => {
    if (!rawLog.trim()) return toast.error('Paste a log line first')
    setSubmitting(true)
    try {
      const res = await axios.post('/api/alerts/', {
        raw_log: rawLog,
        source_system: source,
        severity: 'medium'
      }, { headers })

      // Add to top of list
      setAlerts(prev => [res.data, ...prev])
      setRawLog('')
      toast.success(`Alert enriched — Risk Score: ${res.data.risk_score}/100`)
    } catch (err) {
      toast.error('Enrichment failed')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white font-mono">ALERT CENTER</h1>
          <p className="text-gray-500 text-xs font-mono mt-1">
            Paste any raw log → get IOC extraction, MITRE mapping, DB cross-check
          </p>
        </div>
        <button onClick={loadAlerts}
          className="px-3 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-400 rounded-lg text-xs font-mono flex items-center gap-1 transition-all">
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {/* Submit Form */}
      <div className="glass-card p-5 border border-cyan-500/10">
        <p className="text-xs font-mono text-gray-500 uppercase mb-3">Submit Raw Log for Analysis</p>

        {/* Example Logs */}
        <div className="flex gap-2 flex-wrap mb-3">
          <span className="text-xs font-mono text-gray-600">Quick examples:</span>
          {EXAMPLE_LOGS.map((ex, i) => (
            <button key={i} onClick={() => setRawLog(ex.log)}
              className="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded text-xs font-mono text-gray-400 transition-all border border-gray-700">
              {ex.label}
            </button>
          ))}
        </div>

        <textarea
          value={rawLog}
          onChange={e => setRawLog(e.target.value)}
          placeholder={`Paste any firewall, EDR, proxy, or SIEM log here...\n\nExample:\n2026-02-21 14:22:11 CRITICAL EDR blocked connection to 185.220.101.45:4444 process: powershell.exe`}
          rows={5}
          className="w-full bg-black/30 border border-gray-700 rounded-lg p-3 text-white font-mono text-xs focus:outline-none focus:border-cyan-400 resize-none placeholder-gray-700"
        />

        <div className="flex items-center gap-3 mt-3">
          <select value={source} onChange={e => setSource(e.target.value)}
            className="bg-black/30 border border-gray-700 rounded-lg px-3 py-2 text-white font-mono text-xs focus:outline-none focus:border-cyan-400">
            {['manual','Splunk','Elastic','Windows Defender','CrowdStrike','Firewall','Proxy'].map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>

          <button onClick={submitAlert} disabled={submitting || !rawLog.trim()}
            className="flex items-center gap-2 px-5 py-2 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed text-black font-bold font-mono rounded-lg text-sm transition-all">
            {submitting
              ? <><RefreshCw size={14} className="animate-spin" /> ANALYZING...</>
              : <><Send size={14} /> ANALYZE LOG</>
            }
          </button>

          <p className="text-gray-600 text-xs font-mono">
            Cross-checks against {alerts.length > 0 ? 'your' : 'local'} threat database
          </p>
        </div>
      </div>

      {/* How it Works Info Box */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { step: '1', title: 'Extract', desc: 'Pulls IPs, domains, hashes from log text' },
          { step: '2', title: 'Match', desc: 'Checks against your 130+ real IOCs in DB' },
          { step: '3', title: 'MITRE', desc: 'Maps to ATT&CK techniques automatically' },
          { step: '4', title: 'Respond', desc: 'Generates specific remediation steps' },
        ].map(item => (
          <div key={item.step} className="glass-card p-3 text-center">
            <div className="w-7 h-7 rounded-full bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 font-bold font-mono text-sm flex items-center justify-center mx-auto mb-2">
              {item.step}
            </div>
            <p className="text-white font-mono text-xs font-bold">{item.title}</p>
            <p className="text-gray-500 text-xs font-mono mt-1">{item.desc}</p>
          </div>
        ))}
      </div>

      {/* Alert List */}
      <div>
        <p className="text-xs font-mono text-gray-500 uppercase mb-3">
          {alerts.length} Enriched Alerts — click any to expand
        </p>
        {loading && <p className="text-gray-600 font-mono text-sm text-center py-8">Loading...</p>}
        {!loading && alerts.length === 0 && (
          <div className="glass-card p-8 text-center">
            <Shield size={32} className="text-gray-700 mx-auto mb-3" />
            <p className="text-gray-500 font-mono text-sm">No alerts yet</p>
            <p className="text-gray-700 font-mono text-xs mt-1">Click an example above and hit "ANALYZE LOG"</p>
          </div>
        )}
        <div className="space-y-3">
          {alerts.map(alert => <AlertCard key={alert.id} alert={alert} />)}
        </div>
      </div>
    </div>
  )
}
