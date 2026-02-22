import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Upload, Send, RefreshCw, CheckCircle, AlertTriangle, Mail, Zap, Clock, X } from 'lucide-react'
import axios from 'axios'
import toast from 'react-hot-toast'

const EXAMPLE_LOGS = [
  {
    label: '🔴 Botnet C2',
    log: '2026-02-22 14:22:11 CRITICAL EDR blocked connection to 185.220.101.45:4444 process: powershell.exe -EncodedCommand bytes: 4829'
  },
  {
    label: '🔴 Ransomware',
    log: '2026-02-22 03:44:02 CRITICAL ransomware detected FILE-SERVER-01 - 4821 files encrypted - extension: .locked - mimikatz.exe - lateral movement psexec'
  },
  {
    label: '🟡 Phishing URL',
    log: '2026-02-22 09:15:44 WARN proxy blocked request to https://faceb00k.com/login from HOST-PC22 user: jsmith'
  },
  {
    label: '🟢 Normal Login',
    log: '2026-02-22 10:15:33 INFO authentication success - user: ravi@company.com - ip: 192.168.1.105 - MFA: passed'
  },
]

function TaskCard({ task }) {
  const scoreColor = task.risk_score >= 80 ? 'text-red-400' : task.risk_score >= 60 ? 'text-amber-400' : 'text-green-400'
  const borderColor = task.risk_score >= 80 ? 'border-red-500/30' : task.risk_score >= 60 ? 'border-amber-500/30' : 'border-green-500/30'
  const bgColor = task.risk_score >= 80 ? 'bg-red-500/5' : task.risk_score >= 60 ? 'bg-amber-500/5' : 'bg-green-500/5'

  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      className={`border ${borderColor} ${bgColor} rounded-lg p-4 font-mono`}
    >
      <div className="flex items-center justify-between mb-2 flex-wrap gap-2">
        <div className="flex items-center gap-2">
          {task.status === 'processing' && <RefreshCw size={13} className="text-cyan-400 animate-spin" />}
          {task.status === 'done' && <CheckCircle size={13} className="text-green-400" />}
          {task.status === 'error' && <X size={13} className="text-red-400" />}
          <span className="text-gray-500 text-xs">ID: {task.task_id?.slice(0, 8)}</span>
          <span className="text-gray-700 text-xs">{task.source}</span>
        </div>
        <div className="flex items-center gap-2">
          {task.email_sent && (
            <span className="flex items-center gap-1 px-2 py-0.5 bg-cyan-500/10 border border-cyan-500/30 rounded text-xs text-cyan-400">
              <Mail size={10} /> Email Sent
            </span>
          )}
          {task.risk_score !== undefined && (
            <span className={`text-lg font-bold ${scoreColor}`}>{task.risk_score}/100</span>
          )}
          {task.severity && (
            <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${
              task.severity === 'critical' ? 'bg-purple-500/20 text-purple-400' :
              task.severity === 'high'     ? 'bg-red-500/20 text-red-400' :
              task.severity === 'medium'   ? 'bg-amber-500/20 text-amber-400' :
              'bg-green-500/20 text-green-400'
            }`}>{task.severity}</span>
          )}
        </div>
      </div>

      <p className="text-gray-400 text-xs truncate">{task.log?.slice(0, 100)}...</p>

      {task.iocs?.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {task.iocs.slice(0, 6).map((ioc, i) => (
            <span key={i} className="px-1.5 py-0.5 bg-gray-800 rounded text-xs text-cyan-400">{ioc.slice(0, 30)}</span>
          ))}
        </div>
      )}

      {task.mitre?.length > 0 && (
        <div className="mt-1 flex flex-wrap gap-1">
          {task.mitre.slice(0, 3).map((t, i) => (
            <span key={i} className="px-1.5 py-0.5 bg-purple-500/10 border border-purple-500/20 rounded text-xs text-purple-400">{t}</span>
          ))}
        </div>
      )}

      {task.status === 'processing' && (
        <div className="mt-2 flex items-center gap-2 text-xs text-gray-600">
          <RefreshCw size={10} className="animate-spin" /> Enriching log in background...
        </div>
      )}
    </motion.div>
  )
}

export default function IngestLogsPage() {
  const [logs, setLogs]           = useState('')
  const [source, setSource]       = useState('system')
  const [submitting, setSubmitting] = useState(false)
  const [tasks, setTasks]         = useState([])
  const [stats, setStats]         = useState(null)
  const token = localStorage.getItem('access_token')
  const headers = { Authorization: `Bearer ${token}` }

  const loadStats = async () => {
    try {
      const res = await axios.get('/api/ingest-logs/status', { headers })
      setStats(res.data)
    } catch {}
  }

  useEffect(() => { loadStats() }, [])

  const submitLogs = async () => {
    const lines = logs.split('\n').map(l => l.trim()).filter(Boolean)
    if (!lines.length) return toast.error('Paste at least one log line')
    setSubmitting(true)
    try {
      const res = await axios.post('/api/ingest-logs/', {
        logs: lines,
        source
      }, { headers })

      const { accepted, task_ids } = res.data

      // Add tasks as "processing"
      const newTasks = task_ids.map((id, i) => ({
        task_id: id,
        log: lines[i] || lines[0],
        source,
        status: 'processing',
      }))
      setTasks(prev => [...newTasks, ...prev])

      toast.success(`${accepted} log(s) queued — enriching in background`)
      setLogs('')

      // Poll alerts to get results after 5 seconds
      setTimeout(async () => {
        try {
          const alertsRes = await axios.get('/api/alerts/?limit=20', { headers })
          const recent = alertsRes.data.slice(0, accepted)
          setTasks(prev => prev.map(t => {
            const match = recent.find(a =>
              a.raw_log && t.log && a.raw_log.slice(0, 60) === t.log.slice(0, 60)
            )
            if (match) {
              return {
                ...t,
                status:     'done',
                risk_score: match.risk_score,
                severity:   match.severity,
                iocs:       match.extracted_iocs || [],
                mitre:      match.mitre_techniques || [],
                email_sent: match.risk_score >= 60,
              }
            }
            return { ...t, status: 'done' }
          }))
          loadStats()
        } catch {}
      }, 5000)

    } catch (err) {
      toast.error('Ingest failed — check backend')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="p-6 space-y-5 max-w-5xl mx-auto">

      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white font-mono flex items-center gap-2">
          <Upload size={22} className="text-cyan-400" /> INGEST LOGS
        </h1>
        <p className="text-gray-500 text-xs font-mono mt-1">
          Send logs → auto enrichment → IOC extraction → risk scoring → email alert if score ≥ 60
        </p>
      </div>

      {/* Pipeline Diagram */}
      <div className="glass-card p-4 border border-cyan-500/10">
        <p className="text-xs font-mono text-gray-500 uppercase mb-3">How It Works</p>
        <div className="flex items-center gap-2 flex-wrap">
          {[
            { icon: '📥', label: 'Ingest Log',     color: 'text-cyan-400'   },
            { icon: '→',  label: '',                color: 'text-gray-700'   },
            { icon: '🔍', label: 'Extract IOCs',    color: 'text-purple-400' },
            { icon: '→',  label: '',                color: 'text-gray-700'   },
            { icon: '🗄️', label: 'DB + Live Check', color: 'text-amber-400'  },
            { icon: '→',  label: '',                color: 'text-gray-700'   },
            { icon: '🎯', label: 'MITRE Map',       color: 'text-green-400'  },
            { icon: '→',  label: '',                color: 'text-gray-700'   },
            { icon: '🤖', label: 'AI Analyze',      color: 'text-cyan-400'   },
            { icon: '→',  label: '',                color: 'text-gray-700'   },
            { icon: '📧', label: 'Email if ≥60',    color: 'text-red-400'    },
          ].map((step, i) => (
            <span key={i} className={`text-xs font-mono ${step.color} ${step.label ? 'px-2 py-1 bg-gray-800/50 rounded' : ''}`}>
              {step.icon} {step.label}
            </span>
          ))}
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Total Alerts',    value: stats.total_alerts,      color: 'text-white'   },
            { label: 'High Risk',       value: stats.high_risk_alerts,  color: 'text-red-400' },
            { label: 'Email Threshold', value: '≥ 60',                  color: 'text-cyan-400'},
            { label: 'Status',          value: '● Active',              color: 'text-green-400'},
          ].map(s => (
            <div key={s.label} className="glass-card p-3 text-center border border-gray-800">
              <div className={`text-xl font-bold font-mono ${s.color}`}>{s.value}</div>
              <div className="text-gray-600 text-xs font-mono mt-1">{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Input Form */}
      <div className="glass-card p-5 border border-cyan-500/10 space-y-4">
        <p className="text-xs font-mono text-gray-500 uppercase">Submit Logs for Enrichment</p>

        {/* Quick examples */}
        <div className="flex gap-2 flex-wrap">
          <span className="text-xs font-mono text-gray-600">Quick fill:</span>
          {EXAMPLE_LOGS.map((ex, i) => (
            <button key={i} onClick={() => setLogs(ex.log)}
              className="px-2 py-1 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded text-xs font-mono text-gray-400 transition-all">
              {ex.label}
            </button>
          ))}
        </div>

        {/* Log textarea */}
        <textarea
          value={logs}
          onChange={e => setLogs(e.target.value)}
          rows={6}
          placeholder={`Paste one or multiple log lines here — one per line.\n\nExamples:\n2026-02-22 14:22:11 CRITICAL blocked connection to 185.220.101.45:4444 process: powershell.exe\n2026-02-22 09:15:44 WARN proxy blocked https://faceb00k.com from HOST-PC22`}
          className="w-full bg-black/30 border border-gray-700 rounded-lg p-3 text-white font-mono text-xs focus:outline-none focus:border-cyan-400 resize-none placeholder-gray-700"
        />

        {/* Controls */}
        <div className="flex items-center gap-3 flex-wrap">
          <select value={source} onChange={e => setSource(e.target.value)}
            className="bg-black/30 border border-gray-700 rounded-lg px-3 py-2 text-white font-mono text-xs focus:outline-none focus:border-cyan-400">
            {['system', 'Windows', 'Splunk', 'Elastic', 'Firewall', 'EDR', 'Proxy', 'manual'].map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>

          <button onClick={submitLogs} disabled={submitting || !logs.trim()}
            className="flex items-center gap-2 px-5 py-2 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed text-black font-bold font-mono rounded-lg text-sm transition-all">
            {submitting
              ? <><RefreshCw size={14} className="animate-spin" /> Submitting...</>
              : <><Send size={14} /> Ingest & Analyze</>
            }
          </button>

          <div className="flex items-center gap-2 text-xs font-mono text-gray-600">
            <Mail size={12} className="text-cyan-400" />
            Email sent to klu2300030288@outlook.com if risk ≥ 60
          </div>
        </div>
      </div>

      {/* Email Config Notice */}
      <div className="bg-amber-500/5 border border-amber-500/20 rounded-lg p-4">
        <p className="text-amber-400 text-xs font-mono font-bold mb-2">⚙️ EMAIL SETUP REQUIRED — Add to your .env file:</p>
        <pre className="text-gray-400 text-xs font-mono leading-relaxed">
{`SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-gmail@gmail.com
SMTP_PASSWORD=xxxx-xxxx-xxxx-xxxx   # Gmail App Password
ALERT_EMAIL=klu2300030288@outlook.com`}
        </pre>
        <p className="text-gray-600 text-xs font-mono mt-2">
          Get Gmail App Password → myaccount.google.com → Security → 2-Step → App Passwords
        </p>
      </div>

      {/* Task Results */}
      {tasks.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-xs font-mono text-gray-500 uppercase">
              {tasks.length} Task(s) — <span className="text-cyan-400">{tasks.filter(t => t.status === 'done').length} done</span>
            </p>
            <button onClick={() => setTasks([])} className="text-xs font-mono text-gray-600 hover:text-gray-400">Clear</button>
          </div>
          {tasks.map((task, i) => <TaskCard key={task.task_id || i} task={task} />)}
        </div>
      )}

    </div>
  )
}
