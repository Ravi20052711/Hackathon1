import React, { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  FileText, Search, X, RefreshCw, ChevronDown, ChevronUp,
  Download, Monitor, Server, Lock, Activity
} from 'lucide-react'
import axios from 'axios'

const LEVEL_STYLES = {
  CRITICAL: { border: 'border-purple-500/30', bg: 'bg-purple-500/10', badge: 'bg-purple-500/20 text-purple-400 border border-purple-500/40' },
  ERROR:    { border: 'border-red-500/30',    bg: 'bg-red-500/10',    badge: 'bg-red-500/20 text-red-400 border border-red-500/40' },
  WARNING:  { border: 'border-amber-500/30',  bg: 'bg-amber-500/10',  badge: 'bg-amber-500/20 text-amber-400 border border-amber-500/40' },
  INFO:     { border: 'border-cyan-500/30',   bg: 'bg-cyan-500/10',   badge: 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40' },
  DEBUG:    { border: 'border-gray-600/30',   bg: 'bg-gray-800/30',   badge: 'bg-gray-700 text-gray-400 border border-gray-600' },
}

const SOURCES = [
  { id: 'submitted',   label: 'My Submitted Logs', icon: FileText, desc: 'Logs you analyzed in Alert Center', endpoint: null },
  { id: 'system',      label: 'Windows System',    icon: Monitor,  desc: 'Hardware, drivers, OS events',    endpoint: '/api/systemlogs/windows?log_name=System&limit=80' },
  { id: 'application', label: 'Windows App',       icon: Server,   desc: 'App crashes, software errors',    endpoint: '/api/systemlogs/application?limit=80' },
  { id: 'security',    label: 'Windows Security',  icon: Lock,     desc: 'Logins, access control, audits',  endpoint: '/api/systemlogs/security?limit=80' },
]

function hl(text, q) {
  if (!q || !text) return String(text || '')
  const parts = String(text).split(new RegExp(`(${q})`, 'gi'))
  return parts.map((p, i) =>
    p.toLowerCase() === q.toLowerCase()
      ? <mark key={i} className="bg-yellow-400/20 text-yellow-300 rounded px-0.5">{p}</mark>
      : p
  )
}

function LogCard({ log, query }) {
  const [open, setOpen] = useState(false)
  const level = log.level || 'INFO'
  const s = LEVEL_STYLES[level] || LEVEL_STYLES.INFO

  return (
    <motion.div
      initial={{ opacity: 0, y: -4 }}
      animate={{ opacity: 1, y: 0 }}
      className={`border rounded-lg overflow-hidden mb-1.5 ${log.isNew ? 'border-green-500/50 bg-green-500/8' : `${s.border} ${s.bg}`}`}
    >
      <div className="flex items-start gap-3 p-3 cursor-pointer" onClick={() => setOpen(!open)}>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${s.badge}`}>{level}</span>
            {log.isNew && <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-green-500/20 text-green-400 border border-green-500/40 animate-pulse">● NEW</span>}
            {log.event_id && <span className="text-gray-600 text-xs font-mono">EventID:{log.event_id}</span>}
            {log.timestamp && <span className="text-gray-600 text-xs font-mono">{log.timestamp}</span>}
            {log.source && <span className="text-gray-700 text-xs font-mono truncate max-w-32">{log.source}</span>}
          </div>
          <p className="text-gray-300 font-mono text-xs leading-relaxed line-clamp-2">
            {hl(log.message || log.raw || '', query)}
          </p>
        </div>
        <span className="text-gray-700 flex-shrink-0 mt-1">{open ? <ChevronUp size={12}/> : <ChevronDown size={12}/>}</span>
      </div>

      <AnimatePresence>
        {open && (
          <motion.div initial={{height:0,opacity:0}} animate={{height:'auto',opacity:1}} exit={{height:0,opacity:0}}
            className="border-t border-gray-800 p-3 space-y-3">
            <div>
              <p className="text-xs font-mono text-gray-500 uppercase mb-2">Full Log</p>
              <pre className="bg-black/30 rounded p-3 text-xs font-mono text-gray-300 whitespace-pre-wrap break-all border border-gray-800">
                {log.raw}
              </pre>
            </div>
            {log.mitre?.length > 0 && (
              <div>
                <p className="text-xs font-mono text-gray-500 uppercase mb-1">MITRE Techniques</p>
                <div className="flex flex-wrap gap-1">
                  {log.mitre.map((t,i) => <span key={i} className="px-2 py-0.5 bg-purple-500/10 border border-purple-500/30 rounded text-xs font-mono text-purple-400">{t}</span>)}
                </div>
              </div>
            )}
            {log.iocs?.length > 0 && (
              <div>
                <p className="text-xs font-mono text-gray-500 uppercase mb-1">Extracted IOCs</p>
                <div className="flex flex-wrap gap-1">
                  {log.iocs.slice(0,8).map((ioc,i) => <span key={i} className="px-2 py-0.5 bg-cyan-500/10 border border-cyan-500/30 rounded text-xs font-mono text-cyan-400">{String(ioc).slice(0,40)}</span>)}
                </div>
              </div>
            )}
            {log.risk_score > 0 && (
              <p className="text-xs font-mono">
                Risk Score: <span className={`font-bold ${log.risk_score>=80?'text-red-400':log.risk_score>=50?'text-amber-400':'text-green-400'}`}>{log.risk_score}/100</span>
              </p>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

export default function MyLogsPage() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [levelFilter, setLevelFilter] = useState('ALL')
  const [activeSource, setActiveSource] = useState('submitted')
  const [wsConnected, setWsConnected] = useState(false)
  const [newCount, setNewCount] = useState(0)
  const [error, setError] = useState('')
  const wsRef = useRef(null)
  const token = localStorage.getItem('access_token')
  const headers = { Authorization: `Bearer ${token}` }

  function severityToLevel(s) {
    return { critical:'CRITICAL', high:'ERROR', medium:'WARNING', low:'INFO' }[s] || 'INFO'
  }

  function alertToLog(a) {
    return {
      id: a.id,
      raw: a.raw_log,
      message: (a.raw_log||'').slice(0,200),
      level: severityToLevel(a.severity),
      timestamp: a.created_at ? new Date(a.created_at).toLocaleString() : '',
      source: a.source_system,
      risk_score: a.risk_score||0,
      mitre: a.mitre_techniques||[],
      iocs: a.extracted_iocs||[],
      isNew: false,
    }
  }

  const loadLogs = async (srcId = activeSource) => {
    setLoading(true)
    setError('')
    setLogs([])
    try {
      const src = SOURCES.find(s => s.id === srcId)
      if (srcId === 'submitted') {
        const res = await axios.get('/api/alerts/?limit=100', { headers })
        setLogs(res.data.map(alertToLog))
      } else {
        const res = await axios.get(src.endpoint, { headers })
        if (res.data.error && (!res.data.logs || res.data.logs.length === 0)) {
          setError(`Windows error: ${res.data.error}`)
        } else {
          setLogs(res.data.logs || [])
        }
      }
    } catch (err) {
      setError(
        srcId === 'submitted'
          ? 'Could not load alerts. Is the backend running?'
          : 'Could not read Windows logs. Run backend terminal as Administrator and restart uvicorn.'
      )
    } finally {
      setLoading(false)
    }
  }

  // WebSocket for live submitted alert updates
  const connectWS = useCallback(() => {
    try {
      const ws = new WebSocket('ws://127.0.0.1:8000/api/alerts/ws/live')
      wsRef.current = ws
      ws.onopen = () => setWsConnected(true)
      ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data)
          if (data.event === 'new_alert' && data.data?.raw_log) {
            const newLog = { ...alertToLog(data.data), isNew: true }
            setLogs(prev => {
              if (prev.find(l => l.id === newLog.id)) return prev
              setNewCount(c => c + 1)
              return [newLog, ...prev]
            })
            setTimeout(() => setLogs(prev => prev.map(l => l.id === newLog.id ? {...l, isNew:false} : l)), 4000)
          }
        } catch {}
      }
      ws.onclose = () => { setWsConnected(false); setTimeout(connectWS, 3000) }
      ws.onerror = () => ws.close()
    } catch {}
  }, [])

  useEffect(() => {
    loadLogs()
    connectWS()
    return () => { if (wsRef.current) wsRef.current.close() }
  }, [])

  const handleSource = (id) => {
    setActiveSource(id)
    setNewCount(0)
    setLevelFilter('ALL')
    setSearchQuery('')
    loadLogs(id)
  }

  const filtered = logs.filter(log => {
    const q = searchQuery.toLowerCase()
    const matchSearch = !q ||
      (log.raw||'').toLowerCase().includes(q) ||
      (log.message||'').toLowerCase().includes(q) ||
      (log.source||'').toLowerCase().includes(q) ||
      (log.event_id||'').includes(q) ||
      (log.mitre||[]).some(t => t.toLowerCase().includes(q)) ||
      (log.iocs||[]).some(i => String(i).toLowerCase().includes(q))
    const matchLevel = levelFilter === 'ALL' || log.level === levelFilter
    return matchSearch && matchLevel
  })

  const stats = {
    total: logs.length,
    critical: logs.filter(l=>l.level==='CRITICAL').length,
    error: logs.filter(l=>l.level==='ERROR').length,
    warning: logs.filter(l=>l.level==='WARNING').length,
    info: logs.filter(l=>l.level==='INFO').length,
  }

  const exportLogs = () => {
    const blob = new Blob([filtered.map(l=>`[${l.timestamp}] [${l.level}] ${l.raw}`).join('\n')], {type:'text/plain'})
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `logs_${activeSource}_${new Date().toISOString().slice(0,10)}.txt`
    a.click()
  }

  return (
    <div className="p-6 space-y-5 max-w-6xl mx-auto">

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white font-mono flex items-center gap-2">
            <Activity size={22} className="text-cyan-400"/> MY LOGS
          </h1>
          <p className="text-gray-500 text-xs font-mono mt-1">
            {SOURCES.find(s=>s.id===activeSource)?.desc}
          </p>
        </div>
        <div className="flex gap-2 items-center flex-wrap">
          <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-mono ${wsConnected ? 'bg-green-500/10 border-green-500/30 text-green-400' : 'bg-gray-800 border-gray-700 text-gray-500'}`}>
            <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-green-400 animate-pulse' : 'bg-gray-600'}`}></span>
            {wsConnected ? 'LIVE' : 'OFFLINE'}
          </div>
          {newCount > 0 && (
            <span className="px-3 py-2 rounded-lg border bg-cyan-500/10 border-cyan-500/30 text-cyan-400 text-xs font-mono">+{newCount} new</span>
          )}
          <button onClick={exportLogs} className="flex items-center gap-2 px-3 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-400 rounded-lg text-xs font-mono transition-all">
            <Download size={12}/> Export
          </button>
          <button onClick={() => loadLogs()} className="flex items-center gap-2 px-3 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-400 rounded-lg text-xs font-mono transition-all">
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''}/> Refresh
          </button>
        </div>
      </div>

      {/* Source Tabs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {SOURCES.map(src => {
          const Icon = src.icon
          const active = activeSource === src.id
          return (
            <button key={src.id} onClick={() => handleSource(src.id)}
              className={`p-3 rounded-lg border text-left transition-all ${active ? 'bg-cyan-500/10 border-cyan-500/40 text-cyan-400' : 'bg-gray-800/40 border-gray-700 text-gray-500 hover:border-gray-500 hover:text-gray-300'}`}>
              <div className="flex items-center gap-2 mb-1">
                <Icon size={13}/>
                <span className="text-xs font-mono font-bold">{src.label}</span>
              </div>
              <p className="text-xs font-mono opacity-60 leading-tight">{src.desc}</p>
            </button>
          )
        })}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-5 gap-3">
        {[
          {label:'Total',    value:stats.total,    color:'text-white'},
          {label:'Critical', value:stats.critical, color:'text-purple-400'},
          {label:'Errors',   value:stats.error,    color:'text-red-400'},
          {label:'Warnings', value:stats.warning,  color:'text-amber-400'},
          {label:'Info',     value:stats.info,     color:'text-cyan-400'},
        ].map(s => (
          <div key={s.label} className="glass-card p-3 text-center border border-gray-800">
            <div className={`text-2xl font-bold font-mono ${s.color}`}>{s.value}</div>
            <div className="text-gray-600 text-xs font-mono mt-1 uppercase">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Search + Level Filter */}
      <div className="flex gap-3 flex-wrap items-center">
        <div className="relative flex-1 min-w-64">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500"/>
          <input type="text" value={searchQuery} onChange={e=>setSearchQuery(e.target.value)}
            placeholder="Search keyword, IP, EventID, source, MITRE..."
            className="w-full bg-black/30 border border-gray-700 rounded-lg pl-9 pr-8 py-2.5 text-white font-mono text-xs focus:outline-none focus:border-cyan-400 placeholder-gray-600"/>
          {searchQuery && (
            <button onClick={()=>setSearchQuery('')} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white"><X size={12}/></button>
          )}
        </div>
        <div className="flex gap-2 flex-wrap">
          {['ALL','CRITICAL','ERROR','WARNING','INFO','DEBUG'].map(lv => (
            <button key={lv} onClick={()=>setLevelFilter(lv)}
              className={`px-3 py-2 rounded-lg text-xs font-mono font-bold uppercase border transition-all ${
                levelFilter===lv
                  ? lv==='CRITICAL' ? 'bg-purple-500/20 text-purple-400 border-purple-500/40'
                  : lv==='ERROR'    ? 'bg-red-500/20 text-red-400 border-red-500/40'
                  : lv==='WARNING'  ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                  : lv==='INFO'     ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40'
                  : 'bg-gray-700 text-gray-300 border-gray-600'
                  : 'text-gray-600 border-gray-800 hover:border-gray-600 hover:text-gray-400'
              }`}>{lv}</button>
          ))}
        </div>
      </div>

      {/* Count */}
      <p className="text-xs font-mono text-gray-600">
        Showing <span className="text-cyan-400 font-bold">{filtered.length}</span> of <span className="text-white">{logs.length}</span> logs
        {searchQuery && <span className="text-yellow-400"> — "{searchQuery}"</span>}
      </p>

      {/* Error */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-red-400 font-mono text-xs">
          ⚠️ {error}
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="text-center py-16 text-gray-600 font-mono">
          <RefreshCw size={24} className="animate-spin mx-auto mb-3"/>
          Reading {SOURCES.find(s=>s.id===activeSource)?.label}...
        </div>
      )}

      {/* Empty */}
      {!loading && !error && filtered.length === 0 && (
        <div className="text-center py-16 text-gray-600 font-mono">
          <FileText size={32} className="mx-auto mb-3 opacity-30"/>
          {logs.length === 0
            ? activeSource === 'submitted'
              ? 'No submitted logs yet — go to Alert Center and submit a log'
              : 'No logs loaded'
            : 'No logs match your search'
          }
        </div>
      )}

      {/* Logs */}
      {!loading && filtered.length > 0 && (
        <div>{filtered.map((log,i) => <LogCard key={log.id||i} log={log} query={searchQuery}/>)}</div>
      )}

    </div>
  )
}
