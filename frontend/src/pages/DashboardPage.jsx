/**
 * PAGE - Dashboard with real threat feed refresh button
 */

import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { RefreshCw, Shield, AlertTriangle, Activity, TrendingUp, Wifi, WifiOff } from 'lucide-react'
import axios from 'axios'
import toast from 'react-hot-toast'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts'

const COLORS = ['#06b6d4', '#f59e0b', '#ef4444', '#10b981', '#8b5cf6']

export default function DashboardPage() {
  const [stats, setStats] = useState({ total_iocs: 0, high_risk: 0, critical: 0, avg_risk_score: 0, by_type: {} })
  const [feed, setFeed] = useState([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [wsConnected, setWsConnected] = useState(false)
  const [fetchStatus, setFetchStatus] = useState(null)

  const token = localStorage.getItem('access_token')
  const headers = { Authorization: `Bearer ${token}` }

  const loadData = async () => {
    try {
      const [statsRes, feedRes, statusRes] = await Promise.all([
        axios.get('/api/ioc/stats', { headers }),
        axios.get('/api/feed/?limit=20', { headers }),
        axios.get('/api/feed/refresh/status', { headers }),
      ])
      setStats(statsRes.data)
      setFeed(feedRes.data)
      setFetchStatus(statusRes.data)
    } catch (err) {
      console.error('Load error:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()

    // WebSocket live feed
    const ws = new WebSocket('ws://127.0.0.1:8000/api/alerts/ws/live')
    ws.onopen = () => setWsConnected(true)
    ws.onclose = () => setWsConnected(false)
    ws.onerror = () => setWsConnected(false)
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data)
        if (msg.data) {
          setFeed(prev => [msg.data, ...prev.slice(0, 19)])
        }
      } catch {}
    }
    return () => ws.close()
  }, [])

  const fetchRealThreats = async (source = 'all') => {
    setRefreshing(true)
    try {
      const res = await axios.post(`/api/feed/refresh?source=${source}&limit=50`, {}, { headers })
      toast.success(`Fetching real threats from ${source}... Check IOC Explorer in 10 seconds!`)

      // Poll for new data after 8 seconds
      setTimeout(async () => {
        await loadData()
        toast.success('✅ Real threat data loaded!')
        setRefreshing(false)
      }, 8000)
    } catch (err) {
      toast.error('Fetch failed — check internet connection')
      setRefreshing(false)
    }
  }

  const pieData = Object.entries(stats.by_type || {}).map(([name, value]) => ({ name, value }))

  const metricCards = [
    { label: 'Total IOCs', value: stats.total_iocs, icon: Shield, color: 'cyan', sub: 'tracked indicators' },
    { label: 'High Risk', value: stats.high_risk, icon: AlertTriangle, color: 'amber', sub: 'score ≥ 70' },
    { label: 'Critical', value: stats.critical, icon: TrendingUp, color: 'red', sub: 'score ≥ 90' },
    { label: 'Avg Risk Score', value: stats.avg_risk_score, icon: Activity, color: 'purple', sub: 'out of 100' },
  ]

  const severityColor = (s) => ({
    critical: 'text-red-400 bg-red-400/10 border-red-400/30',
    high: 'text-amber-400 bg-amber-400/10 border-amber-400/30',
    medium: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
    low: 'text-green-400 bg-green-400/10 border-green-400/30',
  }[s] || 'text-gray-400 bg-gray-400/10 border-gray-400/30')

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white font-mono">THREAT DASHBOARD</h1>
          <p className="text-gray-500 text-sm font-mono mt-1">
            {fetchStatus?.total_iocs || 0} indicators tracked
            {fetchStatus?.last_fetched?.all && (
              <span className="ml-2 text-cyan-500">· last fetched {new Date(fetchStatus.last_fetched.all).toLocaleTimeString()}</span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Live indicator */}
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs font-mono ${wsConnected ? 'border-green-500/30 text-green-400' : 'border-gray-700 text-gray-500'}`}>
            {wsConnected ? <Wifi size={12} /> : <WifiOff size={12} />}
            {wsConnected ? 'LIVE' : 'OFFLINE'}
          </div>

          {/* Fetch real data dropdown */}
          <div className="flex gap-2">
            <button
              onClick={() => fetchRealThreats('feodo')}
              disabled={refreshing}
              className="px-3 py-2 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 rounded-lg text-xs font-mono flex items-center gap-1 transition-all disabled:opacity-50"
            >
              🤖 C2 IPs
            </button>
            <button
              onClick={() => fetchRealThreats('urlhaus')}
              disabled={refreshing}
              className="px-3 py-2 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-amber-400 rounded-lg text-xs font-mono flex items-center gap-1 transition-all disabled:opacity-50"
            >
              🔗 Malware URLs
            </button>
            <button
              onClick={() => fetchRealThreats('malwarebazaar')}
              disabled={refreshing}
              className="px-3 py-2 bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/30 text-purple-400 rounded-lg text-xs font-mono flex items-center gap-1 transition-all disabled:opacity-50"
            >
              💀 Hashes
            </button>
            <button
              onClick={() => fetchRealThreats('all')}
              disabled={refreshing}
              className="px-4 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 rounded-lg text-xs font-mono flex items-center gap-2 transition-all disabled:opacity-50"
            >
              <RefreshCw size={12} className={refreshing ? 'animate-spin' : ''} />
              {refreshing ? 'FETCHING...' : 'FETCH ALL'}
            </button>
          </div>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {metricCards.map((card, i) => (
          <motion.div
            key={card.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            className="glass-card p-5"
          >
            <p className="text-gray-500 text-xs font-mono uppercase tracking-wider">{card.label}</p>
            <p className={`text-3xl font-bold font-mono mt-2 text-${card.color}-400`}>
              {loading ? '...' : card.value}
            </p>
            <p className="text-gray-600 text-xs font-mono mt-1">{card.sub}</p>
          </motion.div>
        ))}
      </div>

      {/* Sources Status */}
      {fetchStatus && (
        <div className="glass-card p-4">
          <p className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-3">Data Sources</p>
          <div className="flex flex-wrap gap-2">
            {Object.entries(fetchStatus.by_source || {}).map(([source, count]) => (
              <span key={source} className="px-3 py-1 bg-cyan-500/10 border border-cyan-500/20 rounded-full text-xs font-mono text-cyan-400">
                {source}: {count} IOCs
              </span>
            ))}
            {Object.keys(fetchStatus.by_source || {}).length === 0 && (
              <span className="text-gray-600 text-xs font-mono">
                No real data yet — click "FETCH ALL" to load real threat intel ☝️
              </span>
            )}
          </div>
        </div>
      )}

      {/* Chart + Live Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Pie Chart */}
        <div className="glass-card p-5">
          <p className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-4">IOC Distribution</p>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" outerRadius={80} dataKey="value" label={({name, percent}) => `${name} ${(percent*100).toFixed(0)}%`}>
                  {pieData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#0d1117', border: '1px solid #1f2937', borderRadius: 8, fontFamily: 'monospace', fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-48 text-gray-600 font-mono text-sm">
              Fetch real data to see distribution
            </div>
          )}
        </div>

        {/* Live Feed */}
        <div className="glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <p className="text-xs font-mono text-gray-500 uppercase tracking-wider">Live Threat Feed</p>
            <span className={`text-xs font-mono px-2 py-0.5 rounded-full border ${wsConnected ? 'text-green-400 border-green-500/30 bg-green-500/10' : 'text-gray-500 border-gray-700'}`}>
              {wsConnected ? '● LIVE' : '○ OFFLINE'}
            </span>
          </div>
          <div className="space-y-2 max-h-56 overflow-y-auto">
            {feed.length === 0 && (
              <p className="text-gray-600 text-xs font-mono text-center py-8">
                Click "FETCH ALL" to load real threats
              </p>
            )}
            {feed.map((item, i) => (
              <motion.div
                key={item.id || i}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                className={`p-2 rounded-lg border text-xs font-mono ${severityColor(item.severity)}`}
              >
                <div className="flex items-center justify-between">
                  <span className="truncate flex-1">{item.title || item.ioc_value}</span>
                  <span className="ml-2 shrink-0 uppercase text-[10px] opacity-70">{item.severity}</span>
                </div>
                <div className="opacity-60 mt-0.5 truncate">{item.source} · {item.ioc_value?.slice(0, 50)}</div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
