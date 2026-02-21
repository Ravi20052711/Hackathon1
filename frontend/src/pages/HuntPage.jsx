/**
 * =============================================================
 * PAGE - Hunt Center
 * =============================================================
 * Auto-generated threat hunting queries from IOC intelligence.
 * Browse hunt templates, generate new queries, and copy to SIEM.
 * =============================================================
 */

import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Search, Copy, ChevronDown, ChevronUp, Zap, Check } from 'lucide-react'
import { huntApi } from '../utils/api'
import toast from 'react-hot-toast'

function HuntCard({ hunt }) {
  const [expanded, setExpanded] = useState(false)
  const [copiedKey, setCopiedKey] = useState(null)

  const copyQuery = (key, text) => {
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    toast.success('Query copied!')
    setTimeout(() => setCopiedKey(null), 2000)
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card border border-gray-800 hover:border-cyan-400/20 transition-all"
    >
      <div
        className="flex items-start gap-3 p-4 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="w-10 h-10 bg-cyan-400/10 rounded-lg flex items-center justify-center flex-shrink-0">
          <Search size={18} className="text-cyan-400" />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-white font-mono text-sm font-semibold">{hunt.name}</p>
          <p className="text-gray-500 text-xs font-mono mt-0.5">{hunt.hypothesis}</p>
          <div className="flex flex-wrap gap-2 mt-2">
            {hunt.data_sources?.map(ds => (
              <span key={ds} className="text-xs px-1.5 py-0.5 bg-gray-800 text-gray-400 rounded font-mono">{ds}</span>
            ))}
            {hunt.triggered_by_ioc && (
              <span className="text-xs px-1.5 py-0.5 bg-cyan-400/10 text-cyan-400 rounded font-mono">
                IOC: {hunt.triggered_by_ioc}
              </span>
            )}
          </div>
        </div>
        {expanded ? <ChevronUp size={16} className="text-gray-500 flex-shrink-0 mt-1" /> : <ChevronDown size={16} className="text-gray-500 flex-shrink-0 mt-1" />}
      </div>

      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-gray-800 pt-4">
          {[
            { key: 'splunk', label: 'Splunk SPL', color: '#f59e0b' },
            { key: 'elastic', label: 'Elastic KQL', color: '#10b981' },
            { key: 'sigma', label: 'Sigma Rule', color: '#8b5cf6' },
          ].map(({ key, label, color }) => hunt[`query_${key}`] && (
            <div key={key} className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold uppercase" style={{ color }}>{label}</span>
                <button
                  onClick={() => copyQuery(key, hunt[`query_${key}`])}
                  className="flex items-center gap-1 text-xs text-gray-500 hover:text-white transition-colors"
                >
                  {copiedKey === key ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
                  {copiedKey === key ? 'Copied' : 'Copy'}
                </button>
              </div>
              <pre className="text-gray-300 text-xs font-mono bg-black/40 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap border border-gray-800">
                {hunt[`query_${key}`]}
              </pre>
            </div>
          ))}
        </div>
      )}
    </motion.div>
  )
}

export default function HuntPage() {
  const [hunts, setHunts] = useState([])
  const [templates, setTemplates] = useState([])
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [genForm, setGenForm] = useState({ ioc: '', type: 'ip' })

  useEffect(() => {
    Promise.all([huntApi.list(), huntApi.templates()])
      .then(([h, t]) => { setHunts(h); setTemplates(t) })
      .finally(() => setLoading(false))
  }, [])

  const handleGenerate = async (e) => {
    e.preventDefault()
    setGenerating(true)
    try {
      const result = await huntApi.generate(genForm.ioc, genForm.type, 80)
      setHunts(prev => [result, ...prev])
      toast.success('Hunt queries generated!')
    } catch {
      toast.error('Generation failed')
    } finally {
      setGenerating(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white font-mono">Hunt <span className="text-green-400">Center</span></h1>
        <p className="text-gray-500 text-sm font-mono mt-1">Auto-generated threat hunting queries</p>
      </div>

      {/* Generate query form */}
      <div className="glass-card p-5 border border-green-500/20">
        <h3 className="text-white font-mono text-sm font-semibold mb-4 flex items-center gap-2">
          <Zap size={14} className="text-green-400" />
          Generate Hunt Query from IOC
        </h3>
        <form onSubmit={handleGenerate} className="flex gap-3 flex-wrap">
          <input
            type="text"
            value={genForm.ioc}
            onChange={e => setGenForm({...genForm, ioc: e.target.value})}
            placeholder="IOC value (IP, domain, hash...)"
            className="flex-1 min-w-48 bg-black/40 border border-gray-700 rounded-lg px-4 py-2.5 text-white font-mono text-sm focus:outline-none focus:border-green-400"
            required
          />
          <select
            value={genForm.type}
            onChange={e => setGenForm({...genForm, type: e.target.value})}
            className="bg-black/40 border border-gray-700 rounded-lg px-3 py-2.5 text-white font-mono text-sm focus:outline-none focus:border-green-400"
          >
            <option value="ip">IP</option>
            <option value="domain">Domain</option>
            <option value="hash">Hash</option>
            <option value="url">URL</option>
          </select>
          <button
            type="submit"
            disabled={generating}
            className="px-4 py-2.5 bg-green-500/20 hover:bg-green-500/30 border border-green-500/30 text-green-400 font-mono text-sm font-bold rounded-lg flex items-center gap-2 transition-all disabled:opacity-50"
          >
            {generating ? '⟳ Generating...' : <><Search size={14} /> Generate</>}
          </button>
        </form>
      </div>

      {/* Hunt templates */}
      <div>
        <p className="text-gray-400 font-mono text-xs uppercase tracking-wider mb-3">Hunt Templates</p>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          {templates.map(t => (
            <div key={t.id} className="glass-card p-4 hover:border-cyan-400/30 transition-all cursor-pointer">
              <div className="text-xs font-mono text-cyan-400 mb-1">{t.technique}</div>
              <p className="text-white text-sm font-semibold">{t.name}</p>
              <p className="text-gray-500 text-xs mt-1">{t.description}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Active hunts */}
      <div>
        <p className="text-gray-400 font-mono text-xs uppercase tracking-wider mb-3">Active Hunt Queries ({hunts.length})</p>
        <div className="space-y-3">
          {loading ? (
            <div className="text-center py-8 text-gray-600 font-mono">Loading hunt queries...</div>
          ) : hunts.map(hunt => (
            <HuntCard key={hunt.id} hunt={hunt} />
          ))}
        </div>
      </div>
    </div>
  )
}
