/**
 * =============================================================
 * PAGE - IOC Explorer
 * =============================================================
 * Browse, search, and add Indicators of Compromise.
 * Shows enriched data from VirusTotal, AbuseIPDB, and GeoIP.
 * Supports filtering by IOC type and minimum risk score.
 * =============================================================
 */

import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Plus, Search, Filter, Shield, Globe, Hash, Link, Mail, RefreshCw, Trash2, Zap } from 'lucide-react'
import { iocApi } from '../utils/api'
import toast from 'react-hot-toast'

// Risk score → color mapping for visual indicators
const getRiskColor = (score) => {
  if (score >= 90) return { text: 'text-red-400', bg: 'bg-red-400/10', border: 'border-red-400/30' }
  if (score >= 70) return { text: 'text-amber-400', bg: 'bg-amber-400/10', border: 'border-amber-400/30' }
  if (score >= 40) return { text: 'text-blue-400', bg: 'bg-blue-400/10', border: 'border-blue-400/30' }
  return { text: 'text-green-400', bg: 'bg-green-400/10', border: 'border-green-400/30' }
}

const IOC_TYPE_ICONS = {
  ip: Globe, domain: Shield, hash: Hash, url: Link, email: Mail
}

export default function IOCExplorerPage() {
  const [iocs, setIocs] = useState([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [showAddForm, setShowAddForm] = useState(false)
  const [newIoc, setNewIoc] = useState({ value: '', ioc_type: 'ip', source: 'manual', tags: [] })
  const [adding, setAdding] = useState(false)

  useEffect(() => { fetchIOCs() }, [typeFilter])

  const fetchIOCs = async () => {
    setLoading(true)
    try {
      const data = await iocApi.list({ ioc_type: typeFilter || undefined, limit: 100 })
      setIocs(data)
    } catch (e) {
      toast.error('Failed to load IOCs')
    } finally {
      setLoading(false)
    }
  }

  const handleAddIOC = async (e) => {
    e.preventDefault()
    setAdding(true)
    try {
      const result = await iocApi.create(newIoc)
      setIocs(prev => [result, ...prev])
      setShowAddForm(false)
      setNewIoc({ value: '', ioc_type: 'ip', source: 'manual', tags: [] })
      toast.success(`IOC added! Risk score: ${result.risk_score}`)
    } catch (e) {
      toast.error('Failed to add IOC')
    } finally {
      setAdding(false)
    }
  }

  const handleDelete = async (id) => {
    await iocApi.delete(id)
    setIocs(prev => prev.filter(i => i.id !== id))
    toast.success('IOC removed')
  }

  // Client-side search filter
  const filtered = iocs.filter(ioc =>
    ioc.value?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    ioc.tags?.some(t => t.toLowerCase().includes(searchTerm.toLowerCase()))
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white font-mono">
            IOC <span className="text-cyan-400">Explorer</span>
          </h1>
          <p className="text-gray-500 text-sm font-mono mt-1">{iocs.length} indicators loaded</p>
        </div>
        <motion.button
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          onClick={() => setShowAddForm(!showAddForm)}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-black font-mono text-sm font-bold rounded-lg transition-all"
        >
          <Plus size={16} />
          Add IOC
        </motion.button>
      </div>

      {/* Add IOC Form (collapsible) */}
      {showAddForm && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          exit={{ opacity: 0, height: 0 }}
          className="glass-card p-5 border border-cyan-400/20"
        >
          <h3 className="text-white font-mono text-sm font-semibold mb-4 flex items-center gap-2">
            <Zap size={14} className="text-cyan-400" />
            Submit IOC for Enrichment
          </h3>
          <form onSubmit={handleAddIOC} className="flex gap-3 flex-wrap">
            <input
              type="text"
              value={newIoc.value}
              onChange={e => setNewIoc({...newIoc, value: e.target.value})}
              placeholder="192.168.1.1 / domain.com / file_hash / url"
              className="flex-1 min-w-48 bg-black/40 border border-gray-700 rounded-lg px-4 py-2.5 text-white font-mono text-sm focus:outline-none focus:border-cyan-400"
              required
            />
            <select
              value={newIoc.ioc_type}
              onChange={e => setNewIoc({...newIoc, ioc_type: e.target.value})}
              className="bg-black/40 border border-gray-700 rounded-lg px-3 py-2.5 text-white font-mono text-sm focus:outline-none focus:border-cyan-400"
            >
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="hash">File Hash</option>
              <option value="url">URL</option>
              <option value="email">Email</option>
            </select>
            <select
              value={newIoc.source}
              onChange={e => setNewIoc({...newIoc, source: e.target.value})}
              className="bg-black/40 border border-gray-700 rounded-lg px-3 py-2.5 text-white font-mono text-sm focus:outline-none focus:border-cyan-400"
            >
              <option value="manual">Manual</option>
              <option value="AlienVault OTX">AlienVault OTX</option>
              <option value="VirusTotal">VirusTotal</option>
              <option value="AbuseIPDB">AbuseIPDB</option>
              <option value="URLhaus">URLhaus</option>
            </select>
            <motion.button
              type="submit"
              disabled={adding}
              whileTap={{ scale: 0.98 }}
              className="px-5 py-2.5 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-black font-mono text-sm font-bold rounded-lg flex items-center gap-2 transition-all"
            >
              {adding ? <RefreshCw size={14} className="animate-spin" /> : <Plus size={14} />}
              {adding ? 'Enriching...' : 'Add & Enrich'}
            </motion.button>
          </form>
        </motion.div>
      )}

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <div className="relative flex-1 min-w-48">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            placeholder="Search IOCs..."
            className="w-full bg-black/30 border border-gray-700 rounded-lg pl-9 pr-4 py-2.5 text-white font-mono text-sm focus:outline-none focus:border-cyan-400 transition-all"
          />
        </div>

        {/* Type filter buttons */}
        <div className="flex gap-2">
          {['', 'ip', 'domain', 'hash', 'url'].map(type => (
            <button
              key={type}
              onClick={() => setTypeFilter(type)}
              className={`px-3 py-2 rounded-lg font-mono text-xs transition-all ${
                typeFilter === type
                  ? 'bg-cyan-400/20 text-cyan-400 border border-cyan-400/30'
                  : 'text-gray-500 border border-gray-700 hover:border-gray-600'
              }`}
            >
              {type === '' ? 'All' : type.toUpperCase()}
            </button>
          ))}
        </div>

        <button onClick={fetchIOCs} className="p-2.5 text-gray-500 hover:text-cyan-400 border border-gray-700 hover:border-cyan-400/50 rounded-lg transition-all">
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
        </button>
      </div>

      {/* IOC Table */}
      <div className="glass-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-800">
                {['IOC Value', 'Type', 'Risk Score', 'VT Detections', 'Country', 'Source', 'Tags', 'Actions'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-mono text-gray-500 uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={8} className="text-center py-12 text-gray-600 font-mono text-sm">Loading IOCs...</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={8} className="text-center py-12 text-gray-600 font-mono text-sm">No IOCs found</td></tr>
              ) : (
                filtered.map((ioc, i) => {
                  const risk = getRiskColor(ioc.risk_score || 0)
                  const TypeIcon = IOC_TYPE_ICONS[ioc.ioc_type] || Shield
                  return (
                    <motion.tr
                      key={ioc.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: i * 0.02 }}
                      className="border-b border-gray-800/50 hover:bg-white/2 transition-colors"
                    >
                      <td className="px-4 py-3">
                        <code className="text-cyan-400 font-mono text-sm">{ioc.value}</code>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          <TypeIcon size={14} className="text-gray-400" />
                          <span className="text-gray-300 font-mono text-xs uppercase">{ioc.ioc_type}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className={`inline-flex items-center gap-1 px-2 py-1 rounded ${risk.bg} border ${risk.border}`}>
                          <div className={`w-1.5 h-1.5 rounded-full ${risk.text.replace('text', 'bg')}`} />
                          <span className={`font-mono text-xs font-bold ${risk.text}`}>{ioc.risk_score || 0}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`font-mono text-sm ${ioc.vt_detections > 0 ? 'text-red-400' : 'text-green-400'}`}>
                          {ioc.vt_detections ?? '—'}/{ioc.vt_total ?? 70}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-gray-400 font-mono text-xs">{ioc.country || '—'}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-gray-500 font-mono text-xs">{ioc.source}</span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {(ioc.tags || []).slice(0, 2).map(tag => (
                            <span key={tag} className="text-xs px-1.5 py-0.5 bg-purple-400/10 text-purple-400 rounded font-mono">{tag}</span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <button onClick={() => handleDelete(ioc.id)} className="text-gray-600 hover:text-red-400 transition-colors">
                          <Trash2 size={14} />
                        </button>
                      </td>
                    </motion.tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
