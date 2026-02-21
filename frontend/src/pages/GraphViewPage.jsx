import React, { useEffect, useRef, useState } from 'react'
import { motion } from 'framer-motion'
import { ZoomIn, ZoomOut, Maximize, RefreshCw, Info } from 'lucide-react'
import axios from 'axios'
import toast from 'react-hot-toast'

// Node color by group
const NODE_COLORS = {
  threat_actor: '#ef4444',
  campaign: '#f59e0b',
  ioc: '#06b6d4',
  ip: '#06b6d4',
  domain: '#8b5cf6',
  hash: '#f59e0b',
  url: '#ec4899',
  source: '#10b981',
  category: '#f97316',
  technique: '#6366f1',
  infrastructure: '#64748b',
}

export default function GraphViewPage() {
  const cyRef = useRef(null)
  const containerRef = useRef(null)
  const [stats, setStats] = useState(null)
  const [selected, setSelected] = useState(null)
  const [loading, setLoading] = useState(true)
  const [nodeCount, setNodeCount] = useState(0)
  const [edgeCount, setEdgeCount] = useState(0)
  const [isRealData, setIsRealData] = useState(false)

  const token = localStorage.getItem('access_token')
  const headers = { Authorization: `Bearer ${token}` }

  const loadGraph = async () => {
    setLoading(true)
    try {
      const [graphRes, statsRes] = await Promise.all([
        axios.get('/api/graph/', { headers }),
        axios.get('/api/graph/stats', { headers }),
      ])

      setStats(statsRes.data)
      setNodeCount(graphRes.data.node_count || 0)
      setEdgeCount(graphRes.data.edge_count || 0)
      setIsRealData(graphRes.data.is_real_data || false)

      await buildCytoscape(graphRes.data.elements || [])
    } catch (err) {
      toast.error('Failed to load graph')
    } finally {
      setLoading(false)
    }
  }

  const buildCytoscape = async (elements) => {
    // Dynamically import cytoscape
    const cytoscape = (await import('cytoscape')).default

    if (cyRef.current) {
      cyRef.current.destroy()
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': (ele) => NODE_COLORS[ele.data('type')] || NODE_COLORS[ele.data('group')] || '#64748b',
            'label': 'data(label)',
            'color': '#e2e8f0',
            'font-size': '9px',
            'font-family': 'JetBrains Mono, monospace',
            'text-valign': 'bottom',
            'text-margin-y': '4px',
            'text-wrap': 'wrap',
            'text-max-width': '80px',
            'width': (ele) => {
              const score = ele.data('risk_score') || 0
              const group = ele.data('group')
              if (group === 'source') return 40
              if (group === 'category') return 35
              if (group === 'technique') return 30
              return Math.max(20, score / 4)
            },
            'height': (ele) => {
              const score = ele.data('risk_score') || 0
              const group = ele.data('group')
              if (group === 'source') return 40
              if (group === 'category') return 35
              if (group === 'technique') return 30
              return Math.max(20, score / 4)
            },
            'border-width': 2,
            'border-color': (ele) => NODE_COLORS[ele.data('type')] || '#374151',
            'border-opacity': 0.6,
          }
        },
        {
          selector: 'node[group="source"]',
          style: {
            'shape': 'hexagon',
            'background-color': '#10b981',
            'font-size': '10px',
            'font-weight': 'bold',
          }
        },
        {
          selector: 'node[group="category"]',
          style: {
            'shape': 'diamond',
            'background-color': '#f97316',
          }
        },
        {
          selector: 'node[group="technique"]',
          style: {
            'shape': 'roundrectangle',
            'background-color': '#6366f1',
          }
        },
        {
          selector: 'node[group="actor"]',
          style: {
            'shape': 'star',
            'background-color': '#ef4444',
            'width': 45,
            'height': 45,
          }
        },
        {
          selector: 'edge',
          style: {
            'width': 1,
            'line-color': '#1f2937',
            'target-arrow-color': '#374151',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'opacity': 0.6,
          }
        },
        {
          selector: 'node:selected',
          style: {
            'border-width': 3,
            'border-color': '#06b6d4',
            'border-opacity': 1,
          }
        },
        {
          selector: 'node:hover',
          style: {
            'border-color': '#06b6d4',
            'border-width': 2,
          }
        },
      ],
      layout: {
        name: 'cose',
        animate: true,
        animationDuration: 800,
        nodeRepulsion: 6000,
        idealEdgeLength: 80,
        gravity: 0.3,
        randomize: false,
        fit: true,
        padding: 30,
      }
    })

    // Click handler
    cy.on('tap', 'node', (evt) => {
      const node = evt.target
      setSelected({
        id: node.id(),
        label: node.data('label'),
        type: node.data('type'),
        group: node.data('group'),
        risk_score: node.data('risk_score'),
        source: node.data('source'),
        country: node.data('country'),
        full_value: node.data('full_value'),
        connections: node.degree(),
      })
    })

    cy.on('tap', (evt) => {
      if (evt.target === cy) setSelected(null)
    })

    cyRef.current = cy
  }

  useEffect(() => {
    loadGraph()
    return () => { if (cyRef.current) cyRef.current.destroy() }
  }, [])

  const riskColor = (score) => {
    if (score >= 90) return 'text-red-400'
    if (score >= 70) return 'text-amber-400'
    if (score >= 40) return 'text-blue-400'
    return 'text-green-400'
  }

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white font-mono">THREAT GRAPH</h1>
          <p className="text-gray-500 text-xs font-mono mt-1">
            {nodeCount} nodes · {edgeCount} connections
            {isRealData
              ? <span className="text-green-400 ml-2">● Live data from your database</span>
              : <span className="text-amber-400 ml-2">● Demo data — fetch real IOCs first</span>
            }
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={loadGraph}
            className="px-3 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 rounded-lg text-xs font-mono flex items-center gap-1 transition-all">
            <RefreshCw size={12} /> Rebuild Graph
          </button>
        </div>
      </div>

      {/* Legend */}
      <div className="glass-card p-3 flex flex-wrap gap-4">
        {[
          { color: '#10b981', label: 'Source Hub', shape: '⬡' },
          { color: '#06b6d4', label: 'IP Address', shape: '●' },
          { color: '#8b5cf6', label: 'Domain', shape: '●' },
          { color: '#f59e0b', label: 'Hash', shape: '●' },
          { color: '#ec4899', label: 'URL', shape: '●' },
          { color: '#f97316', label: 'Category', shape: '◆' },
          { color: '#6366f1', label: 'MITRE Technique', shape: '▬' },
          { color: '#ef4444', label: 'Threat Actor', shape: '★' },
        ].map(item => (
          <div key={item.label} className="flex items-center gap-1.5">
            <span style={{ color: item.color }} className="text-lg leading-none">{item.shape}</span>
            <span className="text-gray-400 text-xs font-mono">{item.label}</span>
          </div>
        ))}
      </div>

      <div className="flex gap-4">
        {/* Graph Canvas */}
        <div className="flex-1 glass-card relative overflow-hidden" style={{ height: '560px' }}>
          {loading && (
            <div className="absolute inset-0 flex items-center justify-center bg-black/50 z-10">
              <div className="text-center">
                <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
                <p className="text-cyan-400 font-mono text-sm">Building graph...</p>
              </div>
            </div>
          )}
          <div ref={containerRef} className="w-full h-full" />

          {/* Zoom Controls */}
          <div className="absolute top-3 right-3 flex flex-col gap-1">
            {[
              { icon: ZoomIn, action: () => cyRef.current?.zoom(cyRef.current.zoom() * 1.3) },
              { icon: ZoomOut, action: () => cyRef.current?.zoom(cyRef.current.zoom() * 0.7) },
              { icon: Maximize, action: () => cyRef.current?.fit(undefined, 30) },
            ].map(({ icon: Icon, action }, i) => (
              <button key={i} onClick={action}
                className="w-7 h-7 bg-gray-900/80 hover:bg-gray-800 border border-gray-700 rounded flex items-center justify-center text-gray-400 hover:text-white transition-all">
                <Icon size={12} />
              </button>
            ))}
          </div>

          {/* Hint */}
          {!loading && (
            <div className="absolute bottom-3 left-3 text-gray-600 text-xs font-mono">
              Click any node for details · Scroll to zoom · Drag to pan
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="w-64 space-y-3">
          {/* Selected Node */}
          {selected ? (
            <motion.div initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }}
              className="glass-card p-4 border border-cyan-500/20">
              <p className="text-xs font-mono text-gray-500 uppercase mb-3">Selected Node</p>
              <div className="space-y-2">
                <div>
                  <p className="text-gray-500 text-xs font-mono">Label</p>
                  <p className="text-white font-mono text-sm break-all">{selected.label}</p>
                </div>
                <div>
                  <p className="text-gray-500 text-xs font-mono">Type</p>
                  <span className="px-2 py-0.5 bg-gray-800 rounded text-xs font-mono text-cyan-400">
                    {selected.type}
                  </span>
                </div>
                {selected.risk_score > 0 && (
                  <div>
                    <p className="text-gray-500 text-xs font-mono">Risk Score</p>
                    <p className={`font-mono font-bold text-lg ${riskColor(selected.risk_score)}`}>
                      {selected.risk_score}/100
                    </p>
                  </div>
                )}
                {selected.source && (
                  <div>
                    <p className="text-gray-500 text-xs font-mono">Source</p>
                    <p className="text-gray-300 font-mono text-xs">{selected.source}</p>
                  </div>
                )}
                {selected.country && (
                  <div>
                    <p className="text-gray-500 text-xs font-mono">Country</p>
                    <p className="text-gray-300 font-mono text-xs">{selected.country}</p>
                  </div>
                )}
                <div>
                  <p className="text-gray-500 text-xs font-mono">Connections</p>
                  <p className="text-gray-300 font-mono text-xs">{selected.connections} edges</p>
                </div>
                {selected.full_value && selected.full_value !== selected.label && (
                  <div>
                    <p className="text-gray-500 text-xs font-mono">Full Value</p>
                    <p className="text-gray-400 font-mono text-xs break-all">{selected.full_value}</p>
                  </div>
                )}
              </div>
            </motion.div>
          ) : (
            <div className="glass-card p-4 border border-gray-800">
              <div className="flex items-center gap-2 text-gray-600 mb-2">
                <Info size={14} />
                <p className="text-xs font-mono uppercase">No Node Selected</p>
              </div>
              <p className="text-gray-700 text-xs font-mono">Click any node in the graph to see its details</p>
            </div>
          )}

          {/* Graph Stats */}
          {stats && (
            <div className="glass-card p-4">
              <p className="text-xs font-mono text-gray-500 uppercase mb-3">Graph Stats</p>
              <div className="space-y-2">
                {[
                  { label: 'Total Nodes', value: stats.total_nodes },
                  { label: 'Total Edges', value: stats.total_edges },
                  { label: 'Critical Nodes', value: stats.critical_nodes },
                  { label: 'Density', value: stats.density },
                ].map(item => (
                  <div key={item.label} className="flex justify-between">
                    <span className="text-gray-500 text-xs font-mono">{item.label}</span>
                    <span className="text-cyan-400 text-xs font-mono font-bold">{item.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Top Sources */}
          {stats?.most_connected?.length > 0 && (
            <div className="glass-card p-4">
              <p className="text-xs font-mono text-gray-500 uppercase mb-3">Top Sources</p>
              <div className="space-y-1">
                {stats.most_connected.map((node, i) => (
                  <div key={i} className="flex justify-between items-center">
                    <span className="text-gray-400 text-xs font-mono truncate flex-1">{node.label}</span>
                    <span className="text-cyan-400 text-xs font-mono ml-2">{node.score}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tip */}
          {!isRealData && (
            <div className="glass-card p-3 border border-amber-500/20">
              <p className="text-amber-400 text-xs font-mono">
                💡 Fetch real IOCs from the Dashboard to see a dynamic graph with 100+ real threat nodes!
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
