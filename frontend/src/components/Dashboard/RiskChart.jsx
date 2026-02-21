/**
 * =============================================================
 * COMPONENT - RiskChart
 * =============================================================
 * Pie chart showing IOC type distribution.
 * Uses Recharts for rendering (included in package.json).
 * =============================================================
 */

import React from 'react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts'

const COLORS = {
  ip: '#06b6d4',      // Cyan for IPs
  domain: '#8b5cf6',  // Purple for domains
  hash: '#f59e0b',    // Amber for hashes
  url: '#10b981',     // Green for URLs
  email: '#ef4444',   // Red for emails
}

const DEMO_DATA = [
  { name: 'IP', value: 892, color: '#06b6d4' },
  { name: 'Domain', value: 543, color: '#8b5cf6' },
  { name: 'Hash', value: 312, color: '#f59e0b' },
  { name: 'URL', value: 100, color: '#10b981' },
]

export function RiskChart({ stats }) {
  // Transform stats.by_type into recharts format
  const data = stats?.by_type
    ? Object.entries(stats.by_type).map(([type, count]) => ({
        name: type.charAt(0).toUpperCase() + type.slice(1),
        value: count,
        color: COLORS[type] || '#6b7280'
      }))
    : DEMO_DATA

  return (
    <div className="glass-card p-5 h-full">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-white font-mono font-semibold text-sm">IOC Distribution</h3>
        <span className="text-gray-500 text-xs font-mono">By Type</span>
      </div>

      {/* Pie chart */}
      <div className="h-48">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={50}  // Donut chart style (inner hole)
              outerRadius={75}
              paddingAngle={3}
              dataKey="value"
            >
              {data.map((entry, index) => (
                <Cell key={index} fill={entry.color} stroke="transparent" />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                background: '#0d1117',
                border: '1px solid #1f2937',
                borderRadius: '8px',
                fontFamily: 'JetBrains Mono, monospace',
                fontSize: '12px',
                color: '#e2e8f0'
              }}
              formatter={(value, name) => [value.toLocaleString(), name]}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>

      {/* Legend */}
      <div className="space-y-2 mt-2">
        {data.map((item, i) => (
          <div key={i} className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-full" style={{ background: item.color }} />
              <span className="text-gray-400 font-mono text-xs">{item.name}</span>
            </div>
            <span className="text-gray-300 font-mono text-xs">{item.value?.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
