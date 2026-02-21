/**
 * =============================================================
 * COMPONENT - MetricCard
 * =============================================================
 * Glassmorphism stat card for dashboard overview metrics.
 * Shows icon, value, label, and trend indicator.
 * =============================================================
 */

import React from 'react'
import { motion } from 'framer-motion'
import { TrendingUp, TrendingDown, Minus } from 'lucide-react'

// Color map: prop name → Tailwind/hex colors
const COLOR_MAP = {
  cyan: { bg: 'rgba(6,182,212,0.1)', border: 'rgba(6,182,212,0.2)', text: '#06b6d4', icon: 'text-cyan-400' },
  amber: { bg: 'rgba(245,158,11,0.1)', border: 'rgba(245,158,11,0.2)', text: '#f59e0b', icon: 'text-amber-400' },
  red: { bg: 'rgba(239,68,68,0.1)', border: 'rgba(239,68,68,0.2)', text: '#ef4444', icon: 'text-red-400' },
  green: { bg: 'rgba(16,185,129,0.1)', border: 'rgba(16,185,129,0.2)', text: '#10b981', icon: 'text-green-400' },
  purple: { bg: 'rgba(139,92,246,0.1)', border: 'rgba(139,92,246,0.2)', text: '#8b5cf6', icon: 'text-purple-400' },
}

export function MetricCard({ icon: Icon, label, value, trend, trendUp, color = 'cyan' }) {
  const colors = COLOR_MAP[color] || COLOR_MAP.cyan

  return (
    <motion.div
      whileHover={{ y: -2, boxShadow: `0 8px 32px ${colors.bg}` }}
      className="glass-card p-5 cursor-default"
      style={{ background: '#0d1117', border: `1px solid ${colors.border}` }}
    >
      {/* Icon + label row */}
      <div className="flex items-center justify-between mb-3">
        <p className="text-gray-500 font-mono text-xs uppercase tracking-wider">{label}</p>
        <div className={`w-9 h-9 rounded-lg flex items-center justify-center`} style={{ background: colors.bg }}>
          <Icon size={18} style={{ color: colors.text }} />
        </div>
      </div>

      {/* Large metric value */}
      <p className="text-3xl font-bold font-mono" style={{ color: colors.text }}>
        {value ?? '—'}
      </p>

      {/* Trend indicator */}
      <div className="flex items-center gap-1 mt-2">
        {trendUp === true && <TrendingUp size={12} className="text-green-400" />}
        {trendUp === false && <TrendingDown size={12} className="text-red-400" />}
        {trendUp === null && <Minus size={12} className="text-gray-500" />}
        <span className={`text-xs font-mono ${
          trendUp === true ? 'text-green-400' :
          trendUp === false ? 'text-red-400' :
          'text-gray-500'
        }`}>
          {trend}
        </span>
      </div>
    </motion.div>
  )
}
