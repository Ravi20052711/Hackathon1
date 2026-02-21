/**
 * =============================================================
 * COMPONENT - ThreatFeed
 * =============================================================
 * Real-time threat intelligence feed.
 * Combines WebSocket live events with historical feed from API.
 * New events animate in from the top with sliding transition.
 * =============================================================
 */

import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Zap, Clock, ExternalLink } from 'lucide-react'
import { feedApi } from '../../utils/api'
import { formatDistanceToNow } from 'date-fns'

// Color coding for severity levels
const SEVERITY_COLORS = {
  critical: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', dot: 'bg-red-400' },
  high: { bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400', dot: 'bg-amber-400' },
  medium: { bg: 'bg-blue-500/10', border: 'border-blue-500/30', text: 'text-blue-400', dot: 'bg-blue-400' },
  low: { bg: 'bg-green-500/10', border: 'border-green-500/30', text: 'text-green-400', dot: 'bg-green-400' },
  info: { bg: 'bg-gray-500/10', border: 'border-gray-500/30', text: 'text-gray-400', dot: 'bg-gray-400' },
}

export function ThreatFeed({ liveEvents = [] }) {
  const [historicalFeed, setHistoricalFeed] = useState([])

  useEffect(() => {
    // Load historical feed items from API on mount
    feedApi.get(20)
      .then(data => setHistoricalFeed(data))
      .catch(() => {})  // Silently fail if API unavailable
  }, [])

  // Merge live events (from WebSocket) with historical feed
  // Live events appear at the top since they're most recent
  const allEvents = [...liveEvents, ...historicalFeed].slice(0, 25)

  return (
    <div className="glass-card p-5 h-full">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Zap size={16} className="text-cyan-400 animate-pulse" />
          <h3 className="text-white font-mono font-semibold text-sm">Live Threat Feed</h3>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-pulse" />
          <span className="text-cyan-400 text-xs font-mono">{liveEvents.length} live</span>
        </div>
      </div>

      {/* Feed items list with animation */}
      <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
        <AnimatePresence>
          {allEvents.map((event, i) => {
            const severity = event.severity?.toLowerCase() || 'info'
            const colors = SEVERITY_COLORS[severity] || SEVERITY_COLORS.info
            const isLive = i < liveEvents.length  // Mark as live if from WebSocket

            return (
              <motion.div
                key={event.id || i}
                initial={{ opacity: 0, x: -20, height: 0 }}
                animate={{ opacity: 1, x: 0, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.3 }}
                className={`p-3 rounded-lg border ${colors.bg} ${colors.border} cursor-pointer hover:opacity-90 transition-opacity`}
              >
                <div className="flex items-start gap-3">
                  {/* Severity dot */}
                  <div className={`w-2 h-2 ${colors.dot} rounded-full mt-1.5 flex-shrink-0 ${severity === 'critical' ? 'animate-pulse' : ''}`} />

                  <div className="flex-1 min-w-0">
                    {/* Title row */}
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-white text-sm font-medium truncate">{event.title}</p>
                      <div className="flex items-center gap-1.5 flex-shrink-0">
                        {isLive && (
                          <span className="text-xs bg-cyan-400/20 text-cyan-400 px-1.5 py-0.5 rounded font-mono">LIVE</span>
                        )}
                        <span className={`text-xs px-1.5 py-0.5 rounded font-mono uppercase ${colors.text}`}>
                          {severity}
                        </span>
                      </div>
                    </div>

                    {/* Description */}
                    <p className="text-gray-500 text-xs mt-0.5 truncate">{event.description}</p>

                    {/* IOC value + metadata */}
                    <div className="flex items-center gap-3 mt-1.5">
                      {event.ioc_value && (
                        <code className="text-cyan-400/70 text-xs font-mono bg-black/30 px-1.5 py-0.5 rounded">
                          {event.ioc_value}
                        </code>
                      )}
                      {event.risk_score !== undefined && (
                        <span className={`text-xs font-mono ${
                          event.risk_score >= 80 ? 'text-red-400' :
                          event.risk_score >= 50 ? 'text-amber-400' :
                          'text-green-400'
                        }`}>
                          Risk: {event.risk_score}
                        </span>
                      )}
                      <div className="flex items-center gap-1 ml-auto">
                        <Clock size={10} className="text-gray-600" />
                        <span className="text-gray-600 text-xs font-mono">
                          {event.timestamp
                            ? formatDistanceToNow(new Date(event.timestamp), { addSuffix: true })
                            : 'just now'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </motion.div>
            )
          })}
        </AnimatePresence>

        {allEvents.length === 0 && (
          <div className="text-center py-12 text-gray-600 font-mono text-sm">
            <p>Waiting for threat data...</p>
            <p className="text-xs mt-1 text-gray-700">WebSocket connecting...</p>
          </div>
        )}
      </div>
    </div>
  )
}
