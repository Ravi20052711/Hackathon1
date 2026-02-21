/**
 * =============================================================
 * COMPONENT - Layout (Sidebar + Main Content)
 * =============================================================
 * Wraps all protected pages with:
 *   - Collapsible sidebar navigation
 *   - Top header with user info
 *   - Threat level status indicator
 *   - Live connection status
 * =============================================================
 */

import React, { useState } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Shield, LayoutDashboard, Database, Bell,
  GitGraph, Search, FileText, LogOut,
  ChevronLeft, ChevronRight, Activity, Zap
} from 'lucide-react'
import { useAuth } from '../../hooks/useAuth'

// Navigation items with icon, label, and route
const NAV_ITEMS = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', exact: true },
  { to: '/iocs', icon: Database, label: 'IOC Explorer' },
  { to: '/alerts', icon: Bell, label: 'Alert Center' },
  { to: '/graph', icon: GitGraph, label: 'Graph View' },
  { to: '/hunt', icon: Search, label: 'Hunt Center' },
]

export default function Layout({ children }) {
  const [collapsed, setCollapsed] = useState(false)  // Sidebar collapse state
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  return (
    <div className="flex h-screen bg-cyber-bg overflow-hidden cyber-grid">

      {/* -------------------------------------------------------
          SIDEBAR NAVIGATION
          ------------------------------------------------------- */}
      <motion.aside
        animate={{ width: collapsed ? 72 : 240 }}
        transition={{ duration: 0.2, ease: 'easeInOut' }}
        className="flex flex-col bg-cyber-surface border-r border-cyber-border relative z-20 overflow-hidden"
        style={{ minWidth: collapsed ? 72 : 240, background: '#0d1117' }}
      >
        {/* Logo area */}
        <div className="flex items-center gap-3 p-4 border-b border-gray-800">
          <div className="w-9 h-9 bg-gradient-to-br from-cyan-400/20 to-purple-500/20 rounded-lg flex items-center justify-center border border-cyan-400/30 flex-shrink-0">
            <Shield size={20} className="text-cyan-400" />
          </div>
          <AnimatePresence>
            {!collapsed && (
              <motion.div
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -10 }}
                className="overflow-hidden"
              >
                <p className="text-white font-bold font-mono text-sm leading-none">THREATINTEL</p>
                <p className="text-cyan-400/60 font-mono text-xs">Fusion Engine</p>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Live threat status indicator */}
        {!collapsed && (
          <div className="mx-3 mt-3 p-2 bg-red-500/10 border border-red-500/20 rounded-lg">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-red-400 rounded-full animate-pulse flex-shrink-0" />
              <span className="text-red-400 text-xs font-mono">THREAT LEVEL: HIGH</span>
            </div>
          </div>
        )}

        {/* Navigation links */}
        <nav className="flex-1 p-3 space-y-1 mt-2">
          {NAV_ITEMS.map(({ to, icon: Icon, label, exact }) => (
            <NavLink
              key={to}
              to={to}
              end={exact}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-mono transition-all group
                ${isActive
                  ? 'bg-cyan-400/10 text-cyan-400 border border-cyan-400/20'
                  : 'text-gray-500 hover:text-gray-300 hover:bg-white/5'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <Icon size={18} className={`flex-shrink-0 ${isActive ? 'text-cyan-400' : 'text-gray-500 group-hover:text-gray-300'}`} />
                  <AnimatePresence>
                    {!collapsed && (
                      <motion.span
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="whitespace-nowrap overflow-hidden"
                      >
                        {label}
                      </motion.span>
                    )}
                  </AnimatePresence>
                  {/* Active indicator dot */}
                  {isActive && !collapsed && (
                    <div className="ml-auto w-1.5 h-1.5 bg-cyan-400 rounded-full" />
                  )}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        {/* User info + logout */}
        <div className="p-3 border-t border-gray-800">
          <div className="flex items-center gap-3 p-2">
            <div className="w-8 h-8 bg-gradient-to-br from-purple-400 to-cyan-400 rounded-lg flex items-center justify-center flex-shrink-0 text-black font-bold text-xs">
              {user?.email?.[0]?.toUpperCase() || 'A'}
            </div>
            <AnimatePresence>
              {!collapsed && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex-1 min-w-0"
                >
                  <p className="text-white text-xs font-mono truncate">{user?.email || 'analyst'}</p>
                  <p className="text-gray-500 text-xs font-mono">Analyst</p>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-3 px-3 py-2 mt-1 text-gray-500 hover:text-red-400 hover:bg-red-400/5 rounded-lg transition-all font-mono text-xs"
          >
            <LogOut size={16} className="flex-shrink-0" />
            <AnimatePresence>
              {!collapsed && (
                <motion.span initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                  Logout
                </motion.span>
              )}
            </AnimatePresence>
          </button>
        </div>

        {/* Collapse toggle button */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="absolute -right-3 top-20 w-6 h-6 bg-gray-800 border border-gray-700 rounded-full flex items-center justify-center text-gray-400 hover:text-cyan-400 hover:border-cyan-400/50 transition-all z-10"
        >
          {collapsed ? <ChevronRight size={12} /> : <ChevronLeft size={12} />}
        </button>
      </motion.aside>

      {/* -------------------------------------------------------
          MAIN CONTENT AREA
          ------------------------------------------------------- */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top header bar */}
        <header className="h-14 bg-cyber-surface border-b border-gray-800 flex items-center justify-between px-6 flex-shrink-0">
          <div className="flex items-center gap-3">
            <Activity size={16} className="text-cyan-400 animate-pulse" />
            <span className="text-gray-400 font-mono text-xs">
              {new Date().toLocaleString('en-US', { hour12: false })} UTC
            </span>
          </div>

          <div className="flex items-center gap-4">
            {/* Live feed indicator */}
            <div className="flex items-center gap-2 px-3 py-1 bg-green-400/10 rounded-full border border-green-400/20">
              <Zap size={12} className="text-green-400" />
              <span className="text-green-400 text-xs font-mono">LIVE FEED ACTIVE</span>
            </div>
            {/* Alert count badge */}
            <div className="relative">
              <Bell size={18} className="text-gray-500" />
              <span className="absolute -top-1 -right-1 w-4 h-4 bg-red-500 rounded-full text-white text-xs flex items-center justify-center font-mono">3</span>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-auto p-6">
          {children}
        </main>
      </div>
    </div>
  )
}
