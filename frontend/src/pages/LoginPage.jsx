/**
 * =============================================================
 * PAGE - Login
 * =============================================================
 * Cyberpunk-themed login page with glassmorphism card.
 * Features animated background, glowing inputs, and
 * a demo login button for testing without Supabase.
 * =============================================================
 */

import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Shield, Eye, EyeOff, Zap, Lock, Terminal } from 'lucide-react'
import { useAuth } from '../hooks/useAuth'

export default function LoginPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const { login, demoLogin } = useAuth()
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    const result = await login(email, password)
    if (result.success) navigate('/')
    setLoading(false)
  }

  const handleDemoLogin = async () => {
    setLoading(true)
    const result = await demoLogin()
    if (result.success) navigate('/')
    setLoading(false)
  }

  return (
    // Full-screen animated gradient background
    <div className="animated-bg min-h-screen flex items-center justify-center p-4 relative overflow-hidden">
      {/* Background grid overlay */}
      <div className="cyber-grid absolute inset-0 opacity-50" />

      {/* Decorative glowing orbs */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500/5 rounded-full blur-3xl" />

      {/* Floating particles (decorative) */}
      {[...Array(6)].map((_, i) => (
        <motion.div
          key={i}
          className="absolute w-1 h-1 bg-cyan-400 rounded-full"
          style={{
            left: `${20 + i * 15}%`,
            top: `${10 + i * 12}%`,
          }}
          animate={{ y: [-10, 10], opacity: [0.3, 1, 0.3] }}
          transition={{ duration: 2 + i, repeat: Infinity, ease: 'easeInOut' }}
        />
      ))}

      {/* Login card */}
      <motion.div
        initial={{ opacity: 0, y: 20, scale: 0.95 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.4 }}
        className="glass-card w-full max-w-md p-8 relative z-10"
        style={{ border: '1px solid rgba(6, 182, 212, 0.2)' }}
      >
        {/* Logo and title */}
        <div className="flex flex-col items-center mb-8">
          <motion.div
            animate={{ rotate: [0, 5, -5, 0] }}
            transition={{ duration: 4, repeat: Infinity }}
            className="w-16 h-16 bg-gradient-to-br from-cyan-400/20 to-purple-500/20 rounded-2xl flex items-center justify-center mb-4 border border-cyan-400/30"
          >
            <Shield size={32} className="text-cyan-400" />
          </motion.div>

          <h1 className="text-2xl font-bold text-white font-mono">
            THREAT<span className="text-cyan-400">INTEL</span>
          </h1>
          <p className="text-gray-500 text-sm mt-1 font-mono">Fusion Engine v1.0</p>

          {/* Animated status line */}
          <div className="flex items-center gap-2 mt-3 px-3 py-1 bg-green-400/10 rounded-full border border-green-400/20">
            <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
            <span className="text-green-400 text-xs font-mono">SYSTEM ONLINE</span>
          </div>
        </div>

        {/* Login form */}
        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">
              Operator ID (Email)
            </label>
            <div className="relative">
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                className="w-full bg-black/30 border border-gray-700 rounded-lg px-4 py-3 text-white font-mono text-sm focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/30 transition-all placeholder-gray-600"
                placeholder="analyst@company.com"
                required
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">
              Access Code
            </label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="w-full bg-black/30 border border-gray-700 rounded-lg px-4 py-3 pr-12 text-white font-mono text-sm focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/30 transition-all placeholder-gray-600"
                placeholder="••••••••"
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-cyan-400 transition-colors"
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          {/* Login button */}
          <motion.button
            type="submit"
            disabled={loading}
            whileHover={{ scale: 1.01 }}
            whileTap={{ scale: 0.99 }}
            className="w-full py-3 bg-gradient-to-r from-cyan-500 to-cyan-600 hover:from-cyan-400 hover:to-cyan-500 text-black font-bold font-mono rounded-lg flex items-center justify-center gap-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <div className="w-5 h-5 border-2 border-black border-t-transparent rounded-full animate-spin" />
            ) : (
              <>
                <Lock size={16} />
                AUTHENTICATE
              </>
            )}
          </motion.button>

          {/* Divider */}
          <div className="flex items-center gap-3">
            <div className="flex-1 h-px bg-gray-700" />
            <span className="text-gray-600 text-xs font-mono">OR</span>
            <div className="flex-1 h-px bg-gray-700" />
          </div>

          {/* Demo login button - bypasses real auth */}
          <motion.button
            type="button"
            onClick={handleDemoLogin}
            disabled={loading}
            whileHover={{ scale: 1.01 }}
            whileTap={{ scale: 0.99 }}
            className="w-full py-3 bg-black/40 hover:bg-black/60 border border-purple-500/30 hover:border-purple-400/50 text-purple-400 font-mono text-sm rounded-lg flex items-center justify-center gap-2 transition-all"
          >
            <Terminal size={16} />
            DEMO ACCESS (No Setup Required)
          </motion.button>
        </form>

        <p className="text-center text-gray-600 text-xs font-mono mt-6">
          New operator?{' '}
          <Link to="/signup" className="text-cyan-400 hover:text-cyan-300">
            Request Access
          </Link>
        </p>

        {/* Demo credentials hint */}
        <div className="mt-4 p-3 bg-yellow-500/5 border border-yellow-500/20 rounded-lg">
          <p className="text-yellow-400/70 text-xs font-mono text-center">
            ⚡ Demo: demo@example.com / demo1234
          </p>
        </div>
      </motion.div>
    </div>
  )
}
