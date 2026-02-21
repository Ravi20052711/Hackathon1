/**
 * PAGE - Signup
 * Registers a new user via local SQLite auth.
 */

import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Shield, UserPlus } from 'lucide-react'
import axios from 'axios'
import toast from 'react-hot-toast'

export default function SignupPage() {
  const [form, setForm] = useState({ email: '', password: '', fullName: '' })
  const [loading, setLoading] = useState(false)
  const [done, setDone] = useState(false)
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()

    if (form.password.length < 6) {
      toast.error('Password must be at least 6 characters')
      return
    }

    setLoading(true)
    try {
      await axios.post('/api/auth/signup', {
        email: form.email,
        password: form.password,
        full_name: form.fullName
      })
      toast.success('Account created! You can now login.')
      setDone(true)
      // Auto redirect to login after 2 seconds
      setTimeout(() => navigate('/login'), 2000)
    } catch (error) {
      const msg = error.response?.data?.detail || 'Signup failed. Try again.'
      toast.error(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="animated-bg min-h-screen flex items-center justify-center p-4 relative overflow-hidden">
      <div className="cyber-grid absolute inset-0 opacity-50" />
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-purple-500/5 rounded-full blur-3xl" />

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="glass-card w-full max-w-md p-8 relative z-10"
        style={{ border: '1px solid rgba(139, 92, 246, 0.2)' }}
      >
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-16 h-16 bg-gradient-to-br from-purple-400/20 to-cyan-500/20 rounded-2xl flex items-center justify-center mb-4 border border-purple-400/30">
            <Shield size={32} className="text-purple-400" />
          </div>
          <h1 className="text-2xl font-bold text-white font-mono">
            CREATE<span className="text-purple-400">ACCOUNT</span>
          </h1>
          <p className="text-gray-500 text-xs font-mono mt-1">Local authentication — no email needed</p>
        </div>

        {done ? (
          <div className="text-center p-6">
            <div className="text-5xl mb-4">✅</div>
            <p className="text-green-400 font-mono font-bold">Account Created!</p>
            <p className="text-gray-400 font-mono text-sm mt-2">Redirecting to login...</p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Full Name */}
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">
                Full Name (optional)
              </label>
              <input
                type="text"
                value={form.fullName}
                onChange={e => setForm({ ...form, fullName: e.target.value })}
                className="w-full bg-black/30 border border-gray-700 rounded-lg px-4 py-3 text-white font-mono text-sm focus:outline-none focus:border-purple-400 focus:ring-1 focus:ring-purple-400/30 transition-all placeholder-gray-600"
                placeholder="Ravi Santosh"
              />
            </div>

            {/* Email */}
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">
                Email
              </label>
              <input
                type="email"
                value={form.email}
                onChange={e => setForm({ ...form, email: e.target.value })}
                className="w-full bg-black/30 border border-gray-700 rounded-lg px-4 py-3 text-white font-mono text-sm focus:outline-none focus:border-purple-400 focus:ring-1 focus:ring-purple-400/30 transition-all placeholder-gray-600"
                placeholder="you@example.com"
                required
              />
            </div>

            {/* Password */}
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">
                Password
              </label>
              <input
                type="password"
                value={form.password}
                onChange={e => setForm({ ...form, password: e.target.value })}
                className="w-full bg-black/30 border border-gray-700 rounded-lg px-4 py-3 text-white font-mono text-sm focus:outline-none focus:border-purple-400 focus:ring-1 focus:ring-purple-400/30 transition-all placeholder-gray-600"
                placeholder="Minimum 6 characters"
                required
                minLength={6}
              />
            </div>

            {/* Submit */}
            <motion.button
              type="submit"
              disabled={loading}
              whileHover={{ scale: 1.01 }}
              whileTap={{ scale: 0.99 }}
              className="w-full py-3 bg-gradient-to-r from-purple-500 to-purple-600 hover:from-purple-400 hover:to-purple-500 text-white font-bold font-mono rounded-lg flex items-center justify-center gap-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                <><UserPlus size={16} /> CREATE ACCOUNT</>
              )}
            </motion.button>
          </form>
        )}

        <p className="text-center text-gray-600 text-xs font-mono mt-6">
          Already have an account?{' '}
          <Link to="/login" className="text-cyan-400 hover:text-cyan-300 transition-colors">
            Login here
          </Link>
        </p>

        {/* Info box */}
        <div className="mt-4 p-3 bg-purple-500/5 border border-purple-500/20 rounded-lg">
          <p className="text-purple-400/70 text-xs font-mono text-center">
            💾 Account saved locally — no email verification needed
          </p>
        </div>
      </motion.div>
    </div>
  )
}
