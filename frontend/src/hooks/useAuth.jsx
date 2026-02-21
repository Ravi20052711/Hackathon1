/**
 * =============================================================
 * AUTH CONTEXT - Global Authentication State
 * =============================================================
 * Provides login/logout/signup to all components.
 * Demo login always works without any setup.
 * =============================================================
 */

import React, { createContext, useContext, useState, useEffect } from 'react'
import toast from 'react-hot-toast'
import axios from 'axios'

const AuthContext = createContext(null)

// Direct axios call to avoid interceptor redirect loop on startup
const apiCall = (method, url, data) =>
  axios({ method, url, data, baseURL: '/api', timeout: 10000 })
    .then(r => r.data)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Check if we have a stored token on page load
    const token = localStorage.getItem('access_token')
    const storedUser = localStorage.getItem('user_data')

    if (token && storedUser) {
      try {
        setUser(JSON.parse(storedUser))  // Restore session from localStorage
      } catch {
        localStorage.removeItem('access_token')
        localStorage.removeItem('user_data')
      }
    }
    setLoading(false)
  }, [])

  const login = async (email, password) => {
    try {
      const response = await apiCall('post', '/auth/login', { email, password })

      // Store token and user info
      localStorage.setItem('access_token', response.access_token)
      const userData = { email: response.email, user_id: response.user_id }
      localStorage.setItem('user_data', JSON.stringify(userData))
      setUser(userData)

      toast.success('Login successful!')
      return { success: true }

    } catch (error) {
      const message = error.response?.data?.detail || 'Login failed. Check your credentials.'
      toast.error(message)
      return { success: false }
    }
  }

  const signup = async (email, password, fullName) => {
    try {
      await apiCall('post', '/auth/signup', { email, password, full_name: fullName })
      toast.success('Account created! You can now log in.')
      return { success: true }
    } catch (error) {
      const message = error.response?.data?.detail || 'Signup failed.'
      toast.error(message)
      return { success: false }
    }
  }

  const logout = () => {
    localStorage.removeItem('access_token')
    localStorage.removeItem('user_data')
    setUser(null)
    toast.success('Logged out')
  }

  // Demo login - uses hardcoded demo credentials
  const demoLogin = () => login('demo@example.com', 'demo1234')

  return (
    <AuthContext.Provider value={{ user, loading, login, signup, logout, demoLogin }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
