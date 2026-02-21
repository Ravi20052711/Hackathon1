/**
 * =============================================================
 * APP.JSX - Root Component & Routing
 * =============================================================
 * Sets up React Router routes and wraps everything in
 * the AuthProvider for global auth state.
 *
 * Routes:
 *   /login     → LoginPage (public, redirect to dashboard if authed)
 *   /signup    → SignupPage (public)
 *   /          → Dashboard (protected)
 *   /iocs      → IOC Explorer (protected)
 *   /alerts    → Alert Center (protected)
 *   /graph     → Graph View (protected)
 *   /hunt      → Hunt Center (protected)
 *   /reports   → Reports (protected)
 * =============================================================
 */

import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './hooks/useAuth'

// Page components (each is its own file in /pages/)
import LoginPage from './pages/LoginPage'
import SignupPage from './pages/SignupPage'
import DashboardPage from './pages/DashboardPage'
import IOCExplorerPage from './pages/IOCExplorerPage'
import AlertsPage from './pages/AlertsPage'
import GraphViewPage from './pages/GraphViewPage'
import HuntPage from './pages/HuntPage'

// Shared layout with sidebar navigation
import Layout from './components/Dashboard/Layout'

/**
 * ProtectedRoute - redirects to /login if user is not authenticated
 * Wraps any route that requires authentication
 */
function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()

  // Show loading spinner while checking auth status
  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-cyber-bg">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
          <p className="text-cyan-400 font-mono text-sm">Authenticating...</p>
        </div>
      </div>
    )
  }

  // Redirect to login if not authenticated
  if (!user) return <Navigate to="/login" replace />

  // Render the protected page wrapped in the Layout (sidebar)
  return <Layout>{children}</Layout>
}

function AppRoutes() {
  const { user } = useAuth()

  return (
    <Routes>
      {/* Public routes */}
      <Route path="/login" element={user ? <Navigate to="/" /> : <LoginPage />} />
      <Route path="/signup" element={user ? <Navigate to="/" /> : <SignupPage />} />

      {/* Protected routes (require authentication) */}
      <Route path="/" element={<ProtectedRoute><DashboardPage /></ProtectedRoute>} />
      <Route path="/iocs" element={<ProtectedRoute><IOCExplorerPage /></ProtectedRoute>} />
      <Route path="/alerts" element={<ProtectedRoute><AlertsPage /></ProtectedRoute>} />
      <Route path="/graph" element={<ProtectedRoute><GraphViewPage /></ProtectedRoute>} />
      <Route path="/hunt" element={<ProtectedRoute><HuntPage /></ProtectedRoute>} />

      {/* Catch-all → redirect to dashboard */}
      <Route path="*" element={<Navigate to="/" />} />
    </Routes>
  )
}

export default function App() {
  return (
    // AuthProvider wraps everything so any component can use useAuth()
    <AuthProvider>
      <AppRoutes />
    </AuthProvider>
  )
}
