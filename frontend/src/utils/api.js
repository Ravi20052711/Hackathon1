/**
 * =============================================================
 * API UTILITY - Backend HTTP Client
 * =============================================================
 * Centralized Axios instance for calling the FastAPI backend.
 * Automatically attaches the auth token from localStorage.
 * =============================================================
 */

import axios from 'axios'

// Create Axios instance with base URL pointing to FastAPI
const api = axios.create({
  baseURL: '/api',  // Vite proxies /api → http://localhost:8000/api
  timeout: 15000,   // 15 second timeout
  headers: {
    'Content-Type': 'application/json',
  }
})

// Request interceptor: attach JWT token if user is logged in
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Response interceptor: handle 401 (redirect to login)
api.interceptors.response.use(
  (response) => response.data,  // Unwrap response.data automatically
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('access_token')
      window.location.href = '/login'  // Redirect to login on auth failure
    }
    return Promise.reject(error.response?.data || error.message)
  }
)

// -------------------------------------------------------
// API Functions - one per feature domain
// -------------------------------------------------------

// Auth
export const authApi = {
  login: (credentials) => api.post('/auth/login', credentials),
  signup: (userData) => api.post('/auth/signup', userData),
  logout: () => api.post('/auth/logout'),
  me: () => api.get('/auth/me'),
}

// IOCs
export const iocApi = {
  list: (params) => api.get('/ioc/', { params }),
  get: (id) => api.get(`/ioc/${id}`),
  create: (ioc) => api.post('/ioc/', ioc),
  delete: (id) => api.delete(`/ioc/${id}`),
  stats: () => api.get('/ioc/stats'),
}

// Alerts
export const alertApi = {
  list: (limit = 20) => api.get('/alerts/', { params: { limit } }),
  submit: (alert) => api.post('/alerts/', alert),
  get: (id) => api.get(`/alerts/${id}`),
}

// Graph
export const graphApi = {
  getData: () => api.get('/graph/'),
  getStats: () => api.get('/graph/stats'),
}

// Threat Feed
export const feedApi = {
  get: (limit = 30) => api.get('/feed/', { params: { limit } }),
}

// Hunt
export const huntApi = {
  list: () => api.get('/hunt/'),
  generate: (iocValue, iocType, riskScore) => api.post(`/hunt/generate?ioc_value=${iocValue}&ioc_type=${iocType}&risk_score=${riskScore}`),
  templates: () => api.get('/hunt/templates'),
}

// Reports
export const reportApi = {
  list: () => api.get('/reports/'),
  generate: (type) => api.post('/reports/generate', null, { params: { report_type: type } }),
}

export default api
