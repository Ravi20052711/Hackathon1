/**
 * =============================================================
 * MAIN ENTRY POINT
 * =============================================================
 * Bootstraps the React app. Sets up:
 *   - React Router for page navigation
 *   - Toaster for notifications (react-hot-toast)
 *   - Global CSS (Tailwind + custom styles)
 * =============================================================
 */

import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import App from './App.jsx'
import './index.css'  // Tailwind base styles

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      {/* Toast notifications appear in top-right corner */}
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: '#0d1117',
            color: '#e2e8f0',
            border: '1px solid #1f2937',
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: '12px',
          },
          success: { iconTheme: { primary: '#10b981', secondary: '#030712' } },
          error: { iconTheme: { primary: '#ef4444', secondary: '#030712' } },
        }}
      />
      <App />
    </BrowserRouter>
  </React.StrictMode>,
)
