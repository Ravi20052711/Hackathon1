/**
 * =============================================================
 * SUPABASE CLIENT - Frontend
 * =============================================================
 * Creates the Supabase client for use in React components.
 * Used for:
 *   - User authentication (signup/login/logout)
 *   - Real-time subscriptions to database changes
 *   - Direct Supabase queries from frontend (with RLS)
 *
 * NOTE: The ANON key is safe to expose in frontend code.
 * Never put the SERVICE_ROLE key in frontend!
 * =============================================================
 */

import { createClient } from '@supabase/supabase-js'

// Read from environment variables (set in .env file)
// Vite exposes env vars prefixed with VITE_ to the frontend
const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL || ''
const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY || ''

// Check if Supabase is configured
export const isSupabaseConfigured = Boolean(SUPABASE_URL && SUPABASE_ANON_KEY)

// Create the Supabase client (or a mock if not configured)
export const supabase = isSupabaseConfigured
  ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      auth: {
        // Store session in localStorage so users stay logged in on refresh
        persistSession: true,
        autoRefreshToken: true,
      },
      realtime: {
        // Enable real-time subscriptions for live feed
        params: { eventsPerSecond: 10 }
      }
    })
  : null  // null in demo mode - auth context handles this gracefully
