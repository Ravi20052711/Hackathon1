/**
 * =============================================================
 * HOOK - useWebSocket
 * =============================================================
 * Connects to the FastAPI WebSocket endpoint for real-time
 * alert streaming. Automatically reconnects on disconnect.
 *
 * Usage:
 *   const { events, connected } = useWebSocket('/api/alerts/ws/live')
 * =============================================================
 */

import { useState, useEffect, useRef, useCallback } from 'react'

export function useWebSocket(url) {
  const [events, setEvents] = useState([])   // Accumulated live events
  const [connected, setConnected] = useState(false)
  const ws = useRef(null)                     // WebSocket instance ref
  const reconnectTimer = useRef(null)         // Reconnect timer ref

  const connect = useCallback(() => {
    // Convert http URL to ws URL (vite proxy handles the routing)
    const wsUrl = url.replace('/api/', 'ws://localhost:8000/api/')

    try {
      ws.current = new WebSocket(wsUrl)

      ws.current.onopen = () => {
        setConnected(true)
        console.log('🔌 WebSocket connected to live feed')
      }

      ws.current.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data)
          // Prepend new event to show latest first
          setEvents(prev => [message.data, ...prev].slice(0, 50))  // Keep last 50
        } catch (e) {
          console.error('Failed to parse WebSocket message', e)
        }
      }

      ws.current.onclose = () => {
        setConnected(false)
        // Auto-reconnect after 3 seconds
        reconnectTimer.current = setTimeout(connect, 3000)
      }

      ws.current.onerror = (error) => {
        console.error('WebSocket error:', error)
        ws.current?.close()
      }
    } catch (error) {
      console.error('WebSocket connection failed:', error)
      // Retry after 5 seconds if connection fails
      reconnectTimer.current = setTimeout(connect, 5000)
    }
  }, [url])

  useEffect(() => {
    connect()

    // Cleanup on unmount
    return () => {
      clearTimeout(reconnectTimer.current)
      ws.current?.close()
    }
  }, [connect])

  const clearEvents = () => setEvents([])

  return { events, connected, clearEvents }
}
