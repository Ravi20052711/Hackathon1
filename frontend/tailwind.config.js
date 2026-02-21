/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",  // Scan all source files for Tailwind classes
  ],
  theme: {
    extend: {
      // Custom colors for the dark threat intel theme
      colors: {
        cyber: {
          bg: '#030712',        // Near-black background
          surface: '#0d1117',   // Card/panel background
          border: '#1f2937',    // Subtle borders
          accent: '#06b6d4',    // Cyan accent (primary)
          accent2: '#8b5cf6',   // Purple accent (secondary)
          danger: '#ef4444',    // Red for critical/danger
          warning: '#f59e0b',   // Amber for high/warning
          success: '#10b981',   // Green for safe/success
          muted: '#6b7280',     // Gray for secondary text
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s ease-in-out infinite',
        'scan': 'scan 2s linear infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        scan: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
        glow: {
          '0%': { boxShadow: '0 0 5px #06b6d4, 0 0 10px #06b6d4' },
          '100%': { boxShadow: '0 0 10px #06b6d4, 0 0 30px #06b6d4, 0 0 60px #06b6d4' },
        }
      },
    },
  },
  plugins: [],
}
