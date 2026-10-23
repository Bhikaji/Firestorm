/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        graphite: {
          950: '#070b12',
          900: '#0b1220',
          850: '#0f1728',
          800: '#131d31',
          700: '#1b2942',
          600: '#26374f',
        },
        neon: {
          cyan: '#22d3ee',
          blue: '#3b82f6',
          teal: '#2dd4bf',
        },
        threat: {
          critical: '#f43f5e',
          high: '#fb7185',
          medium: '#f59e0b',
          low: '#38bdf8',
          info: '#64748b',
          ok: '#34d399',
        },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(34,211,238,0.18), 0 0 32px -12px rgba(34,211,238,0.45)',
        panel: '0 24px 60px -32px rgba(0,0,0,0.9)',
      },
      backgroundImage: {
        'grid-faint':
          'linear-gradient(rgba(148,163,184,0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.06) 1px, transparent 1px)',
        'radial-glow':
          'radial-gradient(1200px 600px at 20% -10%, rgba(34,211,238,0.10), transparent 60%), radial-gradient(900px 500px at 100% 0%, rgba(59,130,246,0.08), transparent 55%)',
      },
      keyframes: {
        'pulse-soft': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.45' },
        },
        'slide-in': {
          from: { opacity: '0', transform: 'translateY(4px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        'pulse-soft': 'pulse-soft 2.4s ease-in-out infinite',
        'slide-in': 'slide-in 180ms ease-out both',
      },
    },
  },
  plugins: [],
}
