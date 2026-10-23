import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const backend = process.env.FIRESTORM_API_URL || 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
    allowedHosts: true,
    proxy: {
      // xfwd forwards X-Forwarded-For so the API rate-limits the real browser
      // address instead of lumping every user behind this proxy together.
      '/api': { target: backend, changeOrigin: true, ws: true, xfwd: true },
    },
  },
  build: { outDir: 'dist', sourcemap: false },
})
