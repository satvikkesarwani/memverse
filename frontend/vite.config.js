import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// All /api calls are proxied to the MEMVERSE gateway (FastAPI).
// The browser NEVER talks to NVIDIA directly.
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    allowedHosts: true,
    proxy: {
      '/api': {
        target: process.env.MEMVERSE_API || 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: '../backend/static',
    emptyOutDir: true,
  },
})
