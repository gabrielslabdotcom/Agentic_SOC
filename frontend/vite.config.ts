import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: '/dashboard/static/',
  build: {
    outDir: '../src/agentic_soc/static',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/tools': 'http://127.0.0.1:8080',
      '/health': 'http://127.0.0.1:8080',
    },
  },
})
