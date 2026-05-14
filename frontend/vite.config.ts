import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],
  server: {
    proxy: {
      '/auth': 'http://localhost:8000',
      '/student': 'http://localhost:8000',
      '/instructor': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
    },
  },
})
