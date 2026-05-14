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
    // Return index.html for all non-asset routes so React Router handles deep
    // links and F5 refreshes on pages like /instructor/dashboard correctly.
    // Without this, Vite forwards /instructor/* to the backend proxy and FastAPI
    // returns {"detail":"Not Found"} for routes that only exist in the frontend.
    historyApiFallback: true,
    proxy: {
      '/auth': 'http://localhost:8000',
      '/student': 'http://localhost:8000',
      '/instructor': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
    },
  },
})
