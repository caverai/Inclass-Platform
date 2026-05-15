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
      '/auth': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/student': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        bypass: (req) => {
          // If the request is for a page (Accept includes text/html), don't proxy it.
          // This allows React Router to handle the URL after Vite serves index.html.
          if (req.headers.accept?.includes('text/html')) {
            return '/index.html';
          }
        },
      },
      '/instructor': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        bypass: (req) => {
          if (req.headers.accept?.includes('text/html')) {
            return '/index.html';
          }
        },
      },
      '/health': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
})
