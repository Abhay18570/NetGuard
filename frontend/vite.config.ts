import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

const proxy = {
  '/api': { target: 'http://127.0.0.1:5001', changeOrigin: true },
  '/socket.io': { target: 'http://127.0.0.1:5001', changeOrigin: true, ws: true },
}
export default defineConfig({
  plugins: [react()],
  server: { host: '127.0.0.1', port: 5173, strictPort: true, proxy },
  preview: { host: '127.0.0.1', port: 5173, strictPort: true, proxy },
})
