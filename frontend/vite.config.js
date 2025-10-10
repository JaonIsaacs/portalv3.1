import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'fs'
import path from 'path'

const certPath = path.resolve(__dirname, 'cert', 'cert.pem')
const keyPath = path.resolve(__dirname, 'cert', 'key.pem')

export default defineConfig({
  plugins: [react()],
  server: fs.existsSync(certPath) && fs.existsSync(keyPath) ? {
    https: {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath),
    },
    port: 5173
  } : { port: 5173 }
})
