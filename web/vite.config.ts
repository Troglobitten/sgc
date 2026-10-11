import { fileURLToPath, URL } from 'node:url'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  define: {
    // The SGC version this interface is built for (set by scripts/build-web.sh).
    // The page compares it with the version SGC reports and reloads itself
    // when SGC has been updated underneath it.
    __SGC_VERSION__: JSON.stringify(process.env.SGC_VERSION ?? 'dev'),
  },
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    // During interface development the pages come from Vite and the API from
    // a local `sgc serve --dev-insecure-http`.
    proxy: { '/api': 'http://127.0.0.1:8443' },
  },
})
