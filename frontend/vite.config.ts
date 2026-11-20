import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The Go API runs on :8080. The Vite dev server proxies /api so the SPA can
// use the relative '/api/v1' base (same-origin → SSE cookies work too).
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/api': {
        // `make dev` shares the chosen API port via WADJET_API_PORT
        // (auto-bumped when 8080 is taken by another process).
        target: `http://127.0.0.1:${process.env.WADJET_API_PORT ?? '8080'}`,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
});
