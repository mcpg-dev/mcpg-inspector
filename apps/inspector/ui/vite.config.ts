import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'node:path';

// Bundle output goes to ../server/static/ so the inspector binary can
// embed it via include_dir at compile time. The built tree is
// committed — Bazel declares it as compile_data and never runs Vite.
export default defineConfig({
  // Pin the project root so a build launched from the workspace root
  // still resolves index.html relative to this file.
  root: __dirname,
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: path.resolve(__dirname, '../server/static'),
    emptyOutDir: true,
    sourcemap: false,
    target: 'es2022',
  },
  server: {
    port: 5174,
    proxy: {
      // Dev server talks to a `mcpg-inspector serve` on its default port.
      '/api': 'http://127.0.0.1:7846',
      '/healthz': 'http://127.0.0.1:7846',
      '/readyz': 'http://127.0.0.1:7846',
    },
  },
});
