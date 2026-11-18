import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte()],
  base: '/',
  build: {
    outDir: '../internal/ui/dist',
    emptyOutDir: true,
    assetsDir: 'assets',
    target: 'es2022',
    minify: 'esbuild',
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: undefined
      }
    }
  },
  server: {
    port: 5173,
    proxy: {
      '/v1': {
        target: process.env.TIKRAY_DEV_API || 'https://127.0.0.1:443',
        changeOrigin: true,
        secure: false
      },
      '/healthz': {
        target: process.env.TIKRAY_DEV_API || 'https://127.0.0.1:443',
        changeOrigin: true,
        secure: false
      }
    }
  }
});
