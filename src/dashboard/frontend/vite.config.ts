import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const backend =
  process.env.DASHBOARD_BACKEND ||
  process.env.BACKEND_URL ||
  "http://localhost:8080";

export default defineConfig({
  base: "/admin/",
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/admin/api": {
        target: backend,
        changeOrigin: true,
      },
      "/admin/domains": {
        target: backend,
        changeOrigin: true,
      },
      "/admin/clusters": {
        target: backend,
        changeOrigin: true,
      },
      "/evidence": {
        target: backend,
        changeOrigin: true,
      },
      "/healthz": {
        target: backend,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
