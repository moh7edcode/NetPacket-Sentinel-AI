import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

const BACKEND = process.env.VITE_BACKEND_PORT ?? "8010";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: `http://localhost:${BACKEND}`, changeOrigin: true },
      "/ws": { target: `ws://localhost:${BACKEND}`, ws: true },
    },
  },
});
