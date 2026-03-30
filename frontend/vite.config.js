import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Forwards REST calls and WebSocket upgrades to the FastAPI server
      "/alerts": "http://localhost:8000",
      "/stats":  "http://localhost:8000",
      "/ws": {
        target:    "ws://localhost:8000",
        ws:        true,
        rewriteWsOrigin: true,
      },
    },
  },
});