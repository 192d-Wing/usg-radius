import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// SPA served at the root by the BFF; /api is the BFF. The dev server proxies
// /api to a locally-running BFF (cargo run in ui/bff) on :8088.
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", sourcemap: false },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8088",
    },
  },
});
