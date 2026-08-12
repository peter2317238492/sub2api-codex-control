import { fileURLToPath, URL } from "node:url";

import vue from "@vitejs/plugin-vue";
import { defineConfig } from "vite";

export default defineConfig({
  base: "/codex/",
  plugins: [vue()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  server: {
    port: 5173,
    strictPort: false,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8090",
      },
      "/codex-api": {
        target: "http://127.0.0.1:8090",
        rewrite: (path) => path.replace(/^\/codex-api/, ""),
      },
      "/codex-ws": {
        target: "ws://127.0.0.1:8090",
        ws: true,
        rewrite: (path) => path.replace(/^\/codex-ws/, "/ws"),
      },
    },
  },
  test: {
    environment: "happy-dom",
  },
});
