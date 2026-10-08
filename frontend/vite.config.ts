import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

// In development the Vite server proxies /api to the backend, so the browser
// only ever talks to one origin (the same arrangement nginx provides in Docker).
export default defineConfig(({ mode }) => {
  // "." is the directory Vite is started from (the frontend folder). Using it
  // instead of process.cwd() keeps this file free of Node-only globals, so the
  // type check needs no @types/node.
  const env = loadEnv(mode, ".", "");
  const backend = env.VITE_BACKEND_URL || "http://localhost:8000";
  return {
    plugins: [react(), tailwindcss()],
    server: {
      port: 5173,
      proxy: { "/api": { target: backend, changeOrigin: true } },
    },
  };
});
