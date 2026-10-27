import { defineConfig } from "vite";

// The build lands where the Python app serves it from; `npm run dev` proxies the API to a running
// Studio (docker compose, port 3001), so the page reloads instantly while the backend stays real.
export default defineConfig({
  build: {
    outDir: "../src/kilnbase_studio/web",
    emptyOutDir: true,
    target: "es2022",
    // A page holding the service_role key ships no source maps.
    sourcemap: false,
  },
  server: {
    host: "127.0.0.1",
    proxy: { "/api": "http://127.0.0.1:3001" },
  },
});
