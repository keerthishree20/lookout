import { fileURLToPath, URL } from "node:url";

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  server: { port: 3000, host: true },
  preview: { port: 3000, host: true },
  build: {
    // Recharts is the one heavy dependency; keep it out of the main chunk.
    rollupOptions: {
      output: {
        manualChunks: (id: string) =>
          id.includes("node_modules/recharts") || id.includes("node_modules/d3-") ? "charts" : undefined,
      },
    },
  },
});
