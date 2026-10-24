import react from "@vitejs/plugin-react";
import { readFileSync } from "node:fs";
import { colophon } from "@openasy/ui/vite";
import { defineConfig } from "vite";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

export default defineConfig({
  root: import.meta.dirname,
  plugins: [react(), colophon()],
  // sast-agent runs the same version as sast (ADR 0019): the command to start one names it.
  define: { __APP_VERSION__: JSON.stringify(version) },
  build: { outDir: "../dist/web", emptyOutDir: true },
  // The API only takes cookie requests from its own origin, so the dev server presents itself as that origin.
  server: { proxy: { "/api": { target: "http://localhost:8080", headers: { origin: "http://localhost:8080" } } } },
});
