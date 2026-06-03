import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";

let port = 4317;
if (process.env.E2E_APP_PORT) {
	port = Number(process.env.E2E_APP_PORT);
}

// The client package (and its `.wasm` asset) lives at the repo root under
// clients/web, outside the app root, so the dev server must be allowed to read.
const repoRoot = fileURLToPath(new URL("..", import.meta.url));

export default defineConfig({
	root: "app",
	server: {
		port,
		strictPort: true,
		host: true,
		fs: {
			allow: [repoRoot],
		},
	},
	// The wasm client locates its `.wasm` asset via `import.meta.url`; excluding
	// it from dependency pre-bundling keeps that URL intact.
	optimizeDeps: {
		exclude: ["@wahidgroup/tightbeam-ws-client"],
	},
});
