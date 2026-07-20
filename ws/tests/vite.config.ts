import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";

let port = 4317;
if (process.env.E2E_APP_PORT) {
	port = Number(process.env.E2E_APP_PORT);
}

// The client package (and its `.wasm` asset) lives in the sibling client/
// workspace, outside the app root, so the dev server must be allowed to read.
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
	optimizeDeps: {
		exclude: ["@wahidgroup/tightbeam-ws-client"],
	},
});
