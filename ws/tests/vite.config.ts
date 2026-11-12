import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";

import { APP_PORT } from "./app_port.js";

// The client package (and its `.wasm` asset) lives in the sibling client/
// workspace, outside the app root, so the dev server must be allowed to read.
const repoRoot = fileURLToPath(new URL("..", import.meta.url));

export default defineConfig({
	root: "app",
	server: {
		port: APP_PORT,
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
