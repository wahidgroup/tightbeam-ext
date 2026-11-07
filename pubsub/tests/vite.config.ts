import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";

import { SOURCE_ALIASES } from "./aliases.js";

let port = 4318;
if (process.env.E2E_PUBSUB_APP_PORT) {
	port = Number(process.env.E2E_PUBSUB_APP_PORT);
}

// Both client packages (and the ws client's `.wasm` asset) live outside
// the app root, so the dev server must be allowed to read the repo.
const repoRoot = fileURLToPath(new URL("../..", import.meta.url));

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
	resolve: {
		// The board page shares the ws e2e fixtures at the source level.
		alias: SOURCE_ALIASES,
	},
	optimizeDeps: {
		exclude: ["@wahidgroup/tightbeam-ws-client"],
	},
});
