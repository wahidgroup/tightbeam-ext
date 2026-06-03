import { defineConfig } from "eslint/config";
import base from "@wahidgroup/lint-rules/eslint/base";

export default defineConfig(...base, {
	// wasm-pack generated bindings; not authored source.
	ignores: ["wasm/"],
});
