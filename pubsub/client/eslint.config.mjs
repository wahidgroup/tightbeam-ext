import { defineConfig } from "eslint/config";
import base from "@wahidgroup/lint-rules/eslint/base";

import { realDependencies } from "../../scripts/eslint/real-dependencies.mjs";

export default defineConfig(...base, realDependencies);
