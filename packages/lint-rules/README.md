# @wahidgroup/lint-rules

Shared linting, formatting, and TypeScript configuration for TypeScript packages.

## Install

```bash
npm install --save-dev @wahidgroup/lint-rules
```

Peer dependencies (`eslint`, `typescript`, and optionally `prettier`) must be installed in the consuming project.

## ESLint

This package provides composable ESLint flat configs exported as arrays. Spread them into a project's `eslint.config.mjs`.

### Base (all TypeScript projects)

Includes `@eslint/js` recommended, `typescript-eslint` recommended, `eslint-config-prettier`, and `eslint-plugin-import`.

```javascript
import { defineConfig } from "eslint/config";
import base from "@wahidgroup/lint-rules/eslint/base";

export default defineConfig(...base);
```

**Rules enforced:**

| Rule                                     | Effect                                          |
| ---------------------------------------- | ----------------------------------------------- |
| `consistent-type-assertions`             | Disallows `as` type assertions                  |
| `consistent-type-imports`                | Requires separate `import type` statements      |
| `no-unused-vars`                         | Errors on unused variables (ignores `_` prefix) |
| `import/consistent-type-specifier-style` | Requires top-level type specifiers              |
| `curly`                                  | Requires braces on all `if`/`else` blocks       |
| `no-multiple-empty-lines`                | Limits consecutive blank lines to 1             |
| `no-restricted-syntax`                   | Bans `.then()` chains and `.forEach()`          |

### React (frontend projects)

Adds `eslint-plugin-jsx-a11y` recommended and `eslint-plugin-react-hooks`. Ignores `*.d.ts` files.

```javascript
import { defineConfig } from "eslint/config";
import base from "@wahidgroup/lint-rules/eslint/base";
import react from "@wahidgroup/lint-rules/eslint/react";

export default defineConfig(...base, ...react);
```

### NestJS (backend projects)

Adds `@darraghor/eslint-plugin-nestjs-typed` recommended with overrides for known false positives.

```javascript
import { defineConfig } from "eslint/config";
import base from "@wahidgroup/lint-rules/eslint/base";
import nestjs from "@wahidgroup/lint-rules/eslint/nestjs";

export default defineConfig(...base, ...nestjs, {
	languageOptions: {
		parserOptions: {
			projectService: {
				allowDefaultProject: ["eslint.config.mjs"],
			},
			tsconfigRootDir: import.meta.dirname,
		},
	},
});
```

### Playwright (E2E test projects)

Adds `eslint-plugin-playwright` recommended with stricter rules for test quality: no conditionals in tests, no force option, no page pause, prefer web-first assertions, and count/length matchers.

```javascript
import { defineConfig } from "eslint/config";
import base from "@wahidgroup/lint-rules/eslint/base";
import playwright from "@wahidgroup/lint-rules/eslint/playwright";

export default defineConfig(...base, ...playwright, {
	ignores: ["test-results/", "playwright-report/", "blob-report/"],
});
```

## Prettier

Shared formatting config: hard tabs, tab width 4. All other options use Prettier defaults (double quotes, semicolons, trailing commas `"all"`, print width 80).

Create a `prettier.config.mjs` in the project root:

```javascript
export { default } from "@wahidgroup/lint-rules/prettier";
```

## TypeScript

Shared `compilerOptions` targeting ES2022 with strict mode, `NodeNext` module resolution, declaration emit, and `noUncheckedIndexedAccess`.

Extend from a project's `tsconfig.json`:

```json
{
	"extends": "@wahidgroup/lint-rules/tsconfig",
	"compilerOptions": {
		"outDir": "dist",
		"rootDir": "src"
	},
	"include": ["src"],
	"exclude": ["node_modules", "dist"]
}
```

## CSpell

Shared base dictionary and ignore paths. Extend from a project's `cspell` config:

```json
{
	"import": ["@wahidgroup/lint-rules/cspell"],
	"words": ["project-specific-words"],
	"ignorePaths": ["project-specific-paths"]
}
```
