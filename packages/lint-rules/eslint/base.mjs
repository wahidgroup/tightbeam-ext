import eslint from "@eslint/js";
import prettier from "eslint-config-prettier";
import importPlugin from "eslint-plugin-import";
import tseslint from "typescript-eslint";

const base = [
	eslint.configs.recommended,
	...tseslint.configs.recommended,
	prettier,
	{
		ignores: ["**/dist/", "**/node_modules/"],
	},
	{
		plugins: {
			import: importPlugin,
		},
		rules: {
			"@typescript-eslint/consistent-type-assertions": [
				"error",
				{ assertionStyle: "never" },
			],
			"@typescript-eslint/consistent-type-imports": [
				"error",
				{ prefer: "type-imports", fixStyle: "separate-type-imports" },
			],
			"@typescript-eslint/no-unused-vars": [
				"error",
				{ argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
			],
			"import/consistent-type-specifier-style": [
				"error",
				"prefer-top-level",
			],
			curly: ["error", "all"],
			"no-multiple-empty-lines": ["error", { max: 1 }],
			"no-restricted-syntax": [
				"error",
				{
					selector: "CallExpression[callee.property.name='then']",
					message: "Prefer async/await over .then() chains.",
				},
				{
					selector: "CallExpression[callee.property.name='forEach']",
					message: "Prefer for...of over .forEach().",
				},
			],
		},
	},
];

export default base;
