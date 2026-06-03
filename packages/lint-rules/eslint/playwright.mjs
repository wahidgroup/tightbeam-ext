import playwrightPlugin from "eslint-plugin-playwright";

const playwright = [
	{
		...playwrightPlugin.configs["flat/recommended"],
		rules: {
			...playwrightPlugin.configs["flat/recommended"].rules,
			"playwright/no-conditional-in-test": "error",
			"playwright/no-force-option": "error",
			"playwright/no-page-pause": "error",
			"playwright/no-wait-for-timeout": "warn",
			"playwright/prefer-to-have-count": "error",
			"playwright/prefer-to-have-length": "error",
			"playwright/prefer-web-first-assertions": "error",
		},
	},
];

export default playwright;
