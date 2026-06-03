/**
 * Shared Prettier configuration.
 *
 * All other options use Prettier defaults:
 * double quotes, semicolons, trailing commas "all", print width 80.
 */
export default {
	useTabs: true,
	tabWidth: 4,
	overrides: [
		{
			files: ["*.yml", "*.yaml"],
			options: {
				useTabs: false,
				tabWidth: 2,
			},
		},
	],
};
