import nestjsTyped from "@darraghor/eslint-plugin-nestjs-typed";

const nestjs = [
	nestjsTyped.configs.flatRecommended,
	{
		rules: {
			"@darraghor/nestjs-typed/api-property-returning-array-should-set-array":
				"off",
			// TODO: Enable eventually
			"@darraghor/nestjs-typed/api-method-should-specify-api-response":
				"off",
			// False positives with dynamic modules (forRoot), useFactory, useExisting, and global modules
			"@darraghor/nestjs-typed/injectable-should-be-provided": "off",
		},
	},
];

export default nestjs;
