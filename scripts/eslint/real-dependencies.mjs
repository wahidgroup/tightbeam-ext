/**
 * The lint that refuses test doubles and call assertions in every TypeScript suite: docs/development.md (Tests).
 *
 * # Sources
 *
 * - `skills/engineer/references/testing.md`, Prefer Real Dependencies, Test Doubles, and Behavior, Not Implementation.
 * - Vitest 4.1, `VitestUtils` in `vitest/dist/index.d.ts`: every member of `vi`.
 */

/**
 * The `vi` members a suite may use. A member that a later vitest adds is refused until this list holds it.
 */
const ALLOWED_VI = [
	"defineHelper",
	"dynamicImportSettled",
	"resetConfig",
	"resetModules",
	"setConfig",
	"waitFor",
	"waitUntil",
];

/**
 * The matchers that assert a call ran, or how often.
 */
const CALL_ASSERTIONS = [
	"toHaveBeenCalled",
	"toHaveBeenCalledOnce",
	"toHaveBeenCalledTimes",
	"toHaveBeenCalledWith",
	"toHaveBeenLastCalledWith",
	"toHaveBeenNthCalledWith",
	"toBeCalled",
	"toBeCalledTimes",
	"toBeCalledWith",
];

const DOUBLE_MESSAGE =
	"Run the real engine or the real peer: vi.{{member}} is not on the allowlist of scripts/eslint/real-dependencies.mjs.";

const ALIAS_MESSAGE =
	"Name a vi member directly: an alias, a destructure, or a computed access of vi hides which member a test uses.";

const CALL_MESSAGE =
	"Assert what the run shows, such as a value, a code, or what a peer received, not that a call ran.";

/**
 * The member that `vi` reads, when it reads one by name.
 */
function memberName(vi) {
	const parent = vi.parent;
	const named =
		parent.type === "MemberExpression" &&
		parent.object === vi &&
		!parent.computed &&
		parent.property.type === "Identifier";
	if (!named) {
		return undefined;
	}

	return parent.property.name;
}

/**
 * The text of `name`, a module export name, which is an identifier or a string literal.
 */
function exportName(name) {
	if (name.type === "Identifier") {
		return name.name;
	}

	return name.value;
}

/**
 * The rule that holds every use of `vi` to the allowlist: the global `vi`,
 * `vi` imported under any name, and `vi` read from a namespace import of
 * vitest.
 */
const viAllowlist = {
	meta: {
		type: "problem",
		schema: [],
		messages: { double: DOUBLE_MESSAGE, alias: ALIAS_MESSAGE },
	},
	create(context) {
		const sourceCode = context.sourceCode;

		function check(vi) {
			const member = memberName(vi);
			if (member === undefined) {
				context.report({ node: vi, messageId: "alias" });
				return;
			}
			if (ALLOWED_VI.includes(member)) {
				return;
			}

			context.report({
				node: vi.parent,
				messageId: "double",
				data: { member },
			});
		}

		function valueReferences(node) {
			const variables = sourceCode.getDeclaredVariables(node);
			const references = variables.flatMap((variable) => variable.references);
			return references.filter((reference) => reference.isValueReference !== false);
		}

		return {
			ImportSpecifier(node) {
				if (exportName(node.imported) !== "vi") {
					return;
				}

				for (const reference of valueReferences(node)) {
					check(reference.identifier);
				}
			},
			ImportNamespaceSpecifier(node) {
				if (node.parent.source.value !== "vitest") {
					return;
				}

				for (const reference of valueReferences(node)) {
					const namespace = reference.identifier;
					const parent = namespace.parent;
					const reads = parent.type === "MemberExpression" && parent.object === namespace;
					if (!reads) {
						context.report({ node: namespace, messageId: "alias" });
						continue;
					}
					if (parent.computed) {
						context.report({ node: parent, messageId: "alias" });
						continue;
					}
					if (parent.property.name === "vi") {
						check(parent);
					}
				}
			},
			ExportSpecifier(node) {
				if (exportName(node.local) === "vi") {
					context.report({ node, messageId: "alias" });
				}
			},
			ExportAllDeclaration(node) {
				if (node.source.value === "vitest") {
					context.report({ node, messageId: "alias" });
				}
			},
			"Program:exit"() {
				const unresolved = sourceCode.scopeManager.globalScope.through;
				for (const reference of unresolved) {
					if (reference.identifier.name === "vi" && reference.isValueReference !== false) {
						check(reference.identifier);
					}
				}
			},
		};
	},
};

/**
 * The config entry that refuses every double and every call assertion.
 */
export const realDependencies = {
	plugins: {
		"real-dependencies": { rules: { "vi-allowlist": viAllowlist } },
	},
	rules: {
		"real-dependencies/vi-allowlist": "error",
		"no-restricted-properties": [
			"error",
			...CALL_ASSERTIONS.map((property) => ({
				property,
				message: CALL_MESSAGE,
			})),
		],
	},
};
