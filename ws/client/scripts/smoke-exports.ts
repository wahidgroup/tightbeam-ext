/**
 * Smoke: load every `package.json` export, which loads without the glue, as
 * the package section of `docs/ws-client.md` describes.
 */

import { access, readFile } from "node:fs/promises";
import { registerHooks } from "node:module";
import { pathToFileURL } from "node:url";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const distDir = path.join(root, "dist");
const pkgPath = path.join(root, "package.json");

const pkgRaw = await readFile(pkgPath, "utf8");
const pkg: unknown = JSON.parse(pkgRaw);
if (typeof pkg !== "object" || pkg === null) {
	console.error("package.json is not an object");
	process.exit(1);
}

const exportsField: unknown = Reflect.get(pkg, "exports");
if (typeof exportsField !== "object" || exportsField === null) {
	console.error("package.json missing exports");
	process.exit(1);
}

/**
 * Resolves an export target to a filesystem path under the package root.
 */
function resolveExportTarget(target: unknown): string | undefined {
	if (typeof target === "string") {
		return path.resolve(root, target);
	}
	if (typeof target !== "object" || target === null) {
		return undefined;
	}

	const defaultTarget: unknown = Reflect.get(target, "default");
	if (typeof defaultTarget === "string") {
		return path.resolve(root, defaultTarget);
	}

	const typesTarget: unknown = Reflect.get(target, "types");
	if (typeof typesTarget === "string") {
		return path.resolve(root, typesTarget);
	}

	return undefined;
}

try {
	await access(distDir);
} catch {
	console.error("dist/ missing - run make client before smoke");
	process.exit(1);
}

/**
 * The directories of the two glue bundles, which no export loads as it imports.
 */
const glue = ["wasm/", "wasm-node/"].map((directory) => new URL(directory, pathToFileURL(`${root}/`)).href);

registerHooks({
	resolve(specifier, context, nextResolve) {
		const resolved = nextResolve(specifier, context);
		if (glue.some((directory) => resolved.url.startsWith(directory))) {
			throw new Error(`${context.parentURL ?? specifier} loads the glue ${resolved.url} as it imports`);
		}

		return resolved;
	},
});

let failed = false;

for (const key of Object.keys(exportsField)) {
	if (key === "./package.json") {
		continue;
	}

	const target = resolveExportTarget(Reflect.get(exportsField, key));
	if (!target) {
		console.error(`export ${key}: unresolvable target`);
		failed = true;
		continue;
	}

	try {
		await access(target);
	} catch {
		console.error(`export ${key}: missing ${path.relative(root, target)}`);
		failed = true;
		continue;
	}

	if (!target.endsWith(".js")) {
		console.log(`ok ${key} -> ${path.relative(root, target)}`);
		continue;
	}

	const mod: unknown = await import(pathToFileURL(target).href);
	if (typeof mod !== "object" || mod === null) {
		console.error(`export ${key}: did not load a module`);
		failed = true;
		continue;
	}

	console.log(`ok ${key} -> ${path.relative(root, target)}`);
}

if (failed) {
	process.exit(1);
}

console.log("smoke: all exports load");
