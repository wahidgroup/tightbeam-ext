/**
 * Smoke: load every `package.json` export and scan dist for Node coupling.
 *
 * Only `dist/` is scanned for isomorphism: the `wasm-node/` tree is the
 * Node-target wasm-pack output and is Node-bound by design, selected via
 * the `#wasm` imports map's `node` condition.
 */

import { access, readFile, readdir } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import path from "node:path";
import process from "node:process";

const root = path.resolve(import.meta.dirname, "..");
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
 * Collects `.js` files under `dir`.
 */
async function collectJsFiles(dir: string): Promise<string[]> {
	const entries = await readdir(dir, {
		recursive: true,
		withFileTypes: true,
	});

	const files: string[] = [];
	for (const entry of entries) {
		if (entry.isFile() && entry.name.endsWith(".js")) {
			files.push(path.join(entry.parentPath, entry.name));
		}
	}

	return files;
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
 * Node-bound markers that must not appear in published dist JS.
 */
const nodeBound = /node:|require\(|__dirname|__filename/;
let failed = false;

const jsFiles = await collectJsFiles(distDir);
for (const file of jsFiles) {
	const source = await readFile(file, "utf8");
	if (!nodeBound.test(source)) {
		continue;
	}

	console.error(`Node-bound pattern in ${path.relative(root, file)}`);
	failed = true;
}

if (!failed) {
	console.log("ok isomorphic dist scan");
}

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
