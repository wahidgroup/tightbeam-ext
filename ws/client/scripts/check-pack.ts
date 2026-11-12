/**
 * Assert that `npm pack` holds what `package.json` names, as the package
 * section of `docs/ws-client.md` lists.
 */

import type { SpawnSyncOptionsWithStringEncoding } from "node:child_process";
import { spawnSync } from "node:child_process";
import { access, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const pkgPath = path.join(root, "package.json");

const pkgRaw = await readFile(pkgPath, "utf8");
const pkg: unknown = JSON.parse(pkgRaw);
if (typeof pkg !== "object" || pkg === null) {
	console.error("package.json is not an object");
	process.exit(1);
}

const filesField: unknown = Reflect.get(pkg, "files");
if (!Array.isArray(filesField) || filesField.length === 0) {
	console.error("package.json missing files array");
	process.exit(1);
}

const allowEntries: string[] = [];
for (const entry of filesField) {
	if (typeof entry !== "string" || entry.length === 0) {
		console.error("package.json files entry must be a non-empty string");
		process.exit(1);
	}

	allowEntries.push(entry);
}

for (const entry of allowEntries) {
	try {
		await access(path.join(root, entry));
	} catch {
		console.error(`files entry missing on disk: ${entry}`);
		process.exit(1);
	}
}

const pack = spawnSync("npm", ["pack", "--dry-run"], {
	cwd: root,
	encoding: "utf8",
});

if (pack.status !== 0) {
	console.error(pack.stderr || pack.stdout || "npm pack --dry-run failed");
	process.exit(1);
}

const listing = `${pack.stdout ?? ""}\n${pack.stderr ?? ""}`;
const packed: string[] = [];

/**
 * Matches `npm pack --dry-run` size lines: `1.2kB path/to/file`.
 */
const npmPackSizeLine = /^[\d.]+[kKmMgG]?B\s+(.+)$/;

for (const line of listing.split("\n")) {
	const marker = "npm notice ";
	if (!line.startsWith(marker)) {
		continue;
	}

	const rest = line.slice(marker.length).trim();
	const match = npmPackSizeLine.exec(rest);
	if (!match?.[1]) {
		continue;
	}

	packed.push(match[1]);
}

if (packed.length === 0) {
	console.error("npm pack --dry-run produced no file list");
	process.exit(1);
}

/**
 * True when a packed path is allowed by `files` (or is package.json).
 */
function isAllowed(file: string): boolean {
	if (file === "package.json") {
		return true;
	}

	for (const entry of allowEntries) {
		if (file === entry) {
			return true;
		}
		if (file.startsWith(`${entry}/`)) {
			return true;
		}
	}

	return false;
}

/**
 * True when a `files` entry appears in the pack.
 */
function isPresent(entry: string): boolean {
	if (packed.includes(entry)) {
		return true;
	}

	for (const file of packed) {
		if (file.startsWith(`${entry}/`)) {
			return true;
		}
	}

	return false;
}

/**
 * The build outputs that `tsc` writes for tsconfig.build.json, as `tsc` resolves the config: one `.js` and one `.d.ts`
 * per source it compiles, and a copy of each JSON source, under its `outDir`.
 */
const showArgs = ["tsc", "-p", "tsconfig.build.json", "--showConfig"];
const showOptions: SpawnSyncOptionsWithStringEncoding = {
	cwd: root,
	encoding: "utf8",
};
const showConfig = spawnSync("npx", showArgs, showOptions);
if (showConfig.status !== 0) {
	console.error(showConfig.stderr || "tsc --showConfig failed");
	process.exit(1);
}

const parsed: unknown = JSON.parse(showConfig.stdout);
const resolved: object = Object(parsed);
const compilerField: unknown = Reflect.get(resolved, "compilerOptions");
const compilerOptions: object = Object(compilerField);
const outDirOption: unknown = Reflect.get(compilerOptions, "outDir");
const rootDirOption: unknown = Reflect.get(compilerOptions, "rootDir");
const sources: unknown = Reflect.get(resolved, "files");

const namesOutDir = typeof outDirOption === "string";
const namesRootDir = typeof rootDirOption === "string";
const listsSources = Array.isArray(sources);
if (!namesOutDir || !namesRootDir || !listsSources) {
	console.error("tsconfig.build.json resolves no outDir, rootDir, or files");
	process.exit(1);
}

const outDir = path.normalize(outDirOption);
const rootDir = path.normalize(rootDirOption);
const built = new Set<string>();
for (const source of sources) {
	const sourcePath = String(source);
	const relative = path.relative(rootDir, sourcePath);
	if (relative.endsWith(".json")) {
		built.add(path.join(outDir, relative));
		continue;
	}

	const stem = relative.replace(/\.ts$/, "");
	built.add(path.join(outDir, `${stem}.js`));
	built.add(path.join(outDir, `${stem}.d.ts`));
}

let failed = false;
for (const file of packed) {
	if (isAllowed(file)) {
		continue;
	}

	console.error(`unexpected pack path: ${file}`);
	failed = true;
}

for (const file of packed) {
	const output = file.startsWith(`${outDir}/`);
	if (!output || built.has(file)) {
		continue;
	}

	const stray = `packed output that tsconfig.build.json does not build: ${file}`;
	console.error(stray);
	failed = true;
}

for (const entry of allowEntries) {
	if (isPresent(entry)) {
		continue;
	}

	console.error(`files entry not in pack: ${entry}`);
	failed = true;
}

if (!packed.includes("package.json")) {
	console.error("package.json missing from pack");
	failed = true;
}

if (failed) {
	process.exit(1);
}

console.log(`ok pack matches files (${packed.length} paths, ${allowEntries.length} files entries)`);
