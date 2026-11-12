/**
 * The compile of the `ts` fences of a markdown page under the options of one package: docs/development.md (Tests).
 *
 * # Sources
 *
 * - TypeScript, Using the Compiler API (`createProgram`, `CompilerHost`).
 */
/// <reference types="node" />
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { basename, dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type * as Ts from "typescript";

/**
 * The line that opens a TypeScript sample, and the line that closes a fence.
 */
const OPEN = "```ts";
const CLOSE = "```";

/**
 * A `ts` fence of a page: the line of the page that opens it, and its text.
 */
interface Fence {
	opens: number;
	text: string;
}

/**
 * The `ts` fences of the markdown at `page`, each with the line of the page that opens it.
 */
function fencesOf(page: string): Fence[] {
	const lines = readFileSync(page, "utf8").split("\n");
	const fences: Fence[] = [];
	let fence: { opens: number; body: string[] } | undefined;

	for (const [index, line] of lines.entries()) {
		const tag = line.trimEnd();
		if (fence === undefined) {
			if (tag === OPEN) {
				fence = { opens: index + 1, body: [] };
			}
			continue;
		}
		if (tag === CLOSE) {
			fences.push({ opens: fence.opens, text: fence.body.join("\n") });
			fence = undefined;
			continue;
		}

		fence.body.push(line);
	}

	if (fence !== undefined) {
		throw new Error(`${page}:${fence.opens} opens a ts fence that never closes`);
	}
	if (fences.length === 0) {
		throw new Error(`${page} holds no ts fence`);
	}

	return fences;
}

/**
 * The package that compiles the samples of a page. Each path resolves from `suite`, as an import specifier does.
 */
export interface DocSamplesProject {
	/**
	 * The URL of the suite module, whose package resolves `typescript`.
	 */
	suite: string;
	/**
	 * The tsconfig of the samples. Each sample sits in its `rootDir`, or beside the tsconfig.
	 */
	tsconfig: string;
	/**
	 * The source entry of each package that a sample imports.
	 */
	sources?: Readonly<Record<string, string>>;
}

/**
 * A page whose samples compile. Each path resolves from the suite.
 */
interface DocSamplesPage {
	/**
	 * The markdown page that holds the samples.
	 */
	page: string;
	/**
	 * The declarations of the names that the samples of the page take from their surroundings.
	 */
	prelude?: string;
}

/**
 * The compile of the samples of a page under the options of one package. Each fence compiles as a module of its own, in
 * the root of the sources of the package.
 */
export class DocSamples {
	readonly #suite: string;
	readonly #ts: typeof Ts;
	readonly #options: Ts.CompilerOptions;
	readonly #configDiagnostics: readonly Ts.Diagnostic[];
	readonly #root: string;
	readonly #host: Ts.CompilerHost;

	constructor({ suite, tsconfig, sources = {} }: DocSamplesProject) {
		this.#suite = suite;

		const ts: typeof Ts = createRequire(suite)("typescript");
		const project = this.#resolve(tsconfig);
		const parsed = ts.getParsedCommandLineOfConfigFile(
			project,
			{},
			{
				...ts.sys,
				onUnRecoverableConfigFileDiagnostic: (diagnostic) => {
					const message = ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n");
					throw new Error(`${project}: ${message}`);
				},
			},
		);
		if (parsed === undefined) {
			throw new Error(`${project}: the tsconfig does not parse`);
		}

		const paths: Record<string, string[]> = { ...parsed.options.paths };
		for (const [name, entry] of Object.entries(sources)) {
			paths[name] = [this.#resolve(entry)];
		}

		// Each fence is a module, even one with no import of its own.
		this.#options = {
			...parsed.options,
			noEmit: true,
			moduleDetection: ts.ModuleDetectionKind.Force,
			paths,
		};
		this.#ts = ts;
		this.#configDiagnostics = parsed.errors;
		this.#root = parsed.options.rootDir ?? dirname(project);
		this.#host = ts.createCompilerHost(this.#options);
	}

	/**
	 * The diagnostics of the `ts` samples of a page, each one named by its line of the page.
	 *
	 * @throws {Error} When the page holds no `ts` fence, or a fence that never closes.
	 */
	diagnostics({ page, prelude }: DocSamplesPage): string[] {
		const markdown = this.#resolve(page);
		const stem = basename(markdown, extname(markdown));
		const samples = new Map<string, Fence>();
		for (const fence of fencesOf(markdown)) {
			const file = join(this.#root, `${stem}-${fence.opens}.ts`);
			samples.set(file, fence);
		}

		const rootNames = [...samples.keys()];
		if (prelude !== undefined) {
			rootNames.push(this.#resolve(prelude));
		}

		const program = this.#ts.createProgram({
			rootNames,
			options: this.#options,
			host: this.#hostOver(samples),
			configFileParsingDiagnostics: this.#configDiagnostics,
		});
		const found = this.#ts.getPreEmitDiagnostics(program);

		const rendered = found.map((diagnostic) => this.#render(diagnostic, markdown, samples));
		return rendered;
	}

	/**
	 * The file path of `path`, which resolves from the suite as an import specifier does.
	 */
	#resolve(path: string): string {
		const url = new URL(path, this.#suite);
		return fileURLToPath(url);
	}

	/**
	 * The compiler host that reads each sample from its fence and every other file from disk.
	 */
	#hostOver(samples: Map<string, Fence>): Ts.CompilerHost {
		const disk = this.#host;
		const ts = this.#ts;

		return {
			...disk,
			fileExists: (file: string) => samples.has(file) || disk.fileExists(file),
			readFile: (file: string) => samples.get(file)?.text ?? disk.readFile(file),
			getSourceFile: (file, language, onError, shouldCreate) => {
				const sample = samples.get(file);
				if (sample === undefined) {
					return disk.getSourceFile(file, language, onError, shouldCreate);
				}

				return ts.createSourceFile(file, sample.text, language);
			},
		};
	}

	/**
	 * `diagnostic` as one line: the page line of a sample, or the file and line of any other source.
	 */
	#render(diagnostic: Ts.Diagnostic, page: string, samples: Map<string, Fence>): string {
		const ts = this.#ts;
		const message = ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n");
		const code = `TS${diagnostic.code}`;
		const file = diagnostic.file;
		if (file === undefined) {
			return `${code}: ${message}`;
		}

		const start = file.getLineAndCharacterOfPosition(diagnostic.start ?? 0);
		const column = start.character + 1;
		const sample = samples.get(file.fileName);
		if (sample === undefined) {
			return `${file.fileName}:${start.line + 1}:${column} ${code}: ${message}`;
		}

		const line = sample.opens + start.line + 1;
		return `${page}:${line}:${column} ${code}: ${message}`;
	}
}
