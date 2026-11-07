import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);

const testsDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(testsDir, "../..");
const messageCodecSource = join(repoRoot, "ws/client/src/message.ts");
const tsc = join(testsDir, "../node_modules/.bin/tsc");

/**
 * The wasm package of the fixture wire types, which `make -C asn test` builds
 * before this suite: the declarations the emitter reads, and the exports the
 * generated codecs bind.
 */
const fixturePackage = join(repoRoot, "target/asn-fixture-package");
const fixtureDts = join(fixturePackage, "asn_fixtures.d.ts");
const fixtureGlue = join(fixturePackage, "asn_fixtures.js");
const fixtureBinary = join(fixturePackage, "asn_fixtures_bg.wasm");

/**
 * The declarations of the ws engine build, which `message.ts` reads as
 * `#wasm`. `make -C asn test` builds the ws client before this suite.
 */
const engineDts = join(repoRoot, "ws/client/wasm/tightbeam_ws_wasm.d.ts");

interface MessageCodec<T> {
	encode(value: T): Uint8Array;
	decode(bodyDer: Uint8Array): T;
}

interface GeneratedCodecs {
	Doc: MessageCodec<{ title: string }>;
	StatusReport: MessageCodec<{ title: string; status: number }>;
}

/**
 * The exports of an initialized wasm module, as the codecs read them.
 */
type AsnModule = Record<string, unknown>;

/**
 * The `AsnCodecs` class of a generated module.
 */
type CodecsClass = new (asn: AsnModule) => GeneratedCodecs;

async function writePackageJson(work: string): Promise<void> {
	const source = { type: "module" };
	await writeFile(
		join(work, "package.json"),
		`${JSON.stringify(source, null, "\t")}\n`,
	);
}

async function writeTsconfig(work: string): Promise<void> {
	const source = {
		compilerOptions: {
			noEmit: true,
			strict: true,
			target: "ES2022",
			lib: ["ES2022", "ESNext.Disposable", "DOM"],
			module: "ESNext",
			moduleResolution: "Bundler",
			skipLibCheck: true,
			types: [],
			paths: {
				"#asn-wasm": [fixtureDts],
				"#wasm": [engineDts],
				"#your-asn-alias": [fixtureDts],
				"@wahidgroup/tightbeam-ws-client": [messageCodecSource],
			},
		},
		files: ["codecs.ts"],
	};
	await writeFile(
		join(work, "tsconfig.json"),
		`${JSON.stringify(source, null, "\t")}\n`,
	);
}

/**
 * The TypeScript sample of the `tightbeam-asn` README quick start, verbatim.
 * Its alias names the web build of the fixture package, whose default export
 * is the `init` of a `wasm-pack` web build.
 */
const README_QUICK_START = `import init, * as asn from "#your-asn-alias";
import { AsnCodecs } from "./codecs.js";

await init();
const codecs = new AsnCodecs(asn);
const bodyDer = codecs.Doc.encode({ title: "hello" });
`;

/**
 * Write the quick start and the project that compiles it against the emitted
 * `codecs.ts`.
 */
async function writeQuickStart(work: string): Promise<void> {
	const project = {
		extends: "./tsconfig.json",
		files: ["quick_start.ts"],
	};
	await writeFile(join(work, "quick_start.ts"), README_QUICK_START);
	await writeFile(
		join(work, "tsconfig.quick-start.json"),
		`${JSON.stringify(project, null, "\t")}\n`,
	);
}

async function seedWorkDir(work: string): Promise<void> {
	await writePackageJson(work);
	await writeTsconfig(work);
}

async function runEmit(work: string): Promise<void> {
	const out = join(work, "codecs.ts");
	await execFileAsync(
		"cargo",
		[
			"run",
			"-p",
			"tightbeam-asn",
			"--features",
			"emit",
			"--bin",
			"tightbeam-asn-emit",
			"--",
			"--from-dts",
			fixtureDts,
			"--out",
			out,
			"--import",
			"#asn-wasm",
			"--message-codec-from",
			"@wahidgroup/tightbeam-ws-client",
		],
		{ cwd: repoRoot },
	);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null;
}

function isMessageCodec(value: unknown): value is MessageCodec<unknown> {
	if (!isRecord(value)) {
		return false;
	}

	return (
		typeof value.encode === "function" && typeof value.decode === "function"
	);
}

function isGeneratedCodecs(value: unknown): value is GeneratedCodecs {
	if (!isRecord(value)) {
		return false;
	}
	if (!isMessageCodec(value.Doc)) {
		return false;
	}
	if (!isMessageCodec(value.StatusReport)) {
		return false;
	}

	return true;
}

function isCodecsClass(value: unknown): value is CodecsClass {
	return typeof value === "function";
}

/**
 * The module the test imports from `path`.
 */
async function importFrom(path: string): Promise<AsnModule> {
	const url = pathToFileURL(path).href;
	const mod: unknown = await import(url);
	if (!isRecord(mod)) {
		throw new Error(`${path} exports no module namespace`);
	}

	return mod;
}

/**
 * The web build of the fixture package, started from its binary.
 */
async function startedFixturePackage(): Promise<AsnModule> {
	const glue = await importFrom(fixtureGlue);
	const start = glue.initSync;
	if (typeof start !== "function") {
		throw new Error("the fixture package exports no initSync");
	}

	const binary = await readFile(fixtureBinary);
	start({ module: binary });
	return glue;
}

/**
 * The codecs of the generated module, bound to `asn`.
 */
function bind(AsnCodecs: CodecsClass, asn: AsnModule): GeneratedCodecs {
	const codecs: unknown = new AsnCodecs(asn);
	if (!isGeneratedCodecs(codecs)) {
		throw new Error("AsnCodecs binds unexpected codecs");
	}

	return codecs;
}

describe("tightbeam-asn-emit", () => {
	let work = "";
	let codecs: GeneratedCodecs;

	beforeAll(async () => {
		work = await mkdtemp(join(tmpdir(), "tightbeam-asn-emit-"));

		await seedWorkDir(work);
		await runEmit(work);

		const generated = await importFrom(join(work, "codecs.ts"));
		if (!isCodecsClass(generated.AsnCodecs)) {
			throw new Error("the generated module exports no AsnCodecs class");
		}

		const asn = await startedFixturePackage();
		codecs = bind(generated.AsnCodecs, asn);
	});

	afterAll(async () => {
		if (work.length > 0) {
			await rm(work, { recursive: true, force: true });
		}
	});

	it("round-trips Doc through MessageCodec.encode/decode", () => {
		const doc = { title: "emit-test" };
		const der = codecs.Doc.encode(doc);
		const round = codecs.Doc.decode(der);
		expect(round).toEqual(doc);
	});

	it("round-trips StatusReport through MessageCodec.encode/decode", () => {
		const report = { title: "emit-test", status: 2 };
		const der = codecs.StatusReport.encode(report);
		const round = codecs.StatusReport.decode(der);
		expect(round).toEqual(report);
	});

	it("typechecks against the real MessageCodec", async () => {
		await execFileAsync(tsc, ["-p", work]);
	}, 60_000);

	it("README quick start compiles against the emitted module", async () => {
		await writeQuickStart(work);

		const project = join(work, "tsconfig.quick-start.json");
		await execFileAsync(tsc, ["-p", project]);
	}, 60_000);
});
