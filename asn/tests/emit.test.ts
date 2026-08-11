import { execFile } from "node:child_process";
import { copyFile, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);

const testsDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(testsDir, "../..");
const rustFixtures = join(testsDir, "../tightbeam-asn/tests/fixtures");
const localFixtures = join(testsDir, "fixtures");

interface MessageCodec<T> {
	encode(value: T): Uint8Array;
	decode(bodyDer: Uint8Array): T;
}

interface GeneratedCodecs {
	Doc: MessageCodec<{ title: string }>;
	StatusReport: MessageCodec<{ status: number }>;
	encodeAsn<T>(codec: MessageCodec<T>, value: T): Promise<Uint8Array>;
	decodeAsn<T>(codec: MessageCodec<T>, bodyDer: Uint8Array): Promise<T>;
	Orphan?: MessageCodec<unknown>;
}

async function writePackageJson(work: string): Promise<void> {
	const source = {
		type: "module",
		imports: {
			"#apollyon-asn": "./stub_apollyon_asn.ts",
			"@wahidgroup/tightbeam-ws-client": "./stub_ws_client.ts",
		},
	};
	await writeFile(
		join(work, "package.json"),
		`${JSON.stringify(source, null, "\t")}\n`,
	);
}

async function seedWorkDir(work: string): Promise<void> {
	await writePackageJson(work);
	await copyFile(
		join(rustFixtures, "sample.d.ts"),
		join(work, "sample.d.ts"),
	);
	await copyFile(
		join(localFixtures, "stub_apollyon_asn.ts"),
		join(work, "stub_apollyon_asn.ts"),
	);
	await copyFile(join(localFixtures, "asnInit.ts"), join(work, "asnInit.ts"));
	await copyFile(
		join(localFixtures, "stub_ws_client.ts"),
		join(work, "stub_ws_client.ts"),
	);
}

async function runEmit(work: string): Promise<void> {
	const fromDts = join(work, "sample.d.ts");
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
			fromDts,
			"--out",
			out,
			"--import",
			"#apollyon-asn",
			"--init-import",
			"./asnInit.js",
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
	if (typeof value.encodeAsn !== "function") {
		return false;
	}
	if (typeof value.decodeAsn !== "function") {
		return false;
	}

	return true;
}

function isAsnInitModule(value: unknown): value is {
	resetInit: () => void;
	wasInitialized: () => boolean;
} {
	if (!isRecord(value)) {
		return false;
	}

	return (
		typeof value.resetInit === "function" &&
		typeof value.wasInitialized === "function"
	);
}

async function loadGeneratedCodecs(work: string): Promise<GeneratedCodecs> {
	const mod: unknown = await import(
		pathToFileURL(join(work, "codecs.ts")).href
	);
	if (!isGeneratedCodecs(mod)) {
		throw new Error("generated codecs module has unexpected exports");
	}

	return mod;
}

describe("tightbeam-asn-emit", () => {
	let work = "";
	let codecs: GeneratedCodecs;
	let resetInit: () => void;
	let wasInitialized: () => boolean;

	beforeAll(async () => {
		work = await mkdtemp(join(tmpdir(), "tightbeam-asn-emit-"));

		await seedWorkDir(work);
		await runEmit(work);

		codecs = await loadGeneratedCodecs(work);
		const init: unknown = await import(
			pathToFileURL(join(work, "asnInit.ts")).href
		);
		if (!isAsnInitModule(init)) {
			throw new Error("asnInit module has unexpected exports");
		}

		resetInit = init.resetInit;
		wasInitialized = init.wasInitialized;
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
		const status = { status: 42 };
		const der = codecs.StatusReport.encode(status);
		const round = codecs.StatusReport.decode(der);
		expect(round).toEqual(status);
	});

	it("calls ensureAsnInit from encodeAsn and decodeAsn", async () => {
		resetInit();
		const doc = { title: "init-gate" };

		if (wasInitialized()) {
			throw new Error("ensureAsnInit must not run before encodeAsn");
		}

		const der = await codecs.encodeAsn(codecs.Doc, doc);
		if (!wasInitialized()) {
			throw new Error("encodeAsn must call ensureAsnInit");
		}

		const round = await codecs.decodeAsn(codecs.Doc, der);
		if (!wasInitialized()) {
			throw new Error("decodeAsn must call ensureAsnInit");
		}

		expect(round).toEqual(doc);
	});

	it("does not export codecs for unpaired wasm encode functions", () => {
		expect(codecs.Orphan).toBeUndefined();
	});
});
