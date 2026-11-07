import { runInNewContext } from "node:vm";

import { describe, expect, it } from "vitest";

import type { BodyCompressor } from "../compress.js";
import type { Hasher, Signatory } from "../crypto.js";
import type { FrameBuilder } from "../index.js";
import { Frame } from "../frame.js";
import { ClientTransportError, TightbeamWsClient } from "../index.js";
import { ValidationError } from "./errors.js";

/**
 * Builder spec accumulation and validation, driven end-to-end against the
 * real wasm codec. Frame round-trips through the codec live in `frame.test.ts`.
 */

const engine = await TightbeamWsClient.init();

const BODY = new Uint8Array([1, 2, 3]);
const AEAD_256 = engine.aes256Gcm({
	key: new Uint8Array(32).fill(1),
	keyId: new TextEncoder().encode("tbws/test/kek/v1"),
});
const RECIPIENT = engine.hpkeEncryptor(new Uint8Array(33).fill(2));

/**
 * The octets of a salt long enough to hide the body.
 */
const SALT_OCTETS = new Uint8Array(16).fill(5);

/**
 * 2 to the power 64, one past the range of a frame order or lifetime.
 */
const PAST_U64 = 2n ** 64n;

/**
 * Build `attempt`, requiring it to reject with a {@link ValidationError}, and
 * return the issue paths it reported.
 */
async function validationIssuePathsOf(
	attempt: FrameBuilder,
): Promise<readonly string[]> {
	try {
		await attempt.build();
	} catch (error) {
		if (ValidationError.isInstance(error)) {
			const paths = error.issues.map((issue) => issue.path);
			return paths;
		}

		throw error;
	}

	throw new Error("build() unexpectedly succeeded");
}

/**
 * The bytes 1, 2, and 3 as a `Uint8Array` of another realm, whose
 * `instanceof Uint8Array` answers false here.
 */
const FOREIGN_BODY: Uint8Array = runInNewContext("new Uint8Array([1, 2, 3])");

/**
 * The engine key that signs every prompted signature.
 */
const PROMPTED_KEY = engine.signingKey(new Uint8Array(32).fill(6));

/**
 * The refusal a WebAuthn prompt answers when the person declines it.
 */
const DECLINED = new DOMException("the person declined", "NotAllowedError");

/**
 * A BYO signatory, the shape a WebAuthn or wallet signer takes, which signs
 * with a real engine key once the person approved, and declines before.
 */
class PromptedSigner implements Signatory {
	#approved = false;

	approve(): void {
		this.#approved = true;
	}

	signerId(): Uint8Array {
		return PROMPTED_KEY.signerId();
	}

	signPrehash(prehash: Uint8Array): Promise<Uint8Array> {
		if (!this.#approved) {
			return Promise.reject(DECLINED);
		}

		return PROMPTED_KEY.signPrehash(prehash);
	}
}

describe("FrameBuilder accumulation", () => {
	it("takes raw bytes of another realm as the opaque body", async () => {
		const built = await engine
			.frameBuilder()
			.withMessage(FOREIGN_BODY)
			.build();
		expect(engine.opaque.decode(built.bodyDer)).toEqual(BODY);
	});

	it("is immutable: each withX returns a new builder", () => {
		const base = engine.frameBuilder(BODY);
		const next = base.withOrder(7);
		expect(base.toSpec().order).toBeUndefined();
		expect(next.toSpec().order).toBe(7);
	});

	it("encodes a string id as UTF-8 bytes", () => {
		const spec = engine.frameBuilder(BODY).withId("msg-1").toSpec();
		expect(spec.id).toEqual(new TextEncoder().encode("msg-1"));
	});

	it("keeps an order as given, for the engine to parse at the build", () => {
		const spec = engine.frameBuilder(BODY).withOrder(42).toSpec();
		expect(spec.order).toBe(42);
	});

	it("records every metadata field", () => {
		const digest = new Uint8Array([9, 9]);
		const matrix = new Uint8Array([0, 1, 1, 0]);
		const salt = engine.salt(SALT_OCTETS);
		const contentOid = engine.oid("1.2.840.10045.4.3.4");
		const algorithmOid = engine.oid("2.16.840.1.101.3.4.2.8");
		const previousHash = engine.digestInfo(algorithmOid, digest);
		const messageHasher = engine.sha3_256;
		const witnessHasher = engine.sha3_256;

		const spec = engine
			.frameBuilder(BODY)
			.withVersion(engine.Version.V2)
			.withId("id")
			.withOrder(1)
			.withContentOid(contentOid)
			.withPriority(engine.MessagePriority.LowLatency)
			.withLifetime(60)
			.withPreviousHash(previousHash)
			.withMatrix(2, matrix)
			.withMessageHasher(messageHasher)
			.withCommitment(salt)
			.withWitnessHasher(witnessHasher)
			.toSpec();
		expect(spec.version).toBe(engine.Version.V2);
		expect(spec.contentOid?.toString()).toBe(contentOid.toString());
		expect(spec.previousHash?.digest).toEqual(digest);
		expect(spec.priority).toBe(engine.MessagePriority.LowLatency);
		expect(spec.lifetime).toBe(60);
		expect(spec.matrix).toEqual({ n: 2, data: matrix });

		const messageOid = spec.messageIntegrity?.algorithmOid.toString();
		const witnessOid = spec.frameIntegrity?.algorithmOid.toString();
		expect(messageOid).toBe(messageHasher.algorithmOid.toString());
		expect(witnessOid).toBe(witnessHasher.algorithmOid.toString());
	});

	it.each([
		{ name: "AEAD cipher", encryptor: AEAD_256 },
		{ name: "HPKE encryptor", encryptor: RECIPIENT },
	])("records the $name in the encryptor slot", ({ encryptor }) => {
		const spec = engine
			.frameBuilder(BODY)
			.withEncryptor(encryptor)
			.toSpec();
		expect(spec.encryptor).toBe(encryptor);
	});

	it("engine.frameBuilder() seeds the message body as a deferred opaque encoding", () => {
		const spec = engine.frameBuilder(BODY).toSpec();

		const bodyDer = spec.message?.encodeBody() ?? new Uint8Array();
		const payload = engine.opaque.decode(bodyDer);
		expect(payload).toEqual(BODY);
	});
});

/**
 * A compressor that holds its algorithm handle and keeps the bytes as they
 * are, as a compressor of any library may hold its `Oid`.
 */
const HELD_LABEL: BodyCompressor = {
	algorithmOid: engine.profile.zlib,
	compress: (bodyDer: Uint8Array) => ({ data: bodyDer }),
};

describe("FrameBuilder copies", () => {
	it("a freed custom-hasher Oid still lets the build succeed", async () => {
		const algorithmOid = engine.oid("2.16.840.1.101.3.4.2.8");
		const hasher: Hasher = {
			algorithmOid,
			digest: (data) => engine.sha3_256.digest(data),
		};
		const builder = engine
			.frameBuilder(BODY)
			.withMessageHasher(hasher)
			.withWitnessHasher(hasher);

		algorithmOid.free();

		const built = await builder.build();
		expect(built.messageIntegrity).toBe(true);
		expect(built.frameIntegrity).toBe(true);
	});

	it("two builds in a row through one held engine zstd both succeed", async () => {
		const zstd = engine.zstd();
		const builder = engine.frameBuilder(BODY).withCompressor(zstd);
		await builder.build();

		const second = await builder.build();
		expect(second.compressed).toBe(true);
	});

	it("one compressor that holds its Oid serves two builds in a row", async () => {
		const builder = engine.frameBuilder(BODY).withCompressor(HELD_LABEL);
		await builder.build();

		const second = await builder.build();
		const algorithm = second.compactnessInfo?.algorithmOid;
		expect(algorithm?.equals(HELD_LABEL.algorithmOid)).toBe(true);
	});

	it("a freed content OID leaves the build its own copy", async () => {
		const contentOid = engine.oid("1.2.840.10045.4.3.4");
		const builder = engine
			.frameBuilder(BODY)
			.withContentOid(contentOid)
			.withEncryptor(AEAD_256);

		contentOid.free();

		const built = await builder.build();
		expect(built.confidential).toBe(true);
	});

	it("a freed previous hash leaves the build its own copy", async () => {
		const digest = new Uint8Array([9, 9]);
		const parent = engine.digestInfo(engine.profile.sha3_256, digest);
		const builder = engine.frameBuilder(BODY).withPreviousHash(parent);
		parent.free();

		const built = await builder.build();
		expect(built.previousFrame?.digest).toEqual(digest);
	});
});

describe("FrameBuilder.withCommitment", () => {
	it("a salt disposed after withCommitment still builds", async () => {
		const salt = engine.salt(SALT_OCTETS);
		const builder = engine
			.frameBuilder(BODY)
			.withMessageHasher(engine.sha3_256)
			.withCommitment(salt);
		salt.free();

		const built = await builder.build();
		const disclosed = engine.salt(SALT_OCTETS);
		const verdict = built.messageCommitmentVerdict(disclosed);
		await expect(verdict).resolves.toBe("verified");
	});

	it("a second take or build refuses with CommitmentSpent", async () => {
		const salt = engine.salt(SALT_OCTETS);
		const builder = engine
			.frameBuilder(BODY)
			.withMessageHasher(engine.sha3_256)
			.withCommitment(salt);
		await builder.build();

		const spent = expect.objectContaining({ code: "CommitmentSpent" });
		expect(() => builder.withCommitment(salt)).toThrow(spent);
		await expect(builder.build()).rejects.toThrow(spent);
	});
});

describe("FrameBuilder.build validation", () => {
	interface InvalidCase {
		name: string;
		make: () => FrameBuilder;
		path: string;
	}

	const cases: InvalidCase[] = [
		{
			name: "missing message body",
			make: () => engine.frameBuilder().withOrder(1),
			path: "message",
		},
		{
			name: "version assertion below the derived floor",
			make: () =>
				engine
					.frameBuilder(BODY)
					.withEncryptor(AEAD_256)
					.assertVersion(engine.Version.V0),
			path: "assertedVersion",
		},
		{
			name: "version assertion above the derived floor",
			make: () =>
				engine.frameBuilder(BODY).assertVersion(engine.Version.V2),
			path: "assertedVersion",
		},
		{
			name: "a commitment salt without a message hasher",
			make: () =>
				engine
					.frameBuilder(BODY)
					.withCommitment(engine.salt(SALT_OCTETS)),
			path: "commitment",
		},
	];

	it.each(cases)("rejects $name on field $path", async ({ make, path }) => {
		const paths = await validationIssuePathsOf(make());
		expect(paths).toContain(path);
	});

	it("reports every issue of a spec", async () => {
		const salt = engine.salt(SALT_OCTETS);
		const attempt = engine.frameBuilder().withCommitment(salt);

		const paths = await validationIssuePathsOf(attempt);
		expect(paths).toEqual(["message", "commitment"]);
	});

	it.each([
		{
			name: "a dimension out of range",
			make: () =>
				engine.frameBuilder(BODY).withMatrix(0, new Uint8Array()),
			code: "InvalidMatrixDimension",
			path: "matrix.n",
		},
		{
			name: "data of another length than n * n",
			make: () =>
				engine
					.frameBuilder(BODY)
					.withMatrix(2, new Uint8Array([0, 1, 1])),
			code: "InvalidMatrixData",
			path: "matrix.data",
		},
	])(
		"a matrix refusal names its field path: $name refuses with $code at $path",
		async ({ make, code, path }) => {
			await expect(make().build()).rejects.toMatchObject({ code, path });
		},
	);

	const pinnedBelowFloor = [
		{
			name: "V0 below the aead floor",
			make: () =>
				engine
					.frameBuilder(BODY)
					.withEncryptor(AEAD_256)
					.withVersion(engine.Version.V0),
		},
		{
			name: "V0 below the hpke floor",
			make: () =>
				engine
					.frameBuilder(BODY)
					.withEncryptor(RECIPIENT)
					.withVersion(engine.Version.V0),
		},
		{
			name: "V0 below the message hasher floor",
			make: () =>
				engine
					.frameBuilder(BODY)
					.withMessageHasher(engine.sha3_256)
					.withVersion(engine.Version.V0),
		},
		{
			name: "V1 below the priority floor",
			make: () =>
				engine
					.frameBuilder(BODY)
					.withPriority(engine.MessagePriority.Standard)
					.withVersion(engine.Version.V1),
		},
	];

	it.each(pinnedBelowFloor)(
		"the engine refuses a pin of $name",
		async ({ make }) => {
			await expect(make().build()).rejects.toMatchObject({
				code: "UnsupportedField",
			});
		},
	);

	it.each([
		{
			name: "a negative order",
			make: () => engine.frameBuilder(BODY).withOrder(-1),
			code: "InvalidOrder",
		},
		{
			name: "an order past u64",
			make: () => engine.frameBuilder(BODY).withOrder(PAST_U64),
			code: "InvalidOrder",
		},
		{
			name: "a fractional lifetime",
			make: () => engine.frameBuilder(BODY).withLifetime(1.5),
			code: "InvalidLifetime",
		},
		{
			name: "a lifetime past u64",
			make: () => engine.frameBuilder(BODY).withLifetime(PAST_U64),
			code: "InvalidLifetime",
		},
	])("the engine refuses $name with $code", async ({ make, code }) => {
		await expect(make().build()).rejects.toMatchObject({
			name: ClientTransportError.NAME,
			code,
		});
	});

	it("the engine refuses an empty previous-hash digest", () => {
		const empty = new Uint8Array();
		const refused = (): unknown =>
			engine.digestInfo(engine.profile.sha3_256, empty);

		expect(refused).toThrow(
			expect.objectContaining({
				name: ClientTransportError.NAME,
				code: "EmptyDigest",
			}),
		);
	});

	it("a declined signature rejects the build, and the same builder builds once approved", async () => {
		const signer = new PromptedSigner();
		const builder = engine
			.frameBuilder(BODY)
			.withMessageHasher(engine.sha3_256)
			.withWitnessHasher(engine.sha3_256)
			.withSigner(signer);

		const declined = builder.build();
		await expect(declined).rejects.toMatchObject({
			name: "NotAllowedError",
		});

		signer.approve();

		const built = await builder.build();
		expect(() => built.verify(PROMPTED_KEY.verifyingKey())).not.toThrow();
	});

	it("accepts a version assertion matching the derived floor", async () => {
		const built = engine
			.frameBuilder(BODY)
			.withEncryptor(AEAD_256)
			.assertVersion(engine.Version.V1)
			.build();

		await expect(built).resolves.toBeInstanceOf(Frame);
	});

	it("accepts a version assertion matching an explicit pin", async () => {
		const built = engine
			.frameBuilder(BODY)
			.withVersion(engine.Version.V3)
			.assertVersion(engine.Version.V3)
			.build();

		await expect(built).resolves.toBeInstanceOf(Frame);
	});

	it("accepts a fully specified V3 frame", async () => {
		const matrix = new Uint8Array([0, 1, 1, 0]);
		const built = engine
			.frameBuilder(BODY)
			.withVersion(engine.Version.V3)
			.withId("id")
			.withOrder(1)
			.withPriority(engine.MessagePriority.LowLatency)
			.withLifetime(60)
			.withMatrix(2, matrix)
			.withMessageHasher(engine.sha3_256)
			.withWitnessHasher(engine.sha3_256)
			.build();

		await expect(built).resolves.toBeInstanceOf(Frame);
	});
});
