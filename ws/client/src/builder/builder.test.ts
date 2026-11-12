import { runInNewContext } from "node:vm";

import { describe, expect, it } from "vitest";

import type { Hasher } from "../crypto.js";
import type { FrameBuilder } from "../index.js";
import { Frame } from "../frame.js";
import { Engine } from "../index.js";
import { PromptedSigner } from "../testing/prompted_signer.js";
import { ZlibCompression } from "../testing/zlib.js";

/**
 * Builder spec accumulation and validation, driven end-to-end against the
 * real wasm codec. Frame round-trips through the codec live in `frame.test.ts`.
 */

const engine = await Engine.load();

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
 * A builder of {@link BODY} named `id`, ready to build.
 */
function named(id = "frame"): FrameBuilder<true> {
	const builder = engine.frameBuilder(BODY).withId(id);
	return builder;
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

describe("FrameBuilder accumulation", () => {
	it("takes raw bytes of another realm as the opaque body", async () => {
		const built = await engine.frameBuilder(FOREIGN_BODY).withId("frame").build();
		expect(engine.opaque.decode(built.bodyDer)).toEqual(BODY);
	});

	it("is immutable: each withX returns a new builder", async () => {
		const base = named();
		const next = base.withOrder(7);

		const [baseFrame, nextFrame] = await Promise.all([base.build(), next.build()]);
		expect(baseFrame.order).not.toBe(7n);
		expect(nextFrame.order).toBe(7n);
	});

	it("encodes a string id as UTF-8 bytes", async () => {
		const built = await named("msg-1").build();
		expect(built.id).toEqual(new TextEncoder().encode("msg-1"));
	});

	it("installs every metadata field", async () => {
		const digest = new Uint8Array([9, 9]);
		const matrix = new Uint8Array([0, 1, 1, 0]);
		const salt = engine.salt(SALT_OCTETS);
		const contentOid = engine.oid("1.2.840.10045.4.3.4");
		const algorithmOid = engine.oid("2.16.840.1.101.3.4.2.8");
		const previousHash = engine.digestInfo(algorithmOid, digest);
		const messageHasher = engine.sha3_256;
		const witnessHasher = engine.sha3_256;

		const built = await named()
			.withVersion(engine.Version.V3)
			.withOrder(1)
			.withContentOid(contentOid)
			.withPriority(engine.MessagePriority.LowLatency)
			.withLifetime(60)
			.withPreviousHash(previousHash)
			.withMatrix(2, matrix)
			.withMessageHasher(messageHasher, salt)
			.withEncryptor(AEAD_256)
			.withWitnessHasher(witnessHasher)
			.build();
		expect(built.version).toBe(engine.Version.V3);
		expect(built.order).toBe(1n);
		expect(built.confidentialityInfo?.contentOid.toString()).toBe(contentOid.toString());
		expect(built.previousFrame?.digest).toEqual(digest);
		expect(built.priority).toBe(engine.MessagePriority.LowLatency);
		expect(built.lifetime).toBe(60n);
		expect(built.matrix).toEqual({ n: 2, data: matrix });

		const messageOid = built.messageIntegrityInfo?.algorithmOid.toString();
		const witnessOid = built.frameIntegrityInfo?.algorithmOid.toString();
		expect(messageOid).toBe(messageHasher.algorithmOid.toString());
		expect(witnessOid).toBe(witnessHasher.algorithmOid.toString());
	});

	it.each([
		{ name: "AEAD cipher", encryptor: AEAD_256 },
		{ name: "HPKE encryptor", encryptor: RECIPIENT },
	])("seals the body with the $name", async ({ encryptor }) => {
		const built = await named().withEncryptor(encryptor).build();
		expect(built.confidentialityInfo?.algorithmOid.toString()).toBe(engine.profile.aes256Gcm.toString());
	});

	it("engine.frameBuilder(bytes) carries the bytes under the opaque wrapper", async () => {
		const built = await named().build();

		const payload = engine.opaque.decode(built.bodyDer);
		expect(payload).toEqual(BODY);
	});

	it("engine.messageBuilder carries the DER the codec encodes", async () => {
		const built = await engine.messageBuilder(engine.opaque, BODY).withId("frame").build();

		await expect(built.open(engine.opaque)).resolves.toEqual(BODY);
	});

	it("refuses a frame without an id for an untyped caller", async () => {
		const unnamed = engine.frameBuilder(BODY);

		const building: unknown = Reflect.apply(unnamed.build, unnamed, []);
		await expect(building).rejects.toMatchObject({ code: "BuildError" });
	});
});

/**
 * A compression of the platform, which holds the profile `Oid` as a
 * compressor of any library may hold its algorithm.
 */
const ZLIB = new ZlibCompression(engine);

describe("FrameBuilder copies", () => {
	it("a freed custom-hasher Oid still lets the build succeed", async () => {
		const algorithmOid = engine.oid("2.16.840.1.101.3.4.2.8");
		const hasher: Hasher = {
			algorithmOid,
			digest: (data) => engine.sha3_256.digest(data),
		};
		const builder = named().withMessageHasher(hasher).withWitnessHasher(hasher);

		algorithmOid.free();

		const built = await builder.build();
		expect(built.messageIntegrity).toBe(true);
		expect(built.frameIntegrity).toBe(true);
	});

	it("two builds in a row through one held engine zstd both succeed", async () => {
		const zstd = engine.zstd();
		const builder = named().withCompressor(zstd);
		await builder.build();

		const second = await builder.build();
		expect(second.compressed).toBe(true);
	});

	it("one compressor that holds its Oid serves two builds in a row", async () => {
		const builder = named().withCompressor(ZLIB);
		await builder.build();

		const second = await builder.build();
		const algorithm = second.compactnessInfo?.algorithmOid;
		expect(algorithm?.equals(ZLIB.algorithmOid)).toBe(true);
	});

	it("a freed content OID leaves the build its own copy", async () => {
		const contentOid = engine.oid("1.2.840.10045.4.3.4");
		const builder = named().withContentOid(contentOid).withEncryptor(AEAD_256);

		contentOid.free();

		const built = await builder.build();
		expect(built.confidential).toBe(true);
	});

	it("a freed previous hash leaves the build its own copy", async () => {
		const digest = new Uint8Array([9, 9]);
		const parent = engine.digestInfo(engine.profile.sha3_256, digest);
		const builder = named().withPreviousHash(parent);
		parent.free();

		const built = await builder.build();
		expect(built.previousFrame?.digest).toEqual(digest);
	});
});

describe("FrameBuilder byte inputs", () => {
	it("keeps the id it received when the caller writes to the array", async () => {
		const id = new TextEncoder().encode("kept");
		const builder = engine.frameBuilder(BODY).withId(id);
		id.fill(0);

		const built = await builder.build();
		expect(built.id).toEqual(new TextEncoder().encode("kept"));
	});

	it("keeps the matrix it received when the caller writes to the array", async () => {
		const data = new Uint8Array([0, 1, 1, 0]);
		const builder = named().withMatrix(2, data);
		data.fill(7);

		const built = await builder.build();
		expect(built.matrix).toEqual({ n: 2, data: new Uint8Array([0, 1, 1, 0]) });
	});
});

describe("FrameBuilder.withMessageHasher under a salt", () => {
	it("a salt disposed after withMessageHasher still builds", async () => {
		const salt = engine.salt(SALT_OCTETS);
		const builder = named().withMessageHasher(engine.sha3_256, salt);
		salt.free();

		const built = await builder.build();
		const disclosed = engine.salt(SALT_OCTETS);
		const verdict = built.messageCommitmentVerdict(disclosed);
		await expect(verdict).resolves.toBe("verified");
	});

	it("a second take or build refuses with CommitmentSpent", async () => {
		const salt = engine.salt(SALT_OCTETS);
		const builder = named().withMessageHasher(engine.sha3_256, salt);
		await builder.build();

		const spent = expect.objectContaining({ code: "CommitmentSpent" });
		expect(() => builder.withMessageHasher(engine.sha3_256, salt)).toThrow(spent);
		await expect(builder.build()).rejects.toThrow(spent);
	});

	it("a hasher that withMessageHasher refuses leaves the salt to the retry, which builds", async () => {
		const salt = engine.salt(SALT_OCTETS);
		const algorithmOid = engine.oid("2.16.840.1.101.3.4.2.8");
		const hasher: Hasher = {
			algorithmOid,
			digest: (data) => engine.sha3_256.digest(data),
		};
		algorithmOid.free();
		expect(() => named().withMessageHasher(hasher, salt)).toThrow("null pointer passed to rust");

		const built = await named().withMessageHasher(engine.sha3_256, salt).build();
		const disclosed = engine.salt(SALT_OCTETS);
		const verdict = built.messageCommitmentVerdict(disclosed);
		await expect(verdict).resolves.toBe("verified");
	});
});

describe("FrameBuilder.build validation", () => {
	it.each([
		{
			name: "below the derived floor",
			make: () => named().withEncryptor(AEAD_256).assertVersion(engine.Version.V0),
		},
		{
			name: "above the derived floor",
			make: () => named().assertVersion(engine.Version.V2),
		},
	])("refuses a version assertion $name", async ({ make }) => {
		await expect(make().build()).rejects.toMatchObject({
			code: "VersionMismatch",
		});
	});

	it.each([
		{
			name: "a dimension out of range",
			make: () => named().withMatrix(0, new Uint8Array()),
			code: "InvalidMatrixDimension",
			path: "matrix.n",
		},
		{
			name: "data of another length than n * n",
			make: () => named().withMatrix(2, new Uint8Array([0, 1, 1])),
			code: "InvalidMatrixData",
			path: "matrix.data",
		},
	])("a matrix refusal names its field path: $name refuses with $code at $path", async ({ make, code, path }) => {
		await expect(make().build()).rejects.toMatchObject({ code, path });
	});

	const pinnedBelowFloor = [
		{
			name: "V0 below the aead floor",
			make: () => named().withEncryptor(AEAD_256).withVersion(engine.Version.V0),
		},
		{
			name: "V0 below the hpke floor",
			make: () => named().withEncryptor(RECIPIENT).withVersion(engine.Version.V0),
		},
		{
			name: "V0 below the message hasher floor",
			make: () => named().withMessageHasher(engine.sha3_256).withVersion(engine.Version.V0),
		},
		{
			name: "V1 below the priority floor",
			make: () => named().withPriority(engine.MessagePriority.Standard).withVersion(engine.Version.V1),
		},
	];

	it.each(pinnedBelowFloor)("the engine refuses a pin of $name", async ({ make }) => {
		await expect(make().build()).rejects.toMatchObject({
			code: "UnsupportedField",
		});
	});

	it.each([
		{
			name: "a negative order",
			make: () => named().withOrder(-1),
			code: "InvalidOrder",
		},
		{
			name: "an order past u64",
			make: () => named().withOrder(PAST_U64),
			code: "InvalidOrder",
		},
		{
			name: "a fractional lifetime",
			make: () => named().withLifetime(1.5),
			code: "InvalidLifetime",
		},
		{
			name: "a lifetime past u64",
			make: () => named().withLifetime(PAST_U64),
			code: "InvalidLifetime",
		},
	])("the engine refuses $name with $code", async ({ make, code }) => {
		await expect(make().build()).rejects.toMatchObject({
			name: "TightbeamTransportError",
			code,
		});
	});

	it("the engine refuses an empty previous-hash digest", () => {
		const empty = new Uint8Array();
		const refused = (): unknown => engine.digestInfo(engine.profile.sha3_256, empty);

		expect(refused).toThrow(
			expect.objectContaining({
				name: "TightbeamTransportError",
				code: "EmptyDigest",
			}),
		);
	});

	it("a declined signature rejects the build, and the same builder builds once approved", async () => {
		const signer = new PromptedSigner(PROMPTED_KEY);
		const builder = named()
			.withMessageHasher(engine.sha3_256)
			.withWitnessHasher(engine.sha3_256)
			.withSigner(signer);

		const declined = builder.build();
		await expect(declined).rejects.toMatchObject({
			name: "NotAllowedError",
		});

		signer.approve();

		const built = await builder.build();
		await expect(built.verify(PROMPTED_KEY.verifyingKey())).resolves.toBeUndefined();
	});

	it("a declined signature leaves the salt to the retry, which builds once approved", async () => {
		const signer = new PromptedSigner(PROMPTED_KEY);
		const salt = engine.salt(SALT_OCTETS);
		const builder = named().withMessageHasher(engine.sha3_256, salt).withSigner(signer);

		await expect(builder.build()).rejects.toMatchObject({
			name: "NotAllowedError",
		});

		signer.approve();

		const built = await builder.build();
		const disclosed = engine.salt(SALT_OCTETS);
		await expect(built.messageCommitmentVerdict(disclosed)).resolves.toBe("verified");
	});

	it("a build holds the salt from its start, so a concurrent build refuses before its signer prompts", async () => {
		const signer = new PromptedSigner(PROMPTED_KEY);
		const salt = engine.salt(SALT_OCTETS);
		const builder = named().withMessageHasher(engine.sha3_256, salt).withSigner(signer);
		const spent = { status: "rejected", reason: { code: "CommitmentSpent" } };

		const declined = await Promise.allSettled([builder.build(), builder.build()]);
		expect(declined).toMatchObject([{ status: "rejected", reason: { name: "NotAllowedError" } }, spent]);

		signer.approve();
		const approved = await Promise.allSettled([builder.build(), builder.build()]);
		expect(approved).toMatchObject([{ status: "fulfilled" }, spent]);
		await expect(builder.build()).rejects.toMatchObject({ code: "CommitmentSpent" });
	});

	it("accepts a version assertion matching the derived floor", async () => {
		const built = engine
			.frameBuilder(BODY)
			.withId("frame")
			.withEncryptor(AEAD_256)
			.assertVersion(engine.Version.V1)
			.build();

		await expect(built).resolves.toBeInstanceOf(Frame);
	});

	it("accepts a version assertion matching an explicit pin", async () => {
		const built = engine
			.frameBuilder(BODY)
			.withId("frame")
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
