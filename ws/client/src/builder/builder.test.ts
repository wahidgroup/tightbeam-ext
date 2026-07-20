import type { FrameBuilder } from "./builder.js";
import { describe, expect, it } from "vitest";

import { Aes256Gcm, EciesEncryptor, Sha3_256 } from "../crypto.js";
import { Frame } from "../frame.js";
import { frame, initClient } from "../index.js";
import { ValidationError } from "./errors.js";
import { MessagePriority } from "./priority.js";
import { Version } from "./version.js";

/**
 * Builder spec accumulation and validation, driven end-to-end against the
 * real wasm codec. Frame round-trips through the codec live in `frame.test.ts`.
 */

const BODY = new Uint8Array([1, 2, 3]);
const AEAD_256 = Aes256Gcm.fromKey(new Uint8Array(32).fill(1));
const RECIPIENT = EciesEncryptor.fromBytes(new Uint8Array(33).fill(2));

await initClient();

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

describe("FrameBuilder accumulation", () => {
	it("is immutable: each withX returns a new builder", () => {
		const base = frame(BODY);
		const next = base.withOrder(7);
		expect(base.toSpec().order).toBeUndefined();
		expect(next.toSpec().order).toBe(7n);
	});

	it("encodes a string id as UTF-8 bytes", () => {
		const spec = frame(BODY).withId("msg-1").toSpec();
		expect(spec.id).toEqual(new TextEncoder().encode("msg-1"));
	});

	it("coerces a number order to bigint", () => {
		const spec = frame(BODY).withOrder(42).toSpec();
		expect(spec.order).toBe(42n);
	});

	it("records every metadata field", () => {
		const digest = new Uint8Array([9, 9]);
		const matrix = new Uint8Array([0, 1, 1, 0]);
		const salt = new Uint8Array([5]);
		const messageHasher = new Sha3_256();
		const witnessHasher = new Sha3_256();
		const spec = frame(BODY)
			.withVersion(Version.V2)
			.withId("id")
			.withOrder(1)
			.withContentOid("1.2.840.10045.4.3.4")
			.withPriority(MessagePriority.LowLatency)
			.withLifetime(60)
			.withPreviousHash({
				algorithmOid: "2.16.840.1.101.3.4.2.8",
				digest,
			})
			.withMatrix(2, matrix)
			.withMessageHasher(messageHasher, salt)
			.withWitnessHasher(witnessHasher)
			.toSpec();

		expect(spec.version).toBe(Version.V2);
		expect(spec.priority).toBe(MessagePriority.LowLatency);
		expect(spec.lifetime).toBe(60n);
		expect(spec.matrix).toEqual({ n: 2, data: matrix });
		expect(spec.messageIntegrity).toEqual({
			hasher: messageHasher,
			salt,
		});
		expect(spec.frameIntegrity).toBe(witnessHasher);
	});

	it.each([
		{ name: "AEAD cipher", encryptor: AEAD_256 },
		{ name: "ECIES encryptor", encryptor: RECIPIENT },
	])("records the $name in the encryptor slot", ({ encryptor }) => {
		const spec = frame(BODY).withEncryptor(encryptor).toSpec();
		expect(spec.encryptor).toBe(encryptor);
	});

	it("frame() seeds the message body", () => {
		const spec = frame(BODY).toSpec();
		expect(spec.message).toEqual(BODY);
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
			make: () => frame().withOrder(1),
			path: "message",
		},
		{
			name: "matrix data length mismatch",
			make: () => frame(BODY).withMatrix(2, new Uint8Array([0, 1, 1])),
			path: "matrix.data",
		},
		{
			name: "matrix n out of range",
			make: () => frame(BODY).withMatrix(0, new Uint8Array()),
			path: "matrix.n",
		},
		{
			name: "content oid not dotted",
			make: () => frame(BODY).withContentOid("not-an-oid"),
			path: "contentOid",
		},
		{
			name: "previous-hash empty digest",
			make: () =>
				frame(BODY).withPreviousHash({
					algorithmOid: "2.16.840.1.101.3.4.2.8",
					digest: new Uint8Array(),
				}),
			path: "previousHash.digest",
		},
		{
			name: "explicit V0 below aead floor",
			make: () =>
				frame(BODY).withEncryptor(AEAD_256).withVersion(Version.V0),
			path: "version",
		},
		{
			name: "explicit V0 below encryptor floor",
			make: () =>
				frame(BODY).withEncryptor(RECIPIENT).withVersion(Version.V0),
			path: "version",
		},
		{
			name: "explicit version below feature floor",
			make: () =>
				frame(BODY)
					.withPriority(MessagePriority.Standard)
					.withVersion(Version.V1),
			path: "version",
		},
		{
			name: "version assertion below the derived floor",
			make: () =>
				frame(BODY).withEncryptor(AEAD_256).assertVersion(Version.V0),
			path: "assertedVersion",
		},
		{
			name: "version assertion above the derived floor",
			make: () => frame(BODY).assertVersion(Version.V2),
			path: "assertedVersion",
		},
		{
			name: "negative order out of u64 range",
			make: () => frame(BODY).withOrder(-1),
			path: "order",
		},
	];

	it.each(cases)("rejects $name on field $path", async ({ make, path }) => {
		const paths = await validationIssuePathsOf(make());
		expect(paths).toContain(path);
	});

	it("accepts a version assertion matching the derived floor", async () => {
		const built = frame(BODY)
			.withEncryptor(AEAD_256)
			.assertVersion(Version.V1)
			.build();

		await expect(built).resolves.toBeInstanceOf(Frame);
	});

	it("accepts a version assertion matching an explicit pin", async () => {
		const built = frame(BODY)
			.withVersion(Version.V3)
			.assertVersion(Version.V3)
			.build();

		await expect(built).resolves.toBeInstanceOf(Frame);
	});

	it("accepts a fully specified V3 frame", async () => {
		const matrix = new Uint8Array([0, 1, 1, 0]);
		const built = frame(BODY)
			.withVersion(Version.V3)
			.withId("id")
			.withOrder(1)
			.withPriority(MessagePriority.LowLatency)
			.withLifetime(60)
			.withMatrix(2, matrix)
			.withMessageHasher(new Sha3_256())
			.withWitnessHasher(new Sha3_256())
			.build();

		await expect(built).resolves.toBeInstanceOf(Frame);
	});
});
