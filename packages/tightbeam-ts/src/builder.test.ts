import { describe, expect, it } from "vitest";

import { ValidationError } from "@wahidgroup/typing-ts";

import type { FrameCodec } from "./codec.js";
import type { FrameSpec } from "./spec.js";
import { FrameBuilder, frame } from "./builder.js";

/**
 * A real, deterministic codec used to drive the builder end-to-end without a
 * WebAssembly backend: it records the last spec it assembled and returns a
 * stable byte encoding (the JSON of the spec's shape).
 */
class RecordingCodec implements FrameCodec {
	last: FrameSpec | undefined;

	compose(spec: FrameSpec): Uint8Array {
		this.last = spec;

		const shape = {
			version: spec.version ?? null,
			hasMessage: spec.message !== undefined,
			order: spec.order === undefined ? null : spec.order.toString(),
		};

		return new TextEncoder().encode(JSON.stringify(shape));
	}
}

const BODY = new Uint8Array([1, 2, 3]);

function builder(): FrameBuilder {
	return new FrameBuilder(new RecordingCodec());
}

describe("FrameBuilder accumulation", () => {
	it("is immutable: each withX returns a new builder", () => {
		const base = builder().withMessage(BODY);
		const next = base.withOrder(7);

		expect(base.toSpec().order).toBeUndefined();
		expect(next.toSpec().order).toBe(7n);
	});

	it("encodes a string id as UTF-8 bytes", () => {
		const spec = builder().withMessage(BODY).withId("msg-1").toSpec();
		expect(spec.id).toEqual(new TextEncoder().encode("msg-1"));
	});

	it("coerces a number order to bigint", () => {
		const spec = builder().withMessage(BODY).withOrder(42).toSpec();
		expect(spec.order).toBe(42n);
	});

	it("records every metadata field", () => {
		const digest = new Uint8Array([9, 9]);
		const matrix = new Uint8Array([0, 1, 1, 0]);
		const spec = builder()
			.withVersion("V2")
			.withMessage(BODY)
			.withId("id")
			.withOrder(1)
			.withContentOid("1.2.840.10045.4.3.4")
			.withPriority("LowLatency")
			.withLifetime(60)
			.withPreviousHash({
				algorithmOid: "2.16.840.1.101.3.4.2.8",
				digest,
			})
			.withMatrix(2, matrix)
			.withMessageHasher()
			.withWitnessHasher()
			.toSpec();

		expect(spec.version).toBe("V2");
		expect(spec.priority).toBe("LowLatency");
		expect(spec.lifetimeSecs).toBe(60n);
		expect(spec.matrix).toEqual({ n: 2, data: matrix });
		expect(spec.messageIntegrity).toEqual({});
		expect(spec.frameIntegrity).toBe(true);
	});

	it("frame() seeds the message body", () => {
		const spec = frame(new RecordingCodec(), BODY).toSpec();
		expect(spec.message).toEqual(BODY);
	});
});

describe("FrameBuilder.build delegation", () => {
	it("passes the validated spec to the codec and returns its bytes", () => {
		const codec = new RecordingCodec();
		const der = frame(codec, BODY).withOrder(5).build();
		expect(codec.last?.order).toBe(5n);

		const decoded: unknown = JSON.parse(new TextDecoder().decode(der));
		expect(decoded).toEqual({
			version: null,
			hasMessage: true,
			order: "5",
		});
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
			make: () => builder().withOrder(1),
			path: "message",
		},
		{
			name: "matrix data length mismatch",
			make: () =>
				builder()
					.withMessage(BODY)
					.withMatrix(2, new Uint8Array([0, 1, 1])),
			path: "matrix.data",
		},
		{
			name: "matrix n out of range",
			make: () =>
				builder().withMessage(BODY).withMatrix(0, new Uint8Array()),
			path: "matrix.n",
		},
		{
			name: "content oid not dotted",
			make: () =>
				builder().withMessage(BODY).withContentOid("not-an-oid"),
			path: "contentOid",
		},
		{
			name: "previous-hash empty digest",
			make: () =>
				builder().withMessage(BODY).withPreviousHash({
					algorithmOid: "2.16.840.1.101.3.4.2.8",
					digest: new Uint8Array(),
				}),
			path: "previousHash.digest",
		},
		{
			name: "secp256k1 key wrong length",
			make: () =>
				builder().withMessage(BODY).withSigner(new Uint8Array(31)),
			path: "signer.keyBytes",
		},
		{
			name: "explicit version below feature floor",
			make: () =>
				builder()
					.withMessage(BODY)
					.withPriority("Standard")
					.withVersion("V1"),
			path: "version",
		},
		{
			name: "negative order out of u64 range",
			make: () => builder().withMessage(BODY).withOrder(-1),
			path: "order",
		},
	];

	it.each(cases)("rejects $name on field $path", ({ make, path }) => {
		let caught: unknown;
		try {
			make().build();
		} catch (error) {
			caught = error;
		}

		expect(ValidationError.isInstance(caught)).toBe(true);
		if (!ValidationError.isInstance(caught)) {
			/**
			 * Simply ensures following `caught` is narrowed to ValidationError.
			 */
			return;
		}

		const paths = caught.issues.map((issue) => issue.path);
		expect(paths).toContain(path);
	});

	it("accepts a fully specified V3 frame", () => {
		const matrix = new Uint8Array([0, 1, 1, 0]);
		expect(() =>
			builder()
				.withVersion("V3")
				.withMessage(BODY)
				.withId("id")
				.withOrder(1)
				.withPriority("LowLatency")
				.withLifetime(60)
				.withMatrix(2, matrix)
				.withMessageHasher()
				.withWitnessHasher()
				.build(),
		).not.toThrow();
	});
});
