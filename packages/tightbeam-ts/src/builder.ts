/**
 * A fluent, immutable builder for tightbeam frames.
 * The method surface mimics the Rust `FrameBuilder` API.
 */

import type { ValidationIssue } from "@wahidgroup/typing-ts";
import { ValidationError } from "@wahidgroup/typing-ts";

import type { FrameCodec } from "./codec.js";
import type {
	FrameSpec,
	LocalSignerScheme,
	MatrixSpec,
	MessageIntegritySpec,
	PreviousHashSpec,
} from "./spec.js";
import type { FrameVersion } from "./version.js";
import type { MessagePriority } from "./priority.js";
import { versionOrdinal } from "./version.js";

/**
 * Largest value representable by the on-the-wire `INTEGER` (u64).
 */
const U64_MAX = 2n ** 64n - 1n;

/**
 * secp256k1 private keys are 32 octets.
 */
const SECP256K1_KEY_LEN = 32;

/**
 * Matches a dotted object identifier such as `1.2.840.10045.4.3.4`.
 */
const OID_PATTERN = /^\d+(?:\.\d+)+$/;

/**
 * UTF-8 encoder.
 */
const UTF8 = new TextEncoder();

/**
 * Coerces a `Uint8Array | string` into bytes, encoding strings as UTF-8.
 */
function toBytes(value: Uint8Array | string): Uint8Array {
	if (typeof value === "string") {
		return UTF8.encode(value);
	}

	return value;
}

/**
 * Coerces a `bigint | number` into a `bigint`.
 */
function toBigInt(value: bigint | number): bigint {
	if (typeof value === "number") {
		return BigInt(value);
	}

	return value;
}

/**
 * The minimum version that admits the fields present in `spec`.
 */
function requiredVersion(spec: FrameSpec): FrameVersion {
	if (spec.matrix !== undefined) {
		return "V3";
	}

	if (
		spec.messageIntegrity !== undefined ||
		spec.frameIntegrity === true ||
		spec.priority !== undefined ||
		spec.lifetimeSecs !== undefined ||
		spec.previousHash !== undefined
	) {
		return "V2";
	}

	if (spec.signer !== undefined) {
		return "V1";
	}

	return "V0";
}

/**
 * Collects every structural issue in `spec` (empty when valid).
 */
function collectIssues(spec: FrameSpec): ValidationIssue[] {
	const issues: ValidationIssue[] = [];

	if (spec.message === undefined) {
		issues.push({
			path: "message",
			message: "Missing required field: message",
		});
	}
	if (spec.order !== undefined) {
		validateU64(spec.order, "order", issues);
	}
	if (spec.lifetimeSecs !== undefined) {
		validateU64(spec.lifetimeSecs, "lifetimeSecs", issues);
	}
	if (spec.contentOid !== undefined && !OID_PATTERN.test(spec.contentOid)) {
		issues.push({
			path: "contentOid",
			message: `Field contentOid must be a dotted OID, got ${spec.contentOid}`,
		});
	}
	if (spec.matrix !== undefined) {
		validateMatrix(spec.matrix, issues);
	}
	if (spec.previousHash !== undefined) {
		validatePreviousHash(spec.previousHash, issues);
	}
	if (spec.signer !== undefined) {
		validateSigner(spec.signer.scheme, spec.signer.keyBytes, issues);
	}
	if (spec.version !== undefined) {
		validateVersionFloor(spec.version, spec, issues);
	}

	return issues;
}

function validateU64(
	value: bigint,
	path: string,
	issues: ValidationIssue[],
): void {
	if (value < 0n || value > U64_MAX) {
		issues.push({
			path,
			message: `Field ${path} must be in 0..=2^64-1, got ${value}`,
		});
	}
}

function validateMatrix(matrix: MatrixSpec, issues: ValidationIssue[]): void {
	if (!Number.isInteger(matrix.n) || matrix.n < 1 || matrix.n > 255) {
		issues.push({
			path: "matrix.n",
			message: `Field matrix.n must be an integer in 1..=255, got ${matrix.n}`,
		});
		return;
	}

	const expected = matrix.n * matrix.n;
	if (matrix.data.length !== expected) {
		issues.push({
			path: "matrix.data",
			message: `Field matrix.data must be exactly n*n (${expected}) octets, got ${matrix.data.length}`,
		});
	}
}

function validatePreviousHash(
	previousHash: PreviousHashSpec,
	issues: ValidationIssue[],
): void {
	if (!OID_PATTERN.test(previousHash.algorithmOid)) {
		issues.push({
			path: "previousHash.algorithmOid",
			message: `Field previousHash.algorithmOid must be a dotted OID, got ${previousHash.algorithmOid}`,
		});
	}

	if (previousHash.digest.length === 0) {
		issues.push({
			path: "previousHash.digest",
			message: "Field previousHash.digest must be non-empty",
		});
	}
}

function validateSigner(
	scheme: LocalSignerScheme,
	keyBytes: Uint8Array,
	issues: ValidationIssue[],
): void {
	if (scheme === "secp256k1" && keyBytes.length !== SECP256K1_KEY_LEN) {
		issues.push({
			path: "signer.keyBytes",
			message: `Field signer.keyBytes must be ${SECP256K1_KEY_LEN} octets for secp256k1, got ${keyBytes.length}`,
		});
	}
}

function validateVersionFloor(
	version: FrameVersion,
	spec: FrameSpec,
	issues: ValidationIssue[],
): void {
	const floor = requiredVersion(spec);
	if (versionOrdinal(version) < versionOrdinal(floor)) {
		issues.push({
			path: "version",
			message: `Field version ${version} is below the floor ${floor} required by the requested fields`,
		});
	}
}

/**
 * A fluent builder over an injected {@link FrameCodec}.
 */
export class FrameBuilder {
	private readonly codec: FrameCodec;
	private readonly spec: FrameSpec;

	constructor(codec: FrameCodec, spec: FrameSpec = {}) {
		this.codec = codec;
		this.spec = spec;
	}

	private with(patch: Partial<FrameSpec>): FrameBuilder {
		return new FrameBuilder(this.codec, { ...this.spec, ...patch });
	}

	/**
	 * Set the explicit protocol version.
	 */
	withVersion(version: FrameVersion): FrameBuilder {
		return this.with({ version });
	}

	/**
	 * Set the opaque message identifier.
	 */
	withId(id: Uint8Array | string): FrameBuilder {
		return this.with({ id: toBytes(id) });
	}

	/**
	 * Set the monotonic order (Unix seconds).
	 */
	withOrder(order: bigint | number): FrameBuilder {
		return this.with({ order: toBigInt(order) });
	}

	/**
	 * Set the opaque message body.
	 */
	withMessage(message: Uint8Array): FrameBuilder {
		return this.with({ message });
	}

	/**
	 * Set the body content-type OID.
	 */
	withContentOid(oid: string): FrameBuilder {
		return this.with({ contentOid: oid });
	}

	/**
	 * Set the message priority (V2+).
	 */
	withPriority(priority: MessagePriority): FrameBuilder {
		return this.with({ priority });
	}

	/**
	 * Set the time-to-live in seconds (V2+).
	 */
	withLifetime(seconds: bigint | number): FrameBuilder {
		return this.with({ lifetimeSecs: toBigInt(seconds) });
	}

	/**
	 * Link this frame to a parent by its content digest (V2+).
	 */
	withPreviousHash(parent: PreviousHashSpec): FrameBuilder {
		return this.with({ previousHash: parent });
	}

	/**
	 * Set an N×N control matrix from row-major bytes (V2+).
	 */
	withMatrix(n: number, data: Uint8Array): FrameBuilder {
		return this.with({ matrix: { n, data } });
	}

	/**
	 * Commit to the message body with SHA3-256 message integrity (V2+).
	 */
	withMessageHasher(salt?: Uint8Array): FrameBuilder {
		const integrity: MessageIntegritySpec =
			salt === undefined ? {} : { salt };
		return this.with({ messageIntegrity: integrity });
	}

	/**
	 * Witness the envelope with SHA3-256 frame integrity (V2+).
	 */
	withWitnessHasher(): FrameBuilder {
		return this.with({ frameIntegrity: true });
	}

	/**
	 * Sign the assembled frame with a local secp256k1 key (V1+).
	 */
	withSigner(keyBytes: Uint8Array): FrameBuilder {
		return this.with({ signer: { scheme: "secp256k1", keyBytes } });
	}

	/**
	 * Return a frozen copy of the accumulated specification without assembling
	 * a frame. Useful for inspection and for the detached-signing flow.
	 */
	toSpec(): Readonly<FrameSpec> {
		return Object.freeze({ ...this.spec });
	}

	/**
	 * Validate the accumulated spec and assemble the frame via the codec,
	 * returning the frame DER.
	 *
	 * @throws ValidationError when the spec is structurally invalid.
	 */
	build(): Uint8Array {
		const issues = collectIssues(this.spec);
		if (issues.length > 0) {
			throw new ValidationError("FRAME_SPEC", issues);
		}

		return this.codec.compose(this.spec);
	}
}

/**
 * Begin building a frame against `codec`, optionally seeding the body.
 */
export function frame(codec: FrameCodec, message?: Uint8Array): FrameBuilder {
	const builder = new FrameBuilder(codec);
	if (message === undefined) {
		return builder;
	}

	return builder.withMessage(message);
}
