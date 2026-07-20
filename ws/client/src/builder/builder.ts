/**
 * A fluent, immutable builder for tightbeam frames.
 * The method surface mirrors the Rust `FrameBuilder` API.
 */

import type { BodyEncryptor, Hasher, Signatory } from "../crypto.js";
import type { FrameCodec } from "./codec.js";
import type { ValidationIssue } from "./errors.js";
import type { MessagePriority } from "./priority.js";
import type { FrameSpec, MatrixSpec, PreviousHashSpec } from "./spec.js";
import { Frame } from "../frame.js";
import { ValidationError } from "./errors.js";
import { Version } from "./version.js";

/**
 * Largest value representable by the on-the-wire `INTEGER` (u64).
 */
const U64_MAX = 2n ** 64n - 1n;

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
function requiredVersion(spec: FrameSpec): Version {
	if (spec.matrix !== undefined) {
		return Version.V3;
	}

	if (
		spec.messageIntegrity !== undefined ||
		spec.frameIntegrity !== undefined ||
		spec.priority !== undefined ||
		spec.lifetime !== undefined ||
		spec.previousHash !== undefined
	) {
		return Version.V2;
	}

	if (spec.signer !== undefined || spec.encryptor !== undefined) {
		return Version.V1;
	}

	return Version.V0;
}

/**
 * The version the assembled frame will carry: the explicit pin when present,
 * the derived floor otherwise. The codec pins this version into the frame,
 * since security artifacts are installed after structural assembly.
 */
export function effectiveVersion(spec: FrameSpec): Version {
	if (spec.version !== undefined) {
		return spec.version;
	}

	return requiredVersion(spec);
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
	if (spec.lifetime !== undefined) {
		validateU64(spec.lifetime, "lifetime", issues);
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
	if (spec.version !== undefined) {
		validateVersionFloor(spec.version, spec, issues);
	}
	if (spec.assertedVersion !== undefined) {
		validateVersionAssertion(spec.assertedVersion, spec, issues);
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

function validateVersionFloor(
	version: Version,
	spec: FrameSpec,
	issues: ValidationIssue[],
): void {
	const floor = requiredVersion(spec);
	if (version < floor) {
		issues.push({
			path: "version",
			message: `Field version V${version} is below the floor V${floor} required by the requested fields`,
		});
	}
}

function validateVersionAssertion(
	asserted: Version,
	spec: FrameSpec,
	issues: ValidationIssue[],
): void {
	const effective = effectiveVersion(spec);
	if (asserted !== effective) {
		issues.push({
			path: "assertedVersion",
			message: `Version assertion failed: asserted V${asserted}, but the frame builds at V${effective}`,
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
	 * Pin the protocol version explicitly. Without a pin the lowest version
	 * that admits the requested fields is used.
	 */
	withVersion(version: Version): FrameBuilder {
		return this.with({ version });
	}

	/**
	 * Assert the version the assembled frame will carry: `build` fails when
	 * the effective version (pinned or derived) differs from `version`.
	 */
	assertVersion(version: Version): FrameBuilder {
		return this.with({ assertedVersion: version });
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
		return this.with({ lifetime: toBigInt(seconds) });
	}

	/**
	 * Link this frame to a parent by its content digest (V2+).
	 */
	withPreviousHash(parent: PreviousHashSpec): FrameBuilder {
		return this.with({ previousHash: parent });
	}

	/**
	 * Set an N×N control matrix from row-major bytes (V3+).
	 */
	withMatrix(n: number, data: Uint8Array): FrameBuilder {
		return this.with({ matrix: { n, data } });
	}

	/**
	 * Commit to the message body under any `Hasher` (V2+). The profile
	 * hasher is `Sha3_256`; bring your own for other digests.
	 */
	withMessageHasher(hasher: Hasher, salt?: Uint8Array): FrameBuilder {
		if (salt === undefined) {
			return this.with({ messageIntegrity: { hasher } });
		}

		return this.with({ messageIntegrity: { hasher, salt } });
	}

	/**
	 * Witness the envelope with frame integrity under any `Hasher` (V2+).
	 */
	withWitnessHasher(hasher: Hasher): FrameBuilder {
		return this.with({ frameIntegrity: hasher });
	}

	/**
	 * Encrypt the message body with any `BodyEncryptor` (V1+). The profile
	 * encryptors are `Aes256Gcm` (shared key) and `EciesEncryptor` (to a
	 * recipient public key); bring your own for other schemes. Open the
	 * received body with `Frame.decryptBytes(decryptor)`.
	 */
	withEncryptor(encryptor: BodyEncryptor): FrameBuilder {
		return this.with({ encryptor });
	}

	/**
	 * Sign the assembled frame with any `Signatory` (V1+) - the profile
	 * `Secp256k1SigningKey`, or an external implementation (wallet, passkey,
	 * HSM) whose private key never enters wasm memory.
	 */
	withSigner(signatory: Signatory): FrameBuilder {
		return this.with({ signer: signatory });
	}

	/**
	 * Return a frozen copy of the accumulated specification without
	 * assembling a frame.
	 */
	toSpec(): Readonly<FrameSpec> {
		return Object.freeze({ ...this.spec });
	}

	/**
	 * Validate the accumulated spec and assemble the frame via the codec,
	 * which drives the configured hashers, encryptor, and signatory through
	 * the assembly pipeline.
	 *
	 * @throws ValidationError when the spec is structurally invalid or a
	 * version assertion fails against the assembled frame.
	 */
	async build(): Promise<Frame> {
		const issues = collectIssues(this.spec);
		if (issues.length > 0) {
			throw new ValidationError("FRAME_SPEC", issues);
		}

		return this.assertBuilt(
			Frame.fromDer(await this.codec.compose(this.spec)),
		);
	}

	/**
	 * Verify the version the codec actually wrote matches the caller's
	 * assertion, catching any drift between the TypeScript version floor and
	 * the Rust one.
	 */
	private assertBuilt(frame: Frame): Frame {
		const asserted = this.spec.assertedVersion;
		if (asserted !== undefined && frame.version !== asserted) {
			throw new ValidationError("FRAME_SPEC", [
				{
					path: "assertedVersion",
					message: `Version assertion failed: asserted V${asserted}, but the codec built V${frame.version}`,
				},
			]);
		}

		return frame;
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
