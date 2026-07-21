# tightbeam-ws-client

Hybrid TypeScript/WebAssembly client for the [tightbeam](https://crates.io/crates/tightbeam-rs) WebSocket transport: build tightbeam frames with a fluent, Rust-parity builder and ship them over a socket from the browser or Node.

The frame codec (ASN.1 DER structure engine) is the actual Rust implementation (`tightbeam-ws-wasm`) compiled with `wasm-pack`; the TypeScript layer adds the builder, validation, and connection ergonomics. Two wasm bundles ship in the package - a `web` build and a `nodejs` build - selected automatically via the package's `imports` map. Node ≥ 24 uses its global `WebSocket`; no shim required.

Same builder methods as tightbeam-rs (`withSigner`, `withEncryptor`, `withMessageHasher`), the same `Frame` type with the same verification methods (`verify`, `frameIntegrityVerdict`, `messageCommitmentVerdict`, `decryptMessage`), the same enums with the same ordinals (`Version`, `MessagePriority`), and `emit` returning the response frame.

Cryptography is bring-your-own: every security operation goes through a capability interface (`Hasher`, `BodyEncryptor`, `BodyDecryptor`, `Signatory`, `BodyCompressor`, `BodyInflator`) identified by the dotted algorithm OID it writes into the frame. The tightbeam profile (SHA3-256 / secp256k1 ECDSA / AES-256-GCM / ECIES / zstd) ships as ready-made wasm-backed implementations; any hash, cipher, signing, or compression library plugs in the same way.

## Install

```sh
npm install @wahidgroup/tightbeam-ws-client
```

The package is published to GitHub Packages; point the `@wahidgroup` scope there in `.npmrc`:

```ini
@wahidgroup:registry=https://npm.pkg.github.com
```

## Cleartext round-trip

```ts
import {
	Opaque,
	TightbeamWsClient,
	frame,
} from "@wahidgroup/tightbeam-ws-client";

const client = await TightbeamWsClient.connect("ws://localhost:9100");

const built = await frame(new TextEncoder().encode("hello"))
	.withId("greeting")
	.withOrder(Math.floor(Date.now() / 1000))
	.build();

const response = await client.emit(built);
console.log(response?.message(Opaque), response?.order, response?.signed);

client.close();
```

`emit` resolves with the response `Frame`, or `undefined` when the peer returns no response (`client.emit(frame) -> Option<Frame>`). A `Frame` exposes the typed body via `message(codec)` (the raw DER via `bodyDer`), metadata (`version`, `id`, `order`, and the V2+/V3+ fields `priority`, `lifetime`, `previousFrame`, `matrix` when present), the security markers (`signed`, `messageIntegrity`, `frameIntegrity`, `confidential`) with their carried infos (`signatureInfo`, `messageIntegrityInfo`, `frameIntegrityInfo`, `confidentialityInfo`), the raw bytes via `toDer()`, and the verification methods below.

## Encrypted sessions (ECIES)

The server is authenticated by pinning its DER certificate; the ECIES handshake runs over the cleartext socket on the first `emit`.

```ts
import { TightbeamWsSecureClient } from "@wahidgroup/tightbeam-ws-client";

// Server-authenticated:
const secure = await TightbeamWsSecureClient.connect(url, serverCertDer);

// Mutually authenticated (32-byte secp256k1 signing key):
const mutual = await TightbeamWsSecureClient.connectMutual(
	url,
	serverCertDer,
	clientCertDer,
	clientSigningKey,
);
```

## Frame builder

Every `with*` returns a new immutable builder; `build()` validates the spec and resolves with the assembled `Frame`. Algorithms are selected with capability objects:

```ts
import {
	Aes256Gcm,
	EciesEncryptor,
	MessagePriority,
	Secp256k1SigningKey,
	Sha3_256,
	Version,
	frame,
} from "@wahidgroup/tightbeam-ws-client";

const signingKey = Secp256k1SigningKey.fromBytes(rawScalar);

const built = await frame(body)
	.withId("doc-42")
	.withOrder(1n)
	.withPriority(MessagePriority.LowLatency) // V2+
	.withLifetime(60) // V2+
	.withPreviousHash({ algorithmOid, digest }) // V2+
	.withMatrix(2, new Uint8Array([0, 1, 1, 0])) // V3+
	.withMessageHasher(new Sha3_256(), salt) // V2+: body commitment
	.withWitnessHasher(new Sha3_256()) // V2+: frame integrity
	.withEncryptor(Aes256Gcm.fromKey(key)) // V1+: body encryption
	.withSigner(signingKey) // V1+: secp256k1 signature
	.assertVersion(Version.V2) // fail the build unless it lands on V2
	.build();
```

- The version floor is derived from the requested fields, or pinned with `withVersion(Version.V2)`; `assertVersion` makes the build fail when the effective version differs from what you expect.
- `withMessageHasher` / `withWitnessHasher` take any `Hasher`; the profile hasher is `Sha3_256`.
- `withEncryptor` takes any `BodyEncryptor`: the profile symmetric cipher (`Aes256Gcm.fromKey(k)`, opened with the shared key), the profile asymmetric encryptor to a recipient (`EciesEncryptor.fromBytes(recipientPublicKey)`, opened with the recipient secret), or your own scheme. The frame has a single body-encryption slot.
- Structurally invalid specs reject with a `ValidationError` carrying per-field issues.

## Typed messages

The protocol treats the frame body as opaque DER: what it encodes is your contract with the peer. A `MessageCodec<T>` pairs a TypeScript type with that contract - `encode` produces the body DER, `decode` parses and runtime-validates it - so payloads are typed at every call site while the wire stays schema-agnostic.

For payloads without an ASN.1 schema, `wrapped(inner)` lifts any byte-level serialization (JSON, CBOR, protobuf) into a codec by wrapping it in the profile opaque body:

```ts
import type { MessageCodec } from "@wahidgroup/tightbeam-ws-client";
import { frame, wrapped } from "@wahidgroup/tightbeam-ws-client";

interface ChatMessage {
	author: string;
	text: string;
}

const Chat: MessageCodec<ChatMessage> = wrapped({
	encode: (message) => new TextEncoder().encode(JSON.stringify(message)),
	decode: (payload) => {
		const parsed = JSON.parse(new TextDecoder().decode(payload));
		// Runtime validation is the codec's responsibility.
		if (
			typeof parsed?.author !== "string" ||
			typeof parsed?.text !== "string"
		) {
			throw new Error("not a ChatMessage");
		}
		return parsed;
	},
});

const built = await frame()
	.withMessage(Chat, { author: "ada", text: "hello" })
	.build();

const reply = await client.emit(built);
const message = reply?.message(Chat); // ChatMessage
```

To interoperate with a peer expecting a specific ASN.1 `Message` schema (e.g. a Rust `der::Sequence`), implement `MessageCodec` directly with the ASN.1 library of your choice; the DER it emits is installed in the frame. `frame(bytes)` / `withMessage(bytes)` are sugar for the profile `Opaque` codec (raw bytes in the opaque wrapper), and a codec's optional `contentOid` is recorded in the confidentiality info when the body is sealed.

## Bring your own cryptography

Each capability interface pairs the operation with the dotted OID recorded in the frame, so implementations are interchangeable across libraries and languages:

```ts
import type { Hasher, Signatory } from "@wahidgroup/tightbeam-ws-client";
import { sha3_512 } from "@noble/hashes/sha3.js";

// Any digest: implement Hasher with the OID peers should recompute under.
const sha3_512Hasher: Hasher = {
	algorithmOid: "2.16.840.1.101.3.4.2.10",
	digest: async (data) => sha3_512(data),
};

// Any signer: the builder hands the implementation the to-be-signed bytes
// and attaches the returned signature, so an external signer's private key
// never enters wasm memory (wallets, passkeys, HSMs, remote KMS).
const walletSigner: Signatory = {
	signatureAlgorithmOid: "2.16.840.1.101.3.4.3.10",
	digestAlgorithmOid: "2.16.840.1.101.3.4.2.8",
	signerId: () => walletKeyId, // subject-key-identifier octets
	sign: async (tbs) => wallet.sign(tbs),
};

const built = await frame(body)
	.withWitnessHasher(sha3_512Hasher)
	.withSigner(walletSigner)
	.build();
```

`BodyEncryptor` / `BodyDecryptor` work the same way: `encrypt(bodyDer)` resolves with `{ algorithmOid, parametersDer, ciphertext }`, and `decrypt(sealed)` receives the carried pieces and resolves with the plaintext body DER. The `PROFILE_OIDS` constant exports the profile identifiers.

## Compression

Compression is a capability too: a `BodyCompressor` shrinks the body DER and names its algorithm by OID, a `BodyInflator` reverses it. The builder compresses after the message commitment (the commitment is over the uncompressed body) and before encryption (peers encrypt the compressed bytes), matching tightbeam-rs.

The profile compression ships ready-made: `ZstdCompression` (zstd in the seekable format, `PROFILE_OIDS.zstd`) is wire-compatible with tightbeam-rs `ZstdCompression` and backed by a lazily loaded wasm build of libzstd - clients that never compress never load it. Its decompression output is capped (16 MiB by default, matching tightbeam-rs; tune with `new ZstdCompression(maxOutput)`), and the cap is enforced against the stream's declared size before anything is allocated.

```ts
import {
	Opaque,
	ZstdCompression,
	frame,
} from "@wahidgroup/tightbeam-ws-client";

const zstd = new ZstdCompression();

const built = await frame(body).withCompressor(zstd).build();

// Cleartext + compressed: inflate and decode in one step.
const message = await received.inflateMessage(zstd, Opaque);

// Compressed then sealed: pass the inflator to decryptMessage.
const opened = await sealed.decryptMessage(cipher, Opaque, zstd);
```

Any other algorithm plugs in the same way. The platform-native `CompressionStream` gives a dependency-free zlib alternative (`PROFILE_OIDS.zlib`, RFC 3274):

```ts
import type {
	BodyCompressor,
	BodyInflator,
	CompressedBody,
} from "@wahidgroup/tightbeam-ws-client";
import { Opaque, PROFILE_OIDS, frame } from "@wahidgroup/tightbeam-ws-client";

async function pump(
	transform: ReadableWritablePair<Uint8Array, BufferSource>,
	bytes: Uint8Array,
): Promise<Uint8Array> {
	const source = new Blob([bytes]).stream().pipeThrough(transform);
	return new Uint8Array(await new Response(source).arrayBuffer());
}

const zlib: BodyCompressor & BodyInflator = {
	compress: async (bodyDer) => ({
		algorithmOid: PROFILE_OIDS.zlib,
		data: await pump(new CompressionStream("deflate"), bodyDer),
	}),
	decompress: (compressed) =>
		pump(new DecompressionStream("deflate"), compressed.data),
};

const built = await frame(body).withCompressor(zlib).build();
```

A compressed frame reports `compressed: true` and carries `compactnessInfo` (`{ algorithmOid, parametersDer?, contentOid? }`); reading it without an inflator rejects with a `ValidationError`. Inflators SHOULD cap their output size - a wire-supplied body can be a decompression bomb.

## Verification and decryption

Verification is on the `Frame` itself. Verdicts are `"verified" | "absent" | "algorithm-mismatch" | "mismatch"`. The verdict methods recompute under any `Hasher` (profile SHA3-256 by default); for frames signed under non-profile schemes, verify `signatureInfo.signature` over `tbs()` with your own library.

```ts
import { Aes256Gcm, EciesDecryptor } from "@wahidgroup/tightbeam-ws-client";

response.verify(signingKey.verifyingKey()); // profile scheme; throws when invalid
await response.frameIntegrityVerdict(); // "verified" | "absent" | ...
await response.frameIntegrityVerdict(sha3_512Hasher); // under your own hasher
await response.messageCommitmentVerdict(salt); // checks the body commitment

// Open an encrypted body with the matching cipher or recipient secret,
// decoding the plaintext under any codec (Opaque for raw bytes):
await response.decryptMessage(Aes256Gcm.fromKey(key), Opaque);
await response.decryptMessage(
	EciesDecryptor.fromBytes(recipientSecretKey),
	Chat,
);

// Raw surfaces for external verification:
response.tbs(); // to-be-signed bytes
response.witnessInput(); // frame-integrity preimage
response.signatureInfo; // { algorithmOid, digestAlgorithmOid, signature }
```

## Detached commitments

A commitment can also live outside a frame (`tightbeam::crypto::commitment::Opening`): publish a hiding digest now, disclose the opening `(salt, body)` later, and any holder of the digest verifies the disclosure. The preimage is the same length-framed `salt || body` the in-frame message commitment uses, so a detached commitment and a frame-carried one are interchangeable.

```ts
import { Opening, Sha3_256 } from "@wahidgroup/tightbeam-ws-client";

// Prover: publish `commitment`, keep `opening` secret until disclosure.
const { commitment, opening } = await Opening.prove(
	new Sha3_256(),
	bodyDer,
	crypto.getRandomValues(new Uint8Array(32)), // high-entropy salt hides the body
);

// Verifier: reassemble the disclosed parts and check in constant time.
const disclosed = Opening.fromParts(opening.salt, opening.bodyDer);
const verified = await disclosed.verify(new Sha3_256(), commitment);
```

`verify` resolves with `false` on an algorithm mismatch or a digest mismatch. An empty salt reproduces the plain body digest (binding, not hiding). Any `Hasher` works on both sides.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE) at your option.
