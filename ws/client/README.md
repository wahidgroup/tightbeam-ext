# tightbeam-ws-client

Hybrid TypeScript/WebAssembly client for the [tightbeam](https://crates.io/crates/tightbeam-rs) WebSocket transport: build tightbeam frames with a fluent, Rust-parity builder and ship them over a socket from the browser or Node.

The frame codec (ASN.1 DER structure engine) is the actual Rust implementation (`tightbeam-ws-wasm`) compiled with `wasm-pack`; the TypeScript layer adds the builder, validation, and connection ergonomics. Two wasm bundles ship in the package - a `web` build and a `nodejs` build - selected automatically via the package's `imports` map. Node ≥ 24 uses its global `WebSocket`; no shim required.

Same builder methods as tightbeam-rs (`withSigner`, `withEncryptor`, `withMessageHasher`), the same `Frame` type with the same verification methods (`verify`, `frameIntegrityVerdict`, `messageCommitmentVerdict`, `decryptBytes`), the same enums with the same ordinals (`Version`, `MessagePriority`), and `emit` returning the response frame.

Cryptography is bring-your-own: every security operation goes through a capability interface (`Hasher`, `BodyEncryptor`, `BodyDecryptor`, `Signatory`) identified by the dotted algorithm OID it writes into the frame. The tightbeam profile (SHA3-256 / secp256k1 ECDSA / AES-256-GCM / ECIES) ships as ready-made wasm-backed implementations; any hash, cipher, or signing library plugs in the same way.

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
import { TightbeamWsClient, frame } from "@wahidgroup/tightbeam-ws-client";

const client = await TightbeamWsClient.connect("ws://localhost:9100");

const built = await frame(new TextEncoder().encode("hello"))
	.withId("greeting")
	.withOrder(Math.floor(Date.now() / 1000))
	.build();

const response = await client.emit(built);
console.log(response?.body, response?.order, response?.signed);

client.close();
```

`emit` resolves with the response `Frame`, or `undefined` when the peer returns no response (`client.emit(frame) -> Option<Frame>`). A `Frame` exposes the decoded body, metadata (`version`, `id`, `order`, and the V2+/V3+ fields `priority`, `lifetime`, `previousFrame`, `matrix` when present), the security markers (`signed`, `messageIntegrity`, `frameIntegrity`, `confidential`) with their carried infos (`signatureInfo`, `messageIntegrityInfo`, `frameIntegrityInfo`, `confidentialityInfo`), the raw bytes via `toDer()`, and the verification methods below.

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

## Verification and decryption

Verification is on the `Frame` itself. Verdicts are `"verified" | "absent" | "algorithm-mismatch" | "mismatch"`. The verdict methods recompute under any `Hasher` (profile SHA3-256 by default); for frames signed under non-profile schemes, verify `signatureInfo.signature` over `tbs()` with your own library.

```ts
import { Aes256Gcm, EciesDecryptor } from "@wahidgroup/tightbeam-ws-client";

response.verify(signingKey.verifyingKey()); // profile scheme; throws when invalid
await response.frameIntegrityVerdict(); // "verified" | "absent" | ...
await response.frameIntegrityVerdict(sha3_512Hasher); // under your own hasher
await response.messageCommitmentVerdict(salt); // checks the body commitment

// Open an encrypted body with the matching cipher or recipient secret:
await response.decryptBytes(Aes256Gcm.fromKey(key));
await response.decryptBytes(EciesDecryptor.fromBytes(recipientSecretKey));

// Raw surfaces for external verification:
response.tbs(); // to-be-signed bytes
response.witnessInput(); // frame-integrity preimage
response.signatureInfo; // { algorithmOid, digestAlgorithmOid, signature }
```

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE) at your option.
