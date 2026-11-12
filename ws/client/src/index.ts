/**
 * Client for the tightbeam WebSocket transport, in the browser and in Node,
 * as `docs/ws-client.md` describes.
 */

export type {
	CommitmentSalt,
	DigestInfo,
	GoAwayReason,
	IntegrityVerdict,
	MessagePriority,
	MutualIdentity,
	Oid,
	RefusalCode,
	ServeClaim,
	SharedKey,
	SocketCloseInfo,
	TransitCode,
	TransitRefusal,
	TransportCode,
	TransportErrorName,
	TransportSigner,
	Version,
} from "#wasm";
export { ClientTransportError, StreamRefusal } from "./errors.js";
export type { ClientCode, TransportError, TransportErrorCode } from "./errors.js";
export { Engine } from "./engine.js";
export type { EngineInput } from "./engine.js";
export { Frame } from "./frame.js";
export type {
	CompactnessInfo,
	ConfidentialityInfo,
	FrameMatrix,
	OpenOptions,
	PreviousFrame,
	SignatureInfo,
} from "./frame.js";
export { Opening } from "./commitment.js";
export type { BodyCompressor, BodyInflator, CompressedBody, ZstdView } from "./compress.js";
export type { DigestInfoView, OidView, ProfileView } from "./views.js";
export type { DigestName, OidName } from "./views.js";
export {
	Aes256Gcm,
	HpkeDecryptor,
	HpkeEncryptor,
	Secp256k1SigningKey,
	Secp256k1VerifyingKey,
	Sha3_256,
} from "./crypto.js";
export type {
	BodyDecryptor,
	BodyEncryptor,
	EncryptedBody,
	FrameVerifier,
	Hasher,
	Signatory,
	VerifiableFrame,
	VerifyingKeyView,
} from "./crypto.js";
export { Envelope } from "./envelope.js";
export { HeldCodec } from "./message.js";
export type { MessageCodec, PayloadCodec } from "./message.js";
export { Route, Router, UnroutedTopicError } from "./router.js";
export type { RouteHandler } from "./router.js";
export { FrameBuilder } from "./builder/builder.js";
export { TightbeamWsClient } from "./client.js";
export type {
	CleartextConnectOptions,
	ConnectOptions,
	DuplexBodyHandler,
	DuplexStream,
	EmitOptions,
	MutualConnectOptions,
	MuxStreamHandler,
	ReplySink,
	RequestStream,
	ServeOptions,
	StreamBody,
	StreamRoute,
	StreamingBodyHandler,
	WaitOptions,
} from "./client.js";
