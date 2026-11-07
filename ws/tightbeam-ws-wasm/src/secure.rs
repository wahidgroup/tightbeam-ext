//! Encrypted transport assembly for the browser WebSocket client.
//! Compiled only for `wasm32` targets.
//!
//! Builds tightbeam's transport-level HPKE machinery over a `gloo`
//! WebSocket ([`GlooStream`]) for the multiplexed client (`MuxWsClient`).
//!
//! The session profile is a compile-time choice, exactly as with a native
//! tightbeam-rs transport: [`BrowserSocket::pinned`] assembles the transport
//! for any [`HandshakeProvider`] monomorphization, while the shipped bindings
//! instantiate the tightbeam default profile.
//!
//! [`GlooStream`]: crate::stream::GlooStream
//! [`HandshakeProvider`]: tightbeam::transport::handshake::HandshakeProvider

use std::sync::Arc;

use wasm_bindgen::prelude::*;
use web_sys::AbortSignal;

use tightbeam::crypto::key::Secp256k1KeyProvider;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::der::asn1::OctetString;
use tightbeam::der::Decode;
use tightbeam::transport::handshake::negotiation::{MuxBudgets, TransportOffer};
use tightbeam::transport::handshake::receipt::ReceiptApprover;
use tightbeam::x509::Certificate;
use tightbeam::{TightBeamError, ZeroizingBytes};

use crate::approver::{JsReceiptApprover, OfferedAuthorization, OfferedBudgets};
use crate::fault::{JsFault, RefusalCode, TransportCode};
use crate::profile::Secp256k1SigningKey;
use crate::promise::{JsBytes, Record, WholeNumber};
use crate::protocol::BrowserSocket;
use crate::signer::JsSigningKeyProvider;
use crate::socket::OpeningSocket;
use crate::stream::WsTransport;

/// The default profile, which the shipped bindings instantiate.
type ProfileSocket = BrowserSocket<DefaultCryptoProvider>;

/// The stream cap a dial grants when its options name none.
const DEFAULT_STREAM_CAP: u32 = 8;

/// The members of [`SessionOffer`], which only a mutual-auth dial carries.
const SESSION_KNOBS: [&str; 3] = ["options.budgets", "options.authorization", "options.approveReceipt"];

/// TypeScript shape of the identity a mutual-auth dial presents.
#[wasm_bindgen(typescript_custom_section)]
const MUTUAL_IDENTITY_TS: &'static str = r#"
/**
 * The identity a mutual-auth dial presents, each certificate named for the
 * side it identifies.
 */
export interface MutualIdentity {
	/**
	 * DER certificate pinned as the trusted server.
	 */
	readonly serverCertDer: Uint8Array;
	/**
	 * DER certificate presented to the server.
	 */
	readonly clientCertDer: Uint8Array;
	/**
	 * Proof of the client certificate's key: the raw 32-byte secp256k1
	 * signing scalar, or an external `TransportSigner` (WebAuthn, wallet,
	 * KMS bridge) whose key stays in its JavaScript backend.
	 */
	readonly clientKey: Uint8Array | TransportSigner;
}
"#;

/// The key that proves possession of a client certificate.
enum ClientKey {
	/// The raw secp256k1 scalar, read once into the profile key.
	Scalar(Secp256k1SigningKey),
	/// An external signer, whose key stays in its JavaScript backend.
	Signer(JsSigningKeyProvider),
}

impl TryFrom<JsValue> for ClientKey {
	type Error = JsFault;

	/// Read a client key: a `Uint8Array` is the raw scalar, and any other
	/// object is a `TransportSigner`, which [`JsSigningKeyProvider::new`]
	/// admits.
	///
	/// # Errors
	///
	/// - `InvalidClientKey` -- the value is neither a `Uint8Array` nor an object.
	/// - `InvalidSigningKey` -- the scalar is not 32 octets, or names no key.
	/// - The errors of [`JsSigningKeyProvider::new`].
	fn try_from(value: JsValue) -> Result<Self, Self::Error> {
		if let Some(scalar) = JsBytes::recognize(&value) {
			let scalar = ZeroizingBytes::new(scalar);
			return Secp256k1SigningKey::from_scalar(scalar).map(Self::Scalar);
		}
		if !value.is_object() {
			let message = "clientKey must be the raw signing scalar as a Uint8Array or a TransportSigner";
			return Err(RefusalCode::InvalidClientKey.because(message));
		}

		JsSigningKeyProvider::new(value.unchecked_into()).map(Self::Signer)
	}
}

impl ClientKey {
	/// Pair the certificate in `cert_der` with this key under the default
	/// profile.
	///
	/// Wasm runs one thread, so the `Arc` is sound without `Send + Sync`.
	///
	/// # Errors
	///
	/// - The errors of [`JsSigningKeyProvider::into_identity`], which the scalar key raises too.
	#[allow(clippy::arc_with_non_send_sync)]
	fn identity(self, cert_der: &[u8]) -> Result<SigningIdentity, JsFault> {
		match self {
			Self::Scalar(key) => {
				let certificate = Certificate::from_der(cert_der);
				let certificate = certificate.map_err(|error| TransportCode::InvalidCertificate.because(error))?;
				let provider = Arc::new(Secp256k1KeyProvider::from(key.into_inner()));

				let identity = SigningIdentity::new(certificate, provider);
				identity.map_err(|error| JsFault::from(TightBeamError::from(error)))
			}
			Self::Signer(provider) => provider.into_identity::<DefaultCryptoProvider>(cert_der),
		}
	}
}

/// The identity a mutual-auth dial presents: the pinned server certificate,
/// and the client certificate with the key that proves it, each read once
/// when the dial begins.
pub(crate) struct MutualIdentity {
	server_cert_der: Vec<u8>,
	client_cert_der: Vec<u8>,
	client_key: ClientKey,
}

impl TryFrom<&JsValue> for MutualIdentity {
	type Error = JsFault;

	/// Read the identity that the object `value` names, piece by piece.
	///
	/// # Errors
	///
	/// - `InvalidBytes` -- a certificate is not a `Uint8Array`.
	/// - The errors of the [`ClientKey`] read.
	fn try_from(value: &JsValue) -> Result<Self, Self::Error> {
		let server_cert_der = JsBytes::read_member(value, "identity.serverCertDer")?;
		let client_cert_der = JsBytes::read_member(value, "identity.clientCertDer")?;
		let client_key = ClientKey::try_from(Record::member(value, "identity.clientKey"))?;
		Ok(Self { server_cert_der, client_cert_der, client_key })
	}
}

/// The session knobs a mutual-auth dial offers, each one optional.
#[derive(Default)]
pub(crate) struct SessionOffer {
	budgets: Option<MuxBudgets>,
	authorization: Option<OctetString>,
	approver: Option<Arc<dyn ReceiptApprover>>,
}

/// TypeScript shape of the session offer of a mutual-auth dial.
#[wasm_bindgen(typescript_custom_section)]
const SESSION_OFFER_TS: &'static str = r#"
/**
 * Optional budget / settlement knobs for mutual-auth dials.
 */
export interface SessionOffer {
	budgets?: { clientToServer: number; serverToClient: number };
	authorization?: Uint8Array;
	approveReceipt?: (input: {
		receiptDer: Uint8Array;
		challenge?: Uint8Array;
	}) => Uint8Array | undefined | Promise<Uint8Array | undefined>;
}
"#;

/// TypeScript shapes of the options each dial takes.
#[wasm_bindgen(typescript_custom_section)]
const DIAL_OPTIONS_TS: &'static str = r#"
/**
 * Every session knob typed `never`, so the options of a dial without mutual
 * authentication refuse each knob at compile time.
 */
type WithoutSessionKnobs = { readonly [Knob in keyof SessionOffer]?: never };

/**
 * Options of a server-authenticated dial.
 */
export interface ConnectOptions extends WithoutSessionKnobs {
	/**
	 * Abort the dial and handshake: the socket closes and the promise
	 * rejects with the signal's abort reason. Timeouts compose as
	 * `AbortSignal.timeout(ms)`.
	 */
	readonly signal?: AbortSignal;
	/**
	 * Concurrency cap granted to server-initiated streams: a whole number from
	 * 1 to 2^32-1, and 8 by default. The server's own advertisement caps the
	 * concurrent emits of this client.
	 */
	readonly maxPeerStreams?: number;
}

/**
 * Options of a mutually authenticated dial: the fields of `ConnectOptions`,
 * and the session knobs only mutual authentication carries.
 */
export interface MutualConnectOptions
	extends Omit<ConnectOptions, keyof SessionOffer>,
		SessionOffer {}

/**
 * Options of a cleartext dial.
 */
export interface CleartextConnectOptions extends WithoutSessionKnobs {
	/**
	 * Abort the dial: the socket closes and the promise rejects with the
	 * signal's abort reason. Timeouts compose as `AbortSignal.timeout(ms)`.
	 */
	readonly signal?: AbortSignal;
	/**
	 * Symmetric concurrency cap: a whole number from 1 to 2^32-1, and 8 by
	 * default. Cleartext sessions have no negotiation, so both endpoints MUST
	 * configure the same value.
	 */
	readonly streams?: number;
}
"#;

/// The options of a dial, parsed once: the stream cap the session grants,
/// and the signal that aborts the dial.
pub(crate) struct DialOptions {
	streams: u32,
	signal: Option<AbortSignal>,
}

/// The options of a server-authenticated dial, whose cap is `maxPeerStreams`.
impl TryFrom<&JsValue> for DialOptions {
	type Error = JsFault;

	/// # Errors
	///
	/// - The errors of [`DialOptions::read`].
	/// - `SessionOfferRequiresMutual` -- the options name a session knob.
	fn try_from(options: &JsValue) -> Result<Self, Self::Error> {
		let dial = Self::read(options, "options.maxPeerStreams")?;
		Self::refuse_session(options)?;
		Ok(dial)
	}
}

impl DialOptions {
	/// Parse the options of a cleartext dial, whose symmetric cap is
	/// `streams`.
	///
	/// # Errors
	///
	/// - The errors of [`Self::read`].
	/// - `SessionOfferRequiresMutual` -- the options name a session knob.
	pub(crate) fn cleartext(options: &JsValue) -> Result<Self, JsFault> {
		let dial = Self::read(options, "options.streams")?;
		Self::refuse_session(options)?;
		Ok(dial)
	}

	/// The stream cap the session grants.
	pub(crate) fn streams(&self) -> u32 {
		self.streams
	}

	/// The signal that aborts the dial, when the options name one.
	pub(crate) fn signal(&self) -> &Option<AbortSignal> {
		&self.signal
	}

	/// Read the cap at `cap` and the signal of `options`. Absent options, or
	/// an absent member, take the default.
	///
	/// # Errors
	///
	/// - `InvalidConnectOptions` -- `options` is no object, or `signal` is no `AbortSignal`.
	/// - `InvalidStreamCap` -- the cap is no whole number from 1 to the `u32` ceiling, so zero,
	///   a fraction, a negative number, and `NaN` are refused.
	fn read(options: &JsValue, cap: &str) -> Result<Self, JsFault> {
		let present = Record::present(options.clone());
		let object = present.filter(JsValue::is_object);
		if object.is_none() && !options.is_undefined() {
			let message = "dial options must be an object: a stream cap is an options field, not a positional argument";
			return Err(RefusalCode::InvalidConnectOptions.because(message));
		}

		let cap_member = object.as_ref().and_then(|object| Record::optional_member(object, cap));
		let streams = match cap_member {
			None => DEFAULT_STREAM_CAP,
			Some(value) => {
				let whole = WholeNumber::read::<u32>(&value).filter(|streams| *streams > 0);
				let refusal = || {
					RefusalCode::InvalidStreamCap
						.because("must be a whole number from 1 to 2^32-1")
						.at(cap)
				};
				whole.ok_or_else(refusal)?
			}
		};

		let signal_member = object
			.as_ref()
			.and_then(|object| Record::optional_member(object, "options.signal"));
		let signal = signal_member.map(JsCast::dyn_into::<AbortSignal>).transpose();
		let signal = signal.map_err(|_| {
			RefusalCode::InvalidConnectOptions
				.because("must be an AbortSignal")
				.at("options.signal")
		})?;

		Ok(Self { streams, signal })
	}

	/// Refuse the session knobs of `options`, because a dial without mutual
	/// authentication carries none.
	///
	/// # Errors
	///
	/// - `SessionOfferRequiresMutual` -- the options name a session knob.
	fn refuse_session(options: &JsValue) -> Result<(), JsFault> {
		let named = SESSION_KNOBS
			.iter()
			.find(|knob| Record::optional_member(options, knob).is_some());
		match named {
			Some(knob) => {
				let message = format!("{knob} needs mutual authentication: dial with connectMutual");
				Err(RefusalCode::SessionOfferRequiresMutual.because(message))
			}
			None => Ok(()),
		}
	}
}

/// The options of a mutually authenticated dial, parsed once: the cap and
/// the signal of [`DialOptions`], and the session knobs it offers.
pub(crate) struct MutualDialOptions {
	dial: DialOptions,
	offer: SessionOffer,
}

impl TryFrom<&JsValue> for MutualDialOptions {
	type Error = JsFault;

	/// # Errors
	///
	/// - The errors of [`DialOptions::read`] and of the [`SessionOffer`] read.
	fn try_from(options: &JsValue) -> Result<Self, Self::Error> {
		let dial = DialOptions::read(options, "options.maxPeerStreams")?;
		let offer = SessionOffer::try_from(options)?;
		Ok(Self { dial, offer })
	}
}

impl MutualDialOptions {
	/// The cap and the signal, and the session knobs, apart.
	pub(crate) fn into_parts(self) -> (DialOptions, SessionOffer) {
		(self.dial, self.offer)
	}
}

impl TryFrom<&JsValue> for SessionOffer {
	type Error = JsFault;

	/// Read the knobs that the object `value` names. An absent `value` or an
	/// absent member offers nothing.
	///
	/// # Errors
	///
	/// - The errors of the [`OfferedBudgets`], [`OfferedAuthorization`], and
	///   [`JsReceiptApprover`] reads.
	fn try_from(value: &JsValue) -> Result<Self, Self::Error> {
		let budgets = Record::optional_member(value, "options.budgets");
		let budgets = budgets.as_ref().map(OfferedBudgets::try_from).transpose()?;

		let authorization = Record::optional_member(value, "options.authorization");
		let authorization = authorization.as_ref().map(OfferedAuthorization::try_from).transpose()?;

		let approver = Record::optional_member(value, "options.approveReceipt");
		let approver = approver.as_ref().map(JsReceiptApprover::try_from).transpose()?;

		let budgets = budgets.map(|offered| offered.0);
		let authorization = authorization.map(|offered| offered.0);
		let approver = approver.map(JsReceiptApprover::into_approver);
		Ok(Self { budgets, authorization, approver })
	}
}

impl SessionOffer {
	/// `transport` with `mux` and these knobs offered for its handshake.
	fn offered_on(self, transport: WsTransport, mut mux: TransportOffer) -> WsTransport {
		if let Some(budgets) = self.budgets {
			mux = mux.with_budgets(budgets);
		}
		if let Some(token) = self.authorization {
			mux = mux.with_authorization(token);
		}

		let transport = transport.with_mux_offer(Some(mux));
		match self.approver {
			Some(approver) => transport.with_receipt_approver(approver),
			None => transport,
		}
	}
}

/// What an encrypted dial pins and presents, read before the dial begins.
pub(crate) enum Dial {
	/// A server-authenticated dial that pins this server certificate.
	Server(Vec<u8>),
	/// A mutually authenticated dial, and the session knobs it offers.
	Mutual { identity: MutualIdentity, offer: SessionOffer },
}

impl Dial {
	/// The default-profile encrypted transport to `url`, offering
	/// multiplexing with `max_peer_streams`, and the socket it opened, which
	/// runs the handshake within the signal of the dial.
	///
	/// # Errors
	///
	/// - The errors of [`ClientKey::identity`].
	/// - The transport refusal of a server certificate the trust store does not take.
	/// - `InvalidUrl` -- the browser refuses to open a socket to `url`.
	pub(crate) fn transport(self, url: &str, max_peer_streams: u32) -> Result<(WsTransport, OpeningSocket), JsFault> {
		let mux = TransportOffer::mux(max_peer_streams);
		match self {
			Self::Server(server_cert_der) => {
				let (transport, opening) = Self::pinned(url, &server_cert_der, None)?;
				let transport = transport.with_mux_offer(Some(mux));
				Ok((transport, opening))
			}
			Self::Mutual { identity, offer } => {
				let signing = identity.client_key.identity(&identity.client_cert_der)?;
				let (transport, opening) = Self::pinned(url, &identity.server_cert_der, Some(signing))?;
				let transport = offer.offered_on(transport, mux);
				Ok((transport, opening))
			}
		}
	}

	/// The transport to `url` that pins `server_cert_der` and presents
	/// `identity`, and the socket it opened.
	fn pinned(
		url: &str,
		server_cert_der: &[u8],
		identity: Option<SigningIdentity>,
	) -> Result<(WsTransport, OpeningSocket), JsFault> {
		let trust_store = ProfileSocket::trust_store(server_cert_der)?;

		let (opening, carrier) = OpeningSocket::open(url)?;
		let transport = ProfileSocket::pinned(carrier, trust_store, identity)?;
		Ok((transport, opening))
	}
}
