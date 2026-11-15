//! The dial of the browser client, parsed once from the values JavaScript
//! hands over, as the parse-once section of `docs/ws-wasm.md` describes.

use core::future::Future;
use core::pin::Pin;
use std::sync::Arc;

use gloo_net::websocket::futures::WebSocket;
use wasm_bindgen::prelude::*;
use web_sys::AbortSignal;

use tightbeam::crypto::key::Secp256k1KeyProvider;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::der::asn1::OctetString;
use tightbeam::der::Decode;
use tightbeam::transport::handshake::negotiation::{MuxBudgets, TransportOffer};
use tightbeam::transport::handshake::receipt::ReceiptApprover;
use tightbeam::transport::multiplex::MuxRole;
use tightbeam::x509::Certificate;
use tightbeam::{TightBeamError, ZeroizingBytes};

use crate::approver::{JsReceiptApprover, OfferedAuthorization, OfferedBudgets};
use crate::fault::{JsFault, RefusalCode, TransportCode};
use crate::mux::{BrowserMux, SessionParts};
use crate::profile::Secp256k1SigningKey;
use crate::promise::{AbortRace, JsBytes, Recognized, Record, Signal, WholeNumber};
use crate::protocol::{BrowserSocket, Pinned};
use crate::signer::JsSigningKeyProvider;
use crate::socket::{Opened, OpeningSocket, SocketMonitor, SocketParts};
use crate::stream::GlooStream;

/// The default profile, which the shipped bindings instantiate.
type ProfileSocket = BrowserSocket<DefaultCryptoProvider>;

/// The stream cap a dial grants when its options name none, as a literal that
/// both the Rust constant and the TypeScript options read.
macro_rules! default_stream_cap {
	() => {
		8
	};
}

/// The stream cap a dial grants when its options name none.
const DEFAULT_STREAM_CAP: u32 = default_stream_cap!();

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

/// TypeScript shape of the session offer of a mutual-auth dial.
#[wasm_bindgen(typescript_custom_section)]
const SESSION_OFFER_TS: &'static str = r#"
/**
 * Optional budget / settlement knobs for mutual-auth dials.
 */
export interface SessionOffer {
	/**
	 * The credit ceiling of each direction, in whole credits.
	 */
	budgets?: { clientToServer: number; serverToClient: number };
	/**
	 * The token that the server reads at the handshake.
	 */
	authorization?: Uint8Array;
	/**
	 * The callback that settles each invoice of the server. It receives the
	 * DER of the session receipt and the settlement challenge, when the
	 * receipt carries one, and answers the settlement octets or `undefined`.
	 */
	approveReceipt?: (input: {
		receiptDer: Uint8Array;
		challenge?: Uint8Array;
	}) => Uint8Array | undefined | Promise<Uint8Array | undefined>;
}
"#;

/// TypeScript shapes of the options each dial takes.
#[wasm_bindgen(typescript_custom_section)]
const DIAL_OPTIONS_TS: &'static str = concat!(
	r#"
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
	 * 1 to 2^32-1, and "#,
	default_stream_cap!(),
	r#" by default. The server's own advertisement caps the
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
	 * Symmetric concurrency cap: a whole number from 1 to 2^32-1, and "#,
	default_stream_cap!(),
	r#" by
	 * default. Cleartext sessions have no negotiation, so both endpoints MUST
	 * configure the same value.
	 */
	readonly streams?: number;
}
"#
);

/// The parse of a DER certificate that JavaScript hands over at `path`: the
/// one read of a certificate on the dial path.
///
/// # Errors
///
/// - `InvalidBytes` -- the value is not a `Uint8Array`.
/// - `InvalidCertificate` -- the octets are no DER certificate.
fn certificate(value: &JsValue, path: &str) -> Result<Certificate, JsFault> {
	let der = JsBytes::read_value(value, path)?;
	let parsed = Certificate::from_der(&der);
	parsed.map_err(|error| TransportCode::InvalidCertificate.because(error).at(path))
}

/// The member of a mutual identity that holds its client key.
const CLIENT_KEY: &str = "identity.clientKey";

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
	/// - `InvalidBytes` at `identity.clientKey` -- the scalar is a `Uint8Array` that admits no copy, as
	///   [`JsBytes::recognize`] states.
	/// - `InvalidSigningKey` -- the scalar is not 32 octets, or names no key.
	/// - The errors of [`JsSigningKeyProvider::new`].
	fn try_from(value: JsValue) -> Result<Self, Self::Error> {
		match JsBytes::recognize(&value) {
			Recognized::Bytes(scalar) => {
				let scalar = ZeroizingBytes::new(scalar);
				Secp256k1SigningKey::from_scalar(scalar).map(Self::Scalar)
			}
			Recognized::Unreadable => {
				let message = "clientKey must be a Uint8Array over a readable buffer";
				Err(RefusalCode::InvalidBytes.because(message).at(CLIENT_KEY))
			}
			Recognized::NotBytes if value.is_object() => {
				JsSigningKeyProvider::new(value.unchecked_into()).map(Self::Signer)
			}
			Recognized::NotBytes => {
				let message = "clientKey must be the raw signing scalar as a Uint8Array or a TransportSigner";
				Err(RefusalCode::InvalidClientKey.because(message))
			}
		}
	}
}

impl ClientKey {
	/// Pair `certificate` with this key under the default profile.
	///
	/// Wasm runs one thread, so the `Arc` is sound without `Send + Sync`.
	///
	/// # Errors
	///
	/// - The errors of [`JsSigningKeyProvider::into_identity`], which the scalar key raises too.
	#[allow(clippy::arc_with_non_send_sync)]
	fn identity(self, certificate: Certificate) -> Result<SigningIdentity, JsFault> {
		match self {
			Self::Scalar(key) => {
				let provider = Arc::new(Secp256k1KeyProvider::from(key.into_inner()));
				let identity = SigningIdentity::new(certificate, provider);
				identity.map_err(|error| JsFault::from(TightBeamError::from(error)))
			}
			Self::Signer(provider) => provider.into_identity::<DefaultCryptoProvider>(certificate),
		}
	}
}

/// The identity a mutual-auth dial presents: the pinned server certificate,
/// and the client certificate with the key that proves it, each parsed once
/// as the dial begins.
struct MutualIdentity {
	server: Certificate,
	client: Certificate,
	client_key: ClientKey,
}

impl TryFrom<&JsValue> for MutualIdentity {
	type Error = JsFault;

	/// Read the identity that the object `value` names, piece by piece.
	///
	/// # Errors
	///
	/// - The errors of the certificate parse, for either certificate.
	/// - The errors of the [`ClientKey`] read.
	fn try_from(value: &JsValue) -> Result<Self, Self::Error> {
		let server_member = Record::member(value, "identity.serverCertDer");
		let client_member = Record::member(value, "identity.clientCertDer");
		let server = certificate(&server_member, "identity.serverCertDer")?;
		let client = certificate(&client_member, "identity.clientCertDer")?;

		let client_key = ClientKey::try_from(Record::member(value, CLIENT_KEY))?;
		Ok(Self { server, client, client_key })
	}
}

/// One session knob that only a mutual-auth dial offers.
#[derive(Clone, Copy)]
enum Knob {
	/// `options.budgets`, the credit ceiling of each direction.
	Budgets,
	/// `options.authorization`, the token the server reads at the handshake.
	Authorization,
	/// `options.approveReceipt`, the callback that settles each invoice.
	ApproveReceipt,
}

impl Knob {
	/// Every knob, which a mutual-auth dial reads and every other dial
	/// refuses.
	const ALL: [Self; 3] = [Self::Budgets, Self::Authorization, Self::ApproveReceipt];

	/// The options member that carries this knob.
	fn member(self) -> &'static str {
		match self {
			Self::Budgets => "options.budgets",
			Self::Authorization => "options.authorization",
			Self::ApproveReceipt => "options.approveReceipt",
		}
	}

	/// Read `value` into the slot of this knob on `offer`, and name the member
	/// of this knob on a refusal.
	///
	/// # Errors
	///
	/// - The errors of the [`OfferedBudgets`], [`OfferedAuthorization`], and
	///   [`JsReceiptApprover`] reads.
	fn read_into(self, value: &JsValue, offer: &mut SessionOffer) -> Result<(), JsFault> {
		let path = self.member();
		match self {
			Self::Budgets => offer.budgets = Some(OfferedBudgets::read(value, path)?.0),
			Self::Authorization => offer.authorization = Some(OfferedAuthorization::read(value, path)?.0),
			Self::ApproveReceipt => offer.approver = Some(JsReceiptApprover::read(value, path)?.into_approver()),
		}

		Ok(())
	}
}

/// The session knobs a mutual-auth dial offers, each one optional.
#[derive(Default)]
struct SessionOffer {
	budgets: Option<MuxBudgets>,
	authorization: Option<OctetString>,
	approver: Option<Arc<dyn ReceiptApprover>>,
}

impl SessionOffer {
	/// The transport over `carrier` that pins `trust_store` and presents
	/// `identity`, and offers `mux` with these knobs for its handshake.
	///
	/// # Errors
	///
	/// - The errors of [`BrowserSocket::pinned`].
	fn pin(
		self,
		carrier: WebSocket,
		trust_store: Arc<dyn CertificateTrust>,
		identity: Option<SigningIdentity>,
		mut mux: TransportOffer,
	) -> Result<Pinned<DefaultCryptoProvider>, JsFault> {
		if let Some(budgets) = self.budgets {
			mux = mux.with_budgets(budgets);
		}
		if let Some(token) = self.authorization {
			mux = mux.with_authorization(token);
		}

		let pinned = ProfileSocket::pinned(carrier, trust_store, identity, mux)?;
		match self.approver {
			Some(approver) => Ok(pinned.approving(approver)),
			None => Ok(pinned),
		}
	}
}

/// What a dial pins and presents, by the kind of session.
enum SessionKind {
	/// A session with no handshake, no confidentiality, and no integrity,
	/// whose stream cap both endpoints configure alike.
	Cleartext,
	/// A server-authenticated session that pins this server certificate.
	Server(Box<Certificate>),
	/// A mutually authenticated session, and the session knobs it offers.
	Mutual {
		/// The pinned server certificate and the client identity.
		identity: Box<MutualIdentity>,
		/// The session knobs of the dial.
		offer: SessionOffer,
	},
}

impl SessionKind {
	/// The options member that names the stream cap of this kind: the
	/// symmetric cap of a cleartext session, or the cap on the streams a
	/// server initiates.
	fn cap_member(&self) -> &'static str {
		match self {
			Self::Cleartext => "options.streams",
			Self::Server(_) | Self::Mutual { .. } => "options.maxPeerStreams",
		}
	}

	/// Take `value` as the `knob` of the offer of this session.
	///
	/// # Errors
	///
	/// - `SessionOfferRequiresMutual` -- the session has no mutual authentication.
	/// - The errors of [`Knob::read_into`].
	fn offer(&mut self, knob: Knob, value: &JsValue) -> Result<(), JsFault> {
		match self {
			Self::Mutual { offer, .. } => knob.read_into(value, offer),
			Self::Cleartext | Self::Server(_) => {
				let message = format!("{} needs mutual authentication: dial with connectMutual", knob.member());
				Err(RefusalCode::SessionOfferRequiresMutual.because(message))
			}
		}
	}

	/// Open a socket to `url`, and provision the transport of this kind over
	/// it under the stream cap `streams`.
	///
	/// # Errors
	///
	/// - `InvalidUrl` -- the browser refuses to open a socket to `url`.
	/// - `InvalidCertificate` -- the trust store refuses the server certificate.
	/// - The errors of [`ClientKey::identity`].
	/// - The errors of [`SessionOffer::pin`].
	fn open(self, url: &str, streams: u32) -> Result<(Negotiation, OpeningSocket), JsFault> {
		match self {
			Self::Cleartext => {
				let SocketParts { opening, carrier } = OpeningSocket::open(url)?;
				let opened = Box::pin(opening.opened());
				let stream = GlooStream::from(carrier);

				Ok((Negotiation::Cleartext { opened, stream, streams }, opening))
			}
			Self::Server(pinned) => Self::pinned(url, *pinned, None, SessionOffer::default(), streams),
			Self::Mutual { identity, offer } => {
				let MutualIdentity { server, client, client_key } = *identity;
				let signing = client_key.identity(client)?;

				Self::pinned(url, server, Some(signing), offer, streams)
			}
		}
	}

	/// The transport to `url` that pins `server`, presents `identity`, and
	/// offers a mux of `streams` with the knobs of `offer`, and the socket it
	/// opened.
	fn pinned(
		url: &str,
		server: Certificate,
		identity: Option<SigningIdentity>,
		offer: SessionOffer,
		streams: u32,
	) -> Result<(Negotiation, OpeningSocket), JsFault> {
		let trust_store = ProfileSocket::trust_store(server)?;
		let mux = TransportOffer::mux(streams);

		let SocketParts { opening, carrier } = OpeningSocket::open(url)?;
		let pinned = offer.pin(carrier, trust_store, identity, mux)?;
		Ok((Negotiation::Secure(Box::new(pinned)), opening))
	}
}

/// One dial, parsed once from the values JavaScript hands over: the session
/// it opens, the stream cap the session grants, and the signal that aborts
/// it.
pub(crate) struct Dial {
	session: SessionKind,
	streams: u32,
	signal: Option<AbortSignal>,
}

impl Dial {
	/// A cleartext dial under `options`.
	///
	/// # Errors
	///
	/// - The errors of [`Self::parse`].
	pub(crate) fn cleartext(options: &JsValue) -> Result<Self, JsFault> {
		Self::parse(SessionKind::Cleartext, options)
	}

	/// A server-authenticated dial that pins the certificate
	/// `server_cert_der`, under `options`.
	///
	/// # Errors
	///
	/// - The errors of the certificate parse.
	/// - The errors of [`Self::parse`].
	pub(crate) fn server(server_cert_der: &JsValue, options: &JsValue) -> Result<Self, JsFault> {
		let pinned = certificate(server_cert_der, "serverCertDer")?;
		Self::parse(SessionKind::Server(Box::new(pinned)), options)
	}

	/// A mutually authenticated dial that presents `identity`, under
	/// `options`.
	///
	/// # Errors
	///
	/// - The errors of the [`MutualIdentity`] read.
	/// - The errors of [`Self::parse`].
	pub(crate) fn mutual(identity: &JsValue, options: &JsValue) -> Result<Self, JsFault> {
		let identity = Box::new(MutualIdentity::try_from(identity)?);
		Self::parse(SessionKind::Mutual { identity, offer: SessionOffer::default() }, options)
	}

	/// The dial of `session` under `options`, read once: the stream cap at
	/// the member the kind names, the signal, and each session knob. Absent
	/// options, or an absent member, take the default.
	///
	/// # Errors
	///
	/// - `InvalidConnectOptions` -- `options` is neither absent nor an object.
	/// - `InvalidStreamCap` -- the cap is no whole number from 1 to the `u32` ceiling, so zero,
	///   a fraction, a negative number, and `NaN` are refused.
	/// - The errors of [`Signal::read`] at `options.signal`.
	/// - The errors of [`SessionKind::offer`] for each knob the options name.
	fn parse(mut session: SessionKind, options: &JsValue) -> Result<Self, JsFault> {
		let object = match Record::present(options.clone()) {
			None => JsValue::UNDEFINED,
			Some(object) if object.is_object() => object,
			Some(_) => {
				let message =
					"dial options must be an object: a stream cap is an options field, not a positional argument";
				return Err(RefusalCode::InvalidConnectOptions.because(message));
			}
		};

		let cap = session.cap_member();
		let streams = match Record::optional_member(&object, cap) {
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

		let signal = Signal::read(&Record::member(&object, "options.signal"), "options.signal")?;
		for knob in Knob::ALL {
			if let Some(value) = Record::optional_member(&object, knob.member()) {
				session.offer(knob, &value)?;
			}
		}

		Ok(Self { session, streams, signal })
	}

	/// Dial `url` under the signal of this dial, and resolve with the split
	/// session, the usable send budget the handshake negotiated, and the
	/// monitor of the socket. An abort closes the socket.
	///
	/// # Errors
	///
	/// - The abort reason of the signal, when it aborted before the dial or aborts during it.
	/// - The errors of [`SessionKind::open`].
	/// - The errors of [`Negotiation::session`].
	pub(crate) async fn connect(mut self, url: &str) -> Result<Dialed, JsValue> {
		let signal = self.signal.take();
		if let Some(reason) = signal.aborted_reason() {
			return Err(reason);
		}

		let (negotiation, opening) = self.session.open(url, self.streams)?;
		let Opened { value: (parts, usable_send_budget), monitor } =
			opening.within(&signal, negotiation.session()).await?;
		Ok(Dialed { parts, usable_send_budget, monitor })
	}
}

/// A session that a dial opened.
pub(crate) struct Dialed {
	/// The split parts of the session.
	pub(crate) parts: SessionParts,
	/// The usable send budget that the handshake negotiated, or `None` when
	/// the session is unmetered.
	pub(crate) usable_send_budget: Option<u64>,
	/// The monitor of the socket.
	pub(crate) monitor: SocketMonitor,
}

/// The setup a dial runs over its opening socket, by the kind of session.
enum Negotiation {
	/// A cleartext session, which waits for the socket to open.
	Cleartext {
		/// Settles once the socket opened, or rejects when it closed first.
		opened: Pin<Box<dyn Future<Output = Result<(), JsValue>>>>,
		/// The stream over the socket.
		stream: GlooStream,
		/// The symmetric stream cap.
		streams: u32,
	},
	/// An encrypted session, which runs the HPKE handshake with the mux offer
	/// it holds.
	Secure(Box<Pinned<DefaultCryptoProvider>>),
}

impl Negotiation {
	/// Run the setup of this kind, and resolve with the split session and the
	/// usable send budget the handshake negotiated, `None` when unmetered.
	///
	/// # Errors
	///
	/// - `ConnectionClosed` -- the socket of a cleartext session closes before it opens.
	/// - The [`TransportError`](tightbeam::transport::TransportError) of a failed handshake.
	/// - `InvalidState` -- the server does not negotiate multiplexing.
	async fn session(self) -> Result<(SessionParts, Option<u64>), JsValue> {
		match self {
			Self::Cleartext { opened, stream, streams } => {
				opened.await?;

				let parts =
					BrowserSocket::cleartext_session(stream, MuxRole::Client, streams).map_err(JsFault::from)?;
				Ok((parts, None))
			}
			Self::Secure(pinned) => {
				let session = pinned.handshake().await.map_err(JsFault::from)?;

				let usable = session.usable_send_budget();
				let parts = session.split().map_err(JsFault::from)?;
				Ok((parts, usable))
			}
		}
	}
}
