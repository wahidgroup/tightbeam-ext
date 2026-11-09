//! The demo environment that the e2e stack's example servers share, and the
//! security kind that decides both halves of a demo connection.
//!
//! Compiled only under the `testing` feature.

use core::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::transport::handshake::negotiation::{MuxBudgets, TransportAuthorizer, TransportOffer};
use tightbeam::transport::handshake::receipt::ReceiptApprover;
use tightbeam::transport::TransportEncryptionConfig;
use tightbeam::x509::Certificate;
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;

use super::env::EnvVar;
use super::fixtures::{Identity, IdentityFiles};
use super::handshake::Pinned;
use super::paywall::DemoPaywall;
use crate::io::WsTransport;
use crate::Result;

/// The variable that sets the stream cap an endpoint grants its peer.
const STREAMS: EnvVar = EnvVar::new("MUX_STREAMS");

/// The variable naming the client certificate DER file, which sits beside its
/// signing key.
const CLIENT_CERT: EnvVar = EnvVar::new("TBWS_CLIENT_CERT");

/// The variable that switches the demo paywall on.
const PAYWALL: EnvVar = EnvVar::new("TBWS_PAYWALL");

/// The variable holding the invoice that challenges each paywalled session.
const INVOICE: EnvVar = EnvVar::new("TBWS_DEMO_INVOICE");

/// The variable holding the payment that settles the invoice.
const PAYMENT: EnvVar = EnvVar::new("TBWS_DEMO_PAYMENT");

/// The variable that sets the client-to-server credit ceiling.
const BUDGET_C2S: EnvVar = EnvVar::new("TBWS_MUX_BUDGET_C2S");

/// The variable that sets the server-to-client credit ceiling.
const BUDGET_S2C: EnvVar = EnvVar::new("TBWS_MUX_BUDGET_S2C");

/// The transport of a demo WebSocket, accepted or dialed.
type DemoTransport = WsTransport<MaybeTlsStream<TcpStream>>;

/// The demo environment that every example server shares, parsed once.
///
/// The `scripts/stack-env.sh` of each extension writes the stack facts, and
/// the compose files pass them on, so this parse holds no default for any of
/// them.
///
/// # Environment
///
/// - `MUX_STREAMS`: the stream cap an endpoint grants its peer. A cleartext dial passes the same cap.
/// - `TBWS_CLIENT_CERT`: the client certificate DER file, beside its key. A server pins it when set.
/// - `TBWS_PAYWALL`: a flag word that switches the paywall on. The paywall requires `TBWS_CLIENT_CERT`.
/// - `TBWS_DEMO_INVOICE` and `TBWS_DEMO_PAYMENT`: the invoice and the payment that settles it.
/// - `TBWS_MUX_BUDGET_C2S` and `TBWS_MUX_BUDGET_S2C`: the credit ceiling of each direction.
///
/// The paywall reads its four facts only when the flag is on, and each one is
/// required then.
///
/// # Examples
///
/// ```
/// use tightbeam_ws::testing::{DemoConfig, Security};
///
/// # std::env::set_var("MUX_STREAMS", "6");
/// # std::env::remove_var("TBWS_CLIENT_CERT");
/// # std::env::remove_var("TBWS_PAYWALL");
/// let config = DemoConfig::from_env()?;
/// assert_eq!(config.streams(), 6);
/// assert!(matches!(config.security(), Security::ServerAuth));
/// # Ok::<(), tightbeam_ws::Error>(())
/// ```
pub struct DemoConfig {
	security: Security,
	streams: u32,
}

impl DemoConfig {
	/// Parse the demo environment of this process.
	///
	/// # Errors
	///
	/// - [`Error::Env`](crate::Error::Env): a variable holds a value that does
	///   not parse, `MUX_STREAMS` is unset, or the paywall is on and
	///   `TBWS_CLIENT_CERT` or a paywall fact is unset.
	/// - [`Error::Io`](crate::Error::Io): the client identity files do not
	///   read.
	/// - [`Error::Tightbeam`](crate::Error::Tightbeam): the client identity, the
	///   invoice, or the payment does not decode.
	pub fn from_env() -> Result<Self> {
		let streams = STREAMS.parsed()?;
		let paywalled = PAYWALL.flag()?;
		let client_cert = CLIENT_CERT.path();

		// `path` refuses only an unset variable, so an error is an absent
		// client certificate.
		let security = match (client_cert, paywalled) {
			(Err(_), false) => Security::ServerAuth,
			(Err(unset), true) => return Err(unset.into()),
			(Ok(certificate), false) => Security::Mutual { pinned: Self::client(certificate)? },
			(Ok(certificate), true) => {
				let pinned = Self::client(certificate)?;
				let paywall = Self::paywall()?;
				Security::Paywalled { pinned, paywall }
			}
		};

		Ok(Self { security, streams })
	}

	/// The security kind of the servers and of their dials.
	#[must_use]
	pub fn security(&self) -> &Security {
		&self.security
	}

	/// The stream cap that an endpoint grants its peer.
	#[must_use]
	pub fn streams(&self) -> u32 {
		self.streams
	}

	/// `transport`, which a demo server accepted, metered by
	/// [`Security::meter`] at the stream cap of this config.
	#[must_use]
	pub fn meter(&self, transport: DemoTransport) -> DemoTransport {
		self.security.meter(transport, self.streams)
	}

	/// `transport`, which dials a demo server, metered by
	/// [`Security::meter_dial`] at the stream cap of this config. A paywalled
	/// kind pays its invoice up to `payments` times.
	#[must_use]
	pub fn meter_dial(&self, transport: DemoTransport, payments: usize) -> DemoTransport {
		self.security.meter_dial(transport, self.streams, payments)
	}

	/// The client identity whose certificate file is `certificate`.
	fn client(certificate: PathBuf) -> Result<Identity> {
		let files = IdentityFiles::of_certificate(certificate)?;
		files.load()
	}

	/// The paywall that the four paywall facts describe.
	fn paywall() -> Result<Arc<DemoPaywall>> {
		let invoice: String = INVOICE.parsed()?;
		let payment: String = PAYMENT.parsed()?;
		let client_to_server = BUDGET_C2S.parsed()?;
		let server_to_client = BUDGET_S2C.parsed()?;

		let ceiling = MuxBudgets { client_to_server, server_to_client };
		let paywall = DemoPaywall::new(invoice, payment, ceiling)?;
		Ok(Arc::new(paywall))
	}
}

/// Which identity of a [`Security`] kind a client certificate is, as
/// [`Security::peer_identity`] decides it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerIdentity {
	/// The handshake authenticated no client certificate.
	None,
	/// The certificate is the client identity that the kind pins.
	Pinned,
	/// The certificate is not the client identity that the kind pins.
	Unpinned,
}

impl PeerIdentity {
	/// The name that the spec of a scenario grades: `none`, `pinned`, or
	/// `unpinned`.
	#[must_use]
	pub const fn as_str(self) -> &'static str {
		match self {
			Self::None => "none",
			Self::Pinned => "pinned",
			Self::Unpinned => "unpinned",
		}
	}
}

/// How a demo server authenticates its clients, and how a dial answers a
/// server of the same kind.
///
/// A paywall exists only beside a pinned client identity, so a paywalled
/// server is always mutual. One value decides both halves of a connection.
/// The server half reads [`server_config`](Self::server_config) and
/// [`meter`](Self::meter). The dial half reads
/// [`client_identity`](Self::client_identity) and
/// [`meter_dial`](Self::meter_dial).
///
/// | Kind | The server pins | A dial presents | A dial pays |
/// | --- | --- | --- | --- |
/// | [`ServerAuth`](Self::ServerAuth) | no client | no certificate | nothing |
/// | [`Mutual`](Self::Mutual) | the client identity | the client identity | nothing |
/// | [`Paywalled`](Self::Paywalled) | the client identity | the client identity | the invoice of the paywall |
///
/// # Examples
///
/// ```
/// use tightbeam_ws::testing::Security;
///
/// let security = Security::ServerAuth;
/// assert!(security.client_identity().is_none());
/// assert_eq!(security.to_string(), "server-auth");
/// ```
pub enum Security {
	/// The server presents its identity and pins no client.
	ServerAuth,
	/// The server pins the client identity.
	Mutual {
		/// The client identity that the server pins and a dial presents.
		pinned: Identity,
	},
	/// The server pins the client identity, and the paywall meters every
	/// session.
	Paywalled {
		/// The client identity that the server pins and a dial presents.
		pinned: Identity,
		/// The paywall that meters every session.
		paywall: Arc<DemoPaywall>,
	},
}

impl Security {
	/// The server transport config that presents `identity` and pins the
	/// client identity that a dial of this kind presents.
	///
	/// # Errors
	///
	/// - The errors of [`Identity::server_config`] and [`Pinned::validators`].
	pub fn server_config(&self, identity: &Identity) -> Result<TransportEncryptionConfig<DefaultCryptoProvider>> {
		let config = identity.server_config()?;
		let Some(client) = self.client_identity() else {
			return Ok(config);
		};

		let pinned = Pinned::from(client.certificate().clone());
		let validators = pinned.validators()?;
		Ok(config.with_client_validators(validators))
	}

	/// `transport`, which a server of this kind accepted, with the mux offer
	/// of `streams` streams.
	///
	/// A paywalled kind advertises the ceiling of its paywall and installs the
	/// paywall as the authorizer of the handshake.
	#[must_use]
	pub fn meter(&self, transport: DemoTransport, streams: u32) -> DemoTransport {
		let offer = self.offer(streams);
		let offered = transport.with_mux_offer(Some(offer));
		let Self::Paywalled { paywall, .. } = self else {
			return offered;
		};

		let shared = Arc::clone(paywall);
		let authorizer: Arc<dyn TransportAuthorizer> = shared;
		offered.with_transport_authorizer(authorizer)
	}

	/// The client identity that a dial of this kind presents.
	///
	/// A mutual and a paywalled kind present the identity that a server of
	/// the same kind pins. A server-auth kind presents none.
	#[must_use]
	pub fn client_identity(&self) -> Option<&Identity> {
		match self {
			Self::ServerAuth => None,
			Self::Mutual { pinned } | Self::Paywalled { pinned, .. } => Some(pinned),
		}
	}

	/// Which identity of this kind `peer`, the client certificate that a
	/// handshake authenticated, is.
	///
	/// The whole certificate decides, so a certificate that only shares the
	/// subject of the pinned identity is another certificate.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam_ws::testing::{PeerIdentity, Security};
	///
	/// assert_eq!(Security::ServerAuth.peer_identity(None), PeerIdentity::None);
	/// ```
	#[must_use]
	pub fn peer_identity(&self, peer: Option<&Certificate>) -> PeerIdentity {
		let Some(peer) = peer else {
			return PeerIdentity::None;
		};

		let pinned = self.client_identity().map(Identity::certificate);
		if pinned == Some(peer) {
			PeerIdentity::Pinned
		} else {
			PeerIdentity::Unpinned
		}
	}

	/// `transport`, which dials a server of this kind, with the mux offer of
	/// `streams` streams.
	///
	/// A paywalled kind requests the ceiling of its paywall and pays its
	/// invoice up to `payments` times, at the handshake and at each renewal.
	#[must_use]
	pub fn meter_dial(&self, transport: DemoTransport, streams: u32, payments: usize) -> DemoTransport {
		let offer = self.offer(streams);
		let offered = transport.with_mux_offer(Some(offer));
		let Self::Paywalled { paywall, .. } = self else {
			return offered;
		};

		let wallet: Arc<dyn ReceiptApprover> = Arc::new(paywall.wallet(payments));
		offered.with_receipt_approver(wallet)
	}

	/// The mux offer of `streams` streams that both halves of this kind make,
	/// with the ceiling of the paywall when the kind is paywalled.
	fn offer(&self, streams: u32) -> TransportOffer {
		let offer = TransportOffer::mux(streams);
		let Self::Paywalled { paywall, .. } = self else {
			return offer;
		};

		offer.with_budgets(paywall.ceiling())
	}
}

/// The mode that a demo server logs: `server-auth`, `mutual-auth`, or
/// `mutual-auth+paywall`.
impl fmt::Display for Security {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let mode = match self {
			Self::ServerAuth => "server-auth",
			Self::Mutual { .. } => "mutual-auth",
			Self::Paywalled { .. } => "mutual-auth+paywall",
		};

		f.write_str(mode)
	}
}

#[cfg(test)]
mod tests {
	use std::env;

	use super::DemoConfig;
	use crate::testing::EnvError;
	use crate::Error;

	#[test]
	fn a_paywalled_config_without_a_client_cert_is_refused() {
		env::set_var("MUX_STREAMS", "4");
		env::set_var("TBWS_PAYWALL", "on");
		env::remove_var("TBWS_CLIENT_CERT");

		let config = DemoConfig::from_env();
		assert!(matches!(config, Err(Error::Env(EnvError::Unset("TBWS_CLIENT_CERT")))));
	}
}
