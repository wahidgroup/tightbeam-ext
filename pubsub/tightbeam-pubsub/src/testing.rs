//! In-memory transport fixtures for tests and examples.
//!
//! Compiled under the `testing` feature. The memory link implements the
//! upstream envelope traits over channels, so a real client/server mux
//! pair runs in one process with no sockets.
//!
//! [`OpaqueFrame`] builds the frames a TypeScript client would build with its
//! frame builder, so integration tests and examples send them in its place.

use std::sync::Arc;

use tightbeam::builder::TypeBuilder;
use tightbeam::clock::{Clock, SystemClock};
use tightbeam::crypto::key::Aes256GcmKeyProvider;
use tightbeam::policy::{AcceptAllGate, SessionContext};
use tightbeam::transport::error::TransportError;
use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::multiplex::{MuxRole, MuxTransport};
use tightbeam::transport::{CheckedLimits, EnvelopeSink, EnvelopeSource, TransportEnvelope, TransportResult};
use tightbeam::{Frame, TightBeamError, Version};
use tightbeam_ws::serve::{AcceptedLink, LinkError, LinkParts};
use tokio::sync::mpsc::{channel, Receiver, Sender};

pub use crate::frame::OpaqueFrame;
use crate::topic::Topic;

/// Envelopes in flight per direction before writers wait.
const LINK_DEPTH: usize = 64;

/// The mux of one end of a [`MemoryLink`].
type MemoryMux = MuxTransport<MemorySource, MemorySink>;

/// The server end of a [`MemoryLink`], as the link a server accepts.
type MemoryServed = AcceptedLink<MemorySource, MemorySink>;

impl OpaqueFrame<'_> {
	/// The V1 frame whose opaque body is sealed to the key-encryption key
	/// `kek`, which `kek_id` names: what a TypeScript client's `sealed`
	/// envelope builds. Only a key holder opens the body.
	///
	/// The body seals under a fresh AES-256-GCM content key, wrapped under
	/// `kek` in a `KEKRecipientInfo`.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`]: the body or the frame fails
	///   to encode as DER.
	/// - Any other [`TightBeamError`] of
	///   [`TypeBuilder::build`](tightbeam::builder::TypeBuilder::build): the
	///   body fails to seal.
	///
	/// # Sources
	///
	/// - RFC 5083, CMS Authenticated-Enveloped-Data Content Type:
	///   <https://datatracker.ietf.org/doc/html/rfc5083>
	/// - RFC 5652 § 6.2.3, `KEKRecipientInfo`:
	///   <https://datatracker.ietf.org/doc/html/rfc5652#section-6.2.3>
	pub fn sealed(&self, kek: &[u8; 32], kek_id: &[u8]) -> Result<Frame, TightBeamError> {
		let framed = self.framed(Version::V1)?;
		let sealer = Aes256GcmKeyProvider::new(kek.to_vec(), kek_id.to_vec())?;
		framed.with_encryptor(sealer).build()
	}
}

impl Topic {
	/// The topic `name`, for a test or an example that names a valid topic.
	///
	/// # Panics
	///
	/// Panics when `name` fails [`Topic`] validation.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam_pubsub::Topic;
	///
	/// let topic = Topic::fixture("prices/spot");
	/// assert_eq!(topic.as_str(), "prices/spot");
	/// ```
	#[must_use]
	pub fn fixture(name: &str) -> Self {
		name.parse().expect("a fixture names a valid topic")
	}
}

/// Receive half of one in-memory link direction.
pub struct MemorySource {
	envelopes: Receiver<TransportEnvelope>,
}

impl EnvelopeSource for MemorySource {
	async fn read_envelope(&mut self) -> TransportResult<TransportEnvelope> {
		self.envelopes.recv().await.ok_or(TransportError::ConnectionClosed)
	}

	fn limits(&self) -> CheckedLimits {
		CheckedLimits::default()
	}
}

/// Send half of one in-memory link direction.
pub struct MemorySink {
	envelopes: Sender<TransportEnvelope>,
	clock: Arc<dyn Clock>,
}

impl EnvelopeSink for MemorySink {
	async fn write_envelope(&mut self, envelope: TransportEnvelope) -> TransportResult<()> {
		self.envelopes
			.send(envelope)
			.await
			.map_err(|_| TransportError::ConnectionClosed)
	}

	fn remaining_records(&self) -> u64 {
		u64::MAX
	}

	fn clock(&self) -> Arc<dyn Clock> {
		Arc::clone(&self.clock)
	}
}

/// The two halves of one end of a [`MemoryLink`].
struct MemoryEnd {
	source: MemorySource,
	sink: MemorySink,
}

/// An in-memory link between a client end and a server end. Every half
/// reads one clock, as the halves of one transport do.
///
/// The link skips the handshake negotiation, so [`MuxSettings::symmetric`]
/// matches cleartext multiplexing. A send budget on the settings meters what
/// each end may emit.
///
/// # Examples
///
/// ```
/// use tightbeam::transport::handshake::negotiation::MuxSettings;
/// use tightbeam_pubsub::testing::MemoryLink;
///
/// let link = MemoryLink::default();
/// let (_client, _server) = link.mux_pair(MuxSettings::symmetric(4));
/// ```
#[derive(Clone)]
pub struct MemoryLink {
	clock: Arc<dyn Clock>,
}

impl Default for MemoryLink {
	/// A link on the system clock.
	fn default() -> Self {
		Self::new(Arc::new(SystemClock))
	}
}

impl MemoryLink {
	/// A link whose halves read `clock`.
	pub fn new(clock: Arc<dyn Clock>) -> Self {
		Self { clock }
	}

	/// The clock every half of this link reads.
	#[must_use]
	pub fn clock(&self) -> Arc<dyn Clock> {
		Arc::clone(&self.clock)
	}

	/// A connected client and server mux over this link, both under
	/// `settings`.
	#[must_use]
	pub fn mux_pair(&self, settings: MuxSettings) -> (MemoryMux, MemoryMux) {
		let (client, server) = self.ends();

		let client_mux = MuxTransport::new(client.source, client.sink, MuxRole::Client, settings);
		let server_mux = MuxTransport::new(server.source, server.sink, MuxRole::Server, settings);
		(client_mux, server_mux)
	}

	/// A connected client mux, and the server end as the [`AcceptedLink`]
	/// that [`PubsubCommands::serve`](crate::PubsubCommands::serve) takes, both
	/// under `settings`.
	///
	/// The link runs no handshake, so its gate admits every call and its peer
	/// is anonymous.
	///
	/// # Errors
	///
	/// - [`LinkError::ClockCannotRace`]: the clock of this link cannot race a wait on the calling
	///   thread.
	pub fn served(&self, settings: MuxSettings) -> Result<(MemoryMux, MemoryServed), LinkError> {
		let (client, server) = self.ends();
		let client_mux = MuxTransport::new(client.source, client.sink, MuxRole::Client, settings);
		let parts = LinkParts {
			reader: server.source,
			writer: server.sink,
			settings,
			gate: Box::new(AcceptAllGate),
			session: SessionContext::default(),
		};

		let server_link = AcceptedLink::from_parts(parts)?;
		Ok((client_mux, server_link))
	}

	/// The halves of the two ends: the client's, then the server's.
	fn ends(&self) -> (MemoryEnd, MemoryEnd) {
		let (to_server, from_client) = channel(LINK_DEPTH);
		let (to_client, from_server) = channel(LINK_DEPTH);

		let client = MemoryEnd {
			source: MemorySource { envelopes: from_server },
			sink: MemorySink { envelopes: to_server, clock: self.clock() },
		};
		let server = MemoryEnd {
			source: MemorySource { envelopes: from_client },
			sink: MemorySink { envelopes: to_client, clock: self.clock() },
		};
		(client, server)
	}
}

/// The faults that the unit tests of this crate inject.
#[cfg(test)]
pub(crate) mod faults {
	use der::{Error as DerError, ErrorKind};

	use crate::backplane::{DeliverError, UpdateSink};
	use crate::topic::Topic;

	/// A node whose every update frame fails to build: the hard refusal that
	/// fails a publish closed.
	pub(crate) struct Rejector;

	impl UpdateSink for Rejector {
		fn deliver(&self, _topic: &Topic, _order: u64, _payload: &[u8]) -> Result<(), DeliverError> {
			let encoding = DerError::from(ErrorKind::Failed);
			Err(DeliverError::Build(encoding.into()))
		}

		fn has_members(&self, _topic: &Topic) -> bool {
			false
		}
	}
}
