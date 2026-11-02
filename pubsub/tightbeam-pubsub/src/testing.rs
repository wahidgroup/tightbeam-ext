//! In-memory transport fixtures for tests and examples.
//!
//! Compiled under the `testing` feature. The memory link implements the
//! upstream envelope traits over channels, so a real client/server mux
//! pair runs in one process with no sockets.

use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::crypto::key::Aes256GcmKeyProvider;
use tightbeam::der::asn1::OctetString;
use tightbeam::transport::error::TransportError;
use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::multiplex::{MuxRole, MuxTransport};
use tightbeam::transport::{EnvelopeSink, EnvelopeSource, TransportEnvelope, TransportResult};
use tightbeam::{Frame, TightBeamError, Version};
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::frame::{build, OpaqueBody};

/// Envelopes in flight per direction before writers wait.
const LINK_DEPTH: usize = 64;

/// A client-built frame carrying a wire command or payload: the fixture
/// integration tests and examples send where a TypeScript client would
/// use its frame builder.
///
/// # Errors
///
/// Returns [`TightBeamError`] when the opaque body or frame fails to build.
pub fn command_frame(id: &str, order: u64, payload: &[u8]) -> Result<Frame, TightBeamError> {
	build(id, order, payload)
}

/// A V1 frame whose opaque body is sealed to the key-encryption key `kek`,
/// which `kek_id` names: what a TypeScript client's `sealed` envelope
/// builds. Only a key holder opens the body.
///
/// The body seals under a fresh AES-256-GCM content key, wrapped under `kek`
/// in a `KEKRecipientInfo`.
///
/// # Errors
///
/// Returns [`TightBeamError`] when the body or the envelope fails to build.
///
/// # Sources
///
/// - RFC 5083, CMS Authenticated-Enveloped-Data Content Type:
///   <https://datatracker.ietf.org/doc/html/rfc5083>
/// - RFC 5652 § 6.2.3, `KEKRecipientInfo`:
///   <https://datatracker.ietf.org/doc/html/rfc5652#section-6.2.3>
pub fn sealed_command_frame(
	id: &str,
	order: u64,
	payload: &[u8],
	kek: &[u8; 32],
	kek_id: &[u8],
) -> Result<Frame, TightBeamError> {
	let body = OpaqueBody { body: OctetString::new(payload)? };
	let sealer = Aes256GcmKeyProvider::new(kek.to_vec(), kek_id.to_vec())?;

	FrameBuilder::<OpaqueBody>::from(Version::V1)
		.with_id(id)
		.with_order(order)
		.with_message(body)
		.with_encryptor(sealer)
		.build()
}

/// Receive half of one in-memory link direction.
pub struct MemorySource {
	envelopes: Receiver<TransportEnvelope>,
}

impl EnvelopeSource for MemorySource {
	async fn read_envelope(&mut self) -> TransportResult<TransportEnvelope> {
		self.envelopes.recv().await.ok_or(TransportError::ConnectionClosed)
	}
}

/// Send half of one in-memory link direction.
pub struct MemorySink {
	envelopes: Sender<TransportEnvelope>,
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
}

/// A connected client/server mux pair over in-memory links with a
/// symmetric stream cap, matching cleartext multiplexing.
pub fn memory_mux_pair(cap: u32) -> (MuxTransport<MemorySource, MemorySink>, MuxTransport<MemorySource, MemorySink>) {
	let (to_server, from_client) = channel(LINK_DEPTH);
	let (to_client, from_server) = channel(LINK_DEPTH);

	let client = MuxTransport::new(
		MemorySource { envelopes: from_server },
		MemorySink { envelopes: to_server },
		MuxRole::Client,
		MuxSettings::symmetric(cap),
	);
	let server = MuxTransport::new(
		MemorySource { envelopes: from_client },
		MemorySink { envelopes: to_client },
		MuxRole::Server,
		MuxSettings::symmetric(cap),
	);

	(client, server)
}
