//! Backend payload processor servlet for the processed-board demo.
//!
//! The demo server's `RelayBackplane` dials this servlet over a multiplexed
//! encrypted tightbeam-ws connection and relays each publish through it. The
//! registry then sequences and fans out the inner frame in each answer.
//!
//! Each relayed payload is an inner tightbeam frame whose body is a JSON note.
//! [`TopicSeal::transformed`] uppercases the note's `text` and rebuilds the
//! frame, sealed under the topic key of the stack. The rebuilt frame is
//! unsigned, because the changed note invalidates the publisher's signature.
//!
//! The [`DemoConfig`] of the environment decides the [`Security`] of every
//! connection. The processor pins the client certificate under mutual auth and
//! under the paywall alike, because the relay dial presents it in both.
//!
//! The processor pushes no stream of its own, so every connection serves
//! through upstream [`MuxAcceptor::serve`], behind the gate of its transport.
//!
//! Environment:
//!   - `TBWS_SERVER_CERT`       path to the server certificate DER, beside its key
//!   - `PUBSUB_PROCESSOR_PORT`  listen port (default `9111`)
//!   - `PUBSUB_TOPIC_KEY`       the key-encryption key of the processed topic, as 64 hex digits
//!   - `PUBSUB_TOPIC_KEY_ID`    the `kekid` that names the key in each sealed envelope
//!   - the variables of [`DemoConfig`]
//!
//! [`Security`]: tightbeam_ws::testing::Security

use core::fmt;
use core::str::{from_utf8, FromStr};
use std::error::Error;
use std::sync::Arc;

use serde_json::Value;
use tightbeam::der::{Decode, Encode};
use tightbeam::policy::{SessionContext, TransitStatus};
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::error::TransportError;
use tightbeam::transport::multiplex::MuxAcceptor;
use tightbeam::transport::EncryptedProtocol;
use tightbeam::{Frame, Opaque, TightBeamError};
use tightbeam_pubsub::testing::OpaqueFrame;
use tightbeam_ws::io::WsTransport;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::serve::LinkError;
use tightbeam_ws::testing::{DemoConfig, EnvVar, Identity};
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;

type BoxError = Box<dyn Error + Send + Sync>;

/// The transport an accepted WebSocket connection follows.
type ServerTransport = WsTransport<MaybeTlsStream<TcpStream>>;

/// The number of octets in a topic key.
const TOPIC_KEY_LEN: usize = 32;

/// The 32-octet key-encryption key of the processed topic, which the stack
/// spells as 64 hex digits.
struct TopicKey([u8; TOPIC_KEY_LEN]);

/// A topic key that is not 64 hex digits.
#[derive(Debug)]
struct NotATopicKey;

impl fmt::Display for NotATopicKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("a topic key is 64 hex digits")
	}
}

impl Error for NotATopicKey {}

impl FromStr for TopicKey {
	type Err = NotATopicKey;

	/// The key that `hex` spells, two digits per octet.
	///
	/// # Errors
	///
	/// - [`NotATopicKey`]: `hex` is not 64 hex digits.
	fn from_str(hex: &str) -> Result<Self, Self::Err> {
		let digits = hex.as_bytes();
		let spelled = digits.len() == 2 * TOPIC_KEY_LEN && digits.iter().all(u8::is_ascii_hexdigit);
		if !spelled {
			return Err(NotATopicKey);
		}

		let mut key = [0u8; TOPIC_KEY_LEN];
		for (octet, pair) in key.iter_mut().zip(digits.chunks_exact(2)) {
			let pair = from_utf8(pair).map_err(|_| NotATopicKey)?;
			*octet = u8::from_str_radix(pair, 16).map_err(|_| NotATopicKey)?;
		}

		Ok(Self(key))
	}
}

/// The seal of the processed topic: the pre-shared key, and the `kekid`
/// that names it in each sealed envelope. Subscribers declare the same pair
/// in their envelope (`sealed(Aes256Gcm.fromKey({ key, keyId }))`). A
/// production servlet would provision per-topic keys instead.
struct TopicSeal {
	key: TopicKey,
	key_id: String,
}

impl TopicSeal {
	/// Uppercase the `text` of the JSON note carried by the inner frame in
	/// `payload`, and return the DER of a rebuilt (unsigned) inner frame
	/// whose body is sealed under this seal.
	fn transformed(&self, payload: &[u8]) -> Result<Vec<u8>, BoxError> {
		let inner = Frame::from_der(payload)?;
		let body = inner.decode_message::<Opaque>()?;

		let mut note: Value = serde_json::from_slice(body.as_bytes())?;
		let object = note.as_object_mut().ok_or("the note payload must be a JSON object")?;
		let text = object.get("text").and_then(Value::as_str).ok_or("the note has no text field")?;
		let uppercased = text.to_uppercase();

		object.insert("text".to_owned(), Value::String(uppercased));

		let id = String::from_utf8_lossy(inner.metadata().id()).into_owned();
		let order = inner.metadata().order();
		let note = serde_json::to_vec(&note)?;
		let frame = OpaqueFrame { id: &id, order, payload: &note };

		let rebuilt = frame.sealed(&self.key.0, self.key_id.as_bytes())?;
		Ok(rebuilt.to_der()?)
	}

	/// Answer one relayed publish: transform the inner frame's note.
	///
	/// # Errors
	///
	/// - A refusal with [`TransitStatus::InvalidArgument`]: the body is not
	///   opaque, or its inner frame carries no note to transform.
	/// - The [`TightBeamError`] of the answer frame, which answers
	///   [`TransitStatus::Internal`].
	async fn answer(&self, frame: Frame) -> Result<Option<Frame>, TightBeamError> {
		let Ok(body) = frame.decode_message::<Opaque>() else {
			return Err(Self::refusal(TransitStatus::InvalidArgument));
		};

		let processed = match self.transformed(body.as_bytes()) {
			Ok(processed) => processed,
			Err(error) => {
				eprintln!("[pubsub-processor] transform failed: {error}");
				return Err(Self::refusal(TransitStatus::InvalidArgument));
			}
		};

		let id = String::from_utf8_lossy(frame.metadata().id()).into_owned();
		let order = frame.metadata().order();
		let answer = OpaqueFrame { id: &id, order, payload: &processed };
		let built = answer.build();
		if let Err(error) = &built {
			eprintln!("[pubsub-processor] answer build failed: {error}");
		}

		built.map(Some)
	}

	/// The failure that answers a relayed publish with `status`.
	fn refusal(status: TransitStatus) -> TightBeamError {
		let refused = TransportError::from(status);
		TightBeamError::from(refused)
	}
}

/// The variable that sets the listen port.
const PORT: EnvVar = EnvVar::new("PUBSUB_PROCESSOR_PORT");

/// The variable that spells the key of the processed topic.
const TOPIC_KEY: EnvVar = EnvVar::new("PUBSUB_TOPIC_KEY");

/// The variable that names the key of the processed topic in each sealed
/// envelope.
const TOPIC_KEY_ID: EnvVar = EnvVar::new("PUBSUB_TOPIC_KEY_ID");

/// One accepted encrypted connection of the processor, the demo
/// configuration that meters it, and the seal of every answer.
struct ProcessorConnection {
	transport: ServerTransport,
	demo: Arc<DemoConfig>,
	seal: Arc<TopicSeal>,
}

impl ProcessorConnection {
	/// Serve the connection until it ends.
	async fn serve(self) -> Result<(), BoxError> {
		let Self { transport, demo, seal } = self;

		let mut transport = demo.meter(transport);
		let negotiated = transport.negotiate_mux().await?;
		let settings = negotiated.ok_or(LinkError::NotMultiplexed)?;

		let service = move |frame, _session: SessionContext| {
			let seal = Arc::clone(&seal);
			async move { seal.answer(frame).await }
		};
		transport.serve(settings, service, None).await?;
		Ok(())
	}
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
	let port = PORT.parsed_or(9111u32)?;
	let bind_addr = TightBeamSocketAddr(format!("0.0.0.0:{port}").parse()?);
	let demo = Arc::new(DemoConfig::from_env()?);
	let key = TOPIC_KEY.parsed()?;
	let key_id = TOPIC_KEY_ID.parsed()?;
	let seal = Arc::new(TopicSeal { key, key_id });

	let identity = Identity::from_env()?;
	let config = demo.security().server_config(&identity)?;
	let (listener, bound) = <WsListener as EncryptedProtocol>::bind_with(bind_addr, config).await?;
	println!(
		"[pubsub-processor] encrypted ({}) payload processor servlet listening on ws://{}",
		demo.security(),
		bound.0
	);

	loop {
		// A failed accept is the listener's own fault, such as a descriptor
		// shortage, and it clears on retry.
		let (transport, peer) = match listener.accept().await {
			Ok(accepted) => accepted,
			Err(error) => {
				eprintln!("[pubsub-processor] accept failed: {error}");
				continue;
			}
		};

		let connection = ProcessorConnection { transport, demo: Arc::clone(&demo), seal: Arc::clone(&seal) };
		tokio::spawn(async move {
			if let Err(error) = connection.serve().await {
				eprintln!("[pubsub-processor] connection from {peer} ended: {error}");
			}
		});
	}
}
