//! The peer a served connection registers under, as tightbeam scenarios over
//! loopback dials with a real handshake. The page `docs/pubsub.md` (Testing)
//! states what each spec grades.

mod support;

use core::time::Duration;
use std::io;
use std::sync::Arc;

use support::DEADLINE;
use tightbeam::policy::{SessionContext, TransitStatus};
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::{ClientEnv, SetupEnv};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::error::{TransportError, TransportFailure};
use tightbeam::transport::multiplex::{MuxAcceptor, MuxRole};
use tightbeam::transport::{EncryptedMessageIO, EncryptedProtocol};
use tightbeam::{exactly, tb_assert_spec, tb_scenario, TightBeamError};
use tightbeam_pubsub::events::{COMMAND_REFUSED, CONNECTION_ADMITTED};
use tightbeam_pubsub::{
	AccessVerdict, OpaqueFrame, PubsubCommands, RegistryView, SubscribePolicy, Topic, TopicRegistry, Unrouted,
};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::serve::AcceptedLink;
use tightbeam_ws::testing::{Identity, PeerIdentity, Security};
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// The stream cap that both ends offer.
const STREAMS: u32 = 4;

/// How long each identity stays valid.
const VALIDITY: Duration = Duration::from_secs(3600);

/// The server of a scenario, and the socket address it bound.
type Served = Result<(JoinHandle<Result<(), TightBeamError>>, TightBeamSocketAddr), TightBeamError>;

/// Allows a topic only to the client identity that the security kind of its
/// case pins.
struct PinnedOnly(Arc<Case>);

impl SubscribePolicy for PinnedOnly {
	fn authorize(&self, _registry: RegistryView<'_>, session: &SessionContext, _topic: &Topic) -> AccessVerdict {
		let peer = self.0.security.peer_identity(session.peer_certificate());
		if peer == PeerIdentity::Pinned {
			return AccessVerdict::Allow;
		}

		AccessVerdict::Forbid
	}
}

/// The identity of a server or a client.
fn identity(subject: &str, serial: u32) -> Identity {
	let issued = Identity::mint(subject, serial, VALIDITY);
	issued.expect("the identity is issued")
}

/// One served dial of a security kind: the identity of the server, and the
/// kind.
struct Case {
	server: Identity,
	security: Security,
}

impl Case {
	/// A case of `security` against the one server identity of this file.
	fn of(security: Security) -> Self {
		let server = identity("CN=pubsub serve server,O=tightbeam-pubsub,C=US", 1);
		Self { server, security }
	}

	/// The kind that pins the client identity of this file.
	fn mutual() -> Self {
		let client = identity("CN=pubsub serve client,O=tightbeam-pubsub,C=US", 2);
		Self::of(Security::Mutual { pinned: client })
	}

	/// Bind a server of this kind on loopback, and on a task accept one dial
	/// on a transport that records on `trace` and serve it through a registry
	/// whose subscribe policy admits the pinned client alone.
	async fn serve(case: Arc<Self>, trace: TraceCollector) -> Served {
		let config = case.security.server_config(&case.server)?;
		let loopback = TightBeamSocketAddr("127.0.0.1:0".parse()?);
		let (listener, addr) = <WsListener as EncryptedProtocol>::bind_with(loopback, config).await?;

		let commands = PubsubCommands::new(TopicRegistry::default(), PinnedOnly(Arc::clone(&case)));
		let serving = tokio::spawn(async move {
			let (transport, _peer) = listener.accept().await?;
			let mut metered = case.security.meter(transport.with_trace(trace), STREAMS);
			metered.negotiate_mux().await?;

			let link = AcceptedLink::accepted(metered).map_err(io::Error::other)?;
			commands.serve(link, Unrouted).await?;
			Ok(())
		});

		Ok((serving, addr))
	}

	/// Dial `addr` under this kind, pinning the server, on a transport that
	/// records on `trace`, and answer how the server answered one `sub/`.
	async fn subscribe(
		&self,
		addr: TightBeamSocketAddr,
		trace: &TraceCollector,
	) -> Result<TransitStatus, TightBeamError> {
		let trust = self.server.trust_anchor()?;
		let builder = self.security.client_builder::<WsListener>(trust);

		let dialed = builder.connect(addr).await?;
		let traced = dialed.into_transport().with_trace(trace.share());
		let mut transport = self.security.meter_dial(traced, STREAMS, 1);
		transport.perform_client_handshake().await?;

		let mux = transport.into_mux(MuxRole::Client)?.spawn();
		let command = OpaqueFrame { id: "sub/prices", order: 1, payload: b"" }.build()?;
		let emitted = timeout(DEADLINE, mux.handle.emit_on_stream(&command)).await;
		let answered = emitted.map_err(io::Error::from)?;
		match answered {
			Ok(_) => Ok(TransitStatus::Ok),
			Err(TransportError::OperationFailed(TransportFailure::PermissionDenied)) => {
				Ok(TransitStatus::PermissionDenied)
			}
			Err(failure) => Err(failure.into()),
		}
	}
}

tb_assert_spec! {
	pub HandshakePeerSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(CONNECTION_ADMITTED, exactly!(1)),
			(COMMAND_REFUSED, exactly!(0))
		]
	}
}

// A served connection registers under the peer that its handshake proved, so
// the subscribe policy reads the pinned client certificate and admits it.
tb_scenario! {
	name: a_served_connection_registers_under_its_handshake_peer,
	spec: HandshakePeerSpec,
	environment ServiceClient {
		context: Case::mutual(),
		server: |SetupEnv { trace, context }| Case::serve(context, trace),
		client: |ClientEnv { trace, context, addr }| async move {
			let answered = context.subscribe(addr, &trace).await?;
			assert_eq!(answered, TransitStatus::Ok, "the pinned client should subscribe");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub AnonymousPeerSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(CONNECTION_ADMITTED, exactly!(1)),
			(COMMAND_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied))
		]
	}
}

// An anonymous connection registers with no peer, so the subscribe policy
// reads no certificate and the registry refuses the `sub/`.
tb_scenario! {
	name: an_anonymous_connection_registers_with_no_peer,
	spec: AnonymousPeerSpec,
	environment ServiceClient {
		context: Case::of(Security::ServerAuth),
		server: |SetupEnv { trace, context }| Case::serve(context, trace),
		client: |ClientEnv { trace, context, addr }| async move {
			let answered = context.subscribe(addr, &trace).await?;
			assert_eq!(answered, TransitStatus::PermissionDenied, "an anonymous client should be refused");
			Ok(())
		}
	}
}
