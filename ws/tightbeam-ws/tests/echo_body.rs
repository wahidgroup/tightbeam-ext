//! Each echo body of the e2e servers serves its own stream kinds alone, over
//! an encrypted loopback link, as tightbeam scenarios.

#![cfg(feature = "testing")]

pub mod support;

use core::time::Duration;
use std::io;

use tightbeam::instrumentation::events;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::SetupEnv;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::multiplex::{MuxAcceptor, MuxRole};
use tightbeam::transport::{EncryptedMessageIO, EncryptedProtocol};
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn, TightBeamError};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::serve::AcceptedLink;
use tightbeam_ws::testing::{EchoBody, Identity, Security};

use support::Answers;

/// The stream kinds that a body answered, joined by commas.
const SERVED: Urn<'static> = urn!("test", "event:echo-body/served");

/// The stream cap that both ends offer.
const STREAMS: u32 = 4;

/// Serve `body` on one server-auth link on loopback, open one stream of each
/// kind against it, and record on `trace` the kinds that answered.
async fn served_kinds(body: EchoBody, trace: &TraceCollector) -> Result<(), TightBeamError> {
	let server = Identity::mint("CN=echo body server,O=tightbeam-ws,C=US", 1, Duration::from_secs(3600))?;
	let security = Security::ServerAuth;
	let loopback = TightBeamSocketAddr("127.0.0.1:0".parse()?);
	let config = security.server_config(&server)?;
	let (listener, addr) = <WsListener as EncryptedProtocol>::bind_with(loopback, config).await?;

	let traced = trace.share();
	let serving = tokio::spawn(async move {
		let (transport, _peer) = listener.accept().await?;
		let mut metered = Security::ServerAuth.meter(transport.with_trace(traced), STREAMS);
		metered.negotiate_mux().await?;

		let link = AcceptedLink::accepted(metered).map_err(io::Error::other)?;
		body.serve(link.spawn()).await?;
		Ok::<(), TightBeamError>(())
	});

	let builder = security.client_builder::<WsListener>(server.trust_anchor()?);
	let dialed = builder.connect(addr).await?;
	let mut transport = security.meter_dial(dialed.into_transport(), STREAMS, 1);
	transport.perform_client_handshake().await?;

	let client = transport.into_mux(MuxRole::Client)?.spawn();
	let answers = Answers::of(&client.handle).await;
	serving.abort();

	trace.event_with(SERVED, &[], answers?.answered())?;
	Ok(())
}

/// One scenario per echo body, and the spec that grades it: the body answers
/// the kinds it names, and the responder refuses each other kind.
macro_rules! served {
	($($name:ident: $body:expr => $spec:ident, $kinds:expr, $refused:expr;)*) => {
		$(
			tb_assert_spec! {
				pub $spec,
				V(1,0,0): {
					mode: Accept,
					assertions: [
						(SERVED, exactly!(1), equals!($kinds)),
						(events::MUX_STREAM_REFUSED, exactly!($refused))
					]
				}
			}

			tb_scenario! {
				name: $name,
				spec: $spec,
				environment Bare {
					exec: |SetupEnv { trace, .. }| async move { served_kinds($body, &trace).await }
				}
			}
		)*
	};
}

served! {
	the_streaming_body_serves_unary_and_streaming: EchoBody::Streaming => StreamingBodySpec, "unary,streaming", 1;
	the_unary_body_serves_unary_alone: EchoBody::Unary => UnaryBodySpec, "unary", 2;
	the_duplex_body_serves_duplex_alone: EchoBody::Duplex => DuplexBodySpec, "duplex", 2;
}
