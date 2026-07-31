//! One-call serving for a multiplexed pub/sub connection.
//!
//! [`serve_connection`] owns the whole per-connection ceremony: spawn
//! the mux drivers, register the connection with the registry behind
//! the commands, answer the wire commands, hand every other stream to
//! the application, and clean up when the serve loop ends.
//!
//! ```ignore
//! let mux = MuxTransport::new(reader, writer, MuxRole::Server, settings);
//! serve_connection(mux, commands.clone(), unrouted).await?;
//! ```

use std::future::Future;
use std::sync::Arc;

use tightbeam::policy::TransitStatus;
use tightbeam::transport::io::{EnvelopeSink, EnvelopeSource};
use tightbeam::transport::multiplex::{MuxHandle, MuxTransport};
use tightbeam::transport::{ResponsePackage, TransportResult};
use tightbeam::Frame;

use crate::dispatch::PubsubCommands;
use crate::policy::SubscribePolicy;
use crate::registry::ConnectionId;

/// What one served connection's application handler works with.
#[derive(Clone)]
pub struct ConnectionContext {
	/// The registry id this connection's subscriptions hang off.
	pub connection: ConnectionId,
	/// The connection's emit handle, for server-initiated streams.
	pub handle: MuxHandle,
}

/// The application handler for streams no wire command claims. Answer
/// [`unrouted`] serves a command-only connection.
///
/// `Sync` because the responder shares one handler across the
/// connection's concurrent streams.
pub trait AppRoutes<F>: Fn(ConnectionContext, Arc<Frame>) -> F + Clone + Send + Sync + 'static {}

impl<A, F> AppRoutes<F> for A where A: Fn(ConnectionContext, Arc<Frame>) -> F + Clone + Send + Sync + 'static {}

/// The command-only application handler: every non-command stream
/// answers `Unimplemented`.
pub async fn unrouted(_context: ConnectionContext, _frame: Arc<Frame>) -> ResponsePackage {
	ResponsePackage::new(TransitStatus::Unimplemented, None)
}

/// Serve one anonymous multiplexed connection until it ends.
///
/// Wire commands answer through `commands`; everything else goes to
/// `app`. The connection registers on entry and drops (with all its
/// subscriptions) on exit, whatever ended the serve loop.
pub async fn serve_connection<R, W, P, A, F>(
	mux: MuxTransport<R, W>,
	commands: PubsubCommands<P>,
	app: A,
) -> TransportResult<()>
where
	R: EnvelopeSource + Send + 'static,
	W: EnvelopeSink + Send + 'static,
	P: SubscribePolicy + 'static,
	A: AppRoutes<F>,
	F: Future<Output = ResponsePackage> + Send,
{
	serve(mux, commands, None, app).await
}

/// [`serve_connection`], registered under `identity` (a mutual-auth
/// peer certificate DER is the expected source) so the policies can
/// authorize by caller.
pub async fn serve_connection_as<R, W, P, A, F>(
	mux: MuxTransport<R, W>,
	commands: PubsubCommands<P>,
	identity: impl Into<Vec<u8>>,
	app: A,
) -> TransportResult<()>
where
	R: EnvelopeSource + Send + 'static,
	W: EnvelopeSink + Send + 'static,
	P: SubscribePolicy + 'static,
	A: AppRoutes<F>,
	F: Future<Output = ResponsePackage> + Send,
{
	serve(mux, commands, Some(identity.into()), app).await
}

async fn serve<R, W, P, A, F>(
	mux: MuxTransport<R, W>,
	commands: PubsubCommands<P>,
	identity: Option<Vec<u8>>,
	app: A,
) -> TransportResult<()>
where
	R: EnvelopeSource + Send + 'static,
	W: EnvelopeSink + Send + 'static,
	P: SubscribePolicy + 'static,
	A: AppRoutes<F>,
	F: Future<Output = ResponsePackage> + Send,
{
	let (handle, reader, writer, responder) = mux.into_parts();
	let reader_task = tokio::spawn(reader.drive());
	let writer_task = tokio::spawn(writer.drive());

	let registry = commands.registry().clone();
	let connection = match identity {
		Some(identity) => registry.register_connection_as(handle.clone(), identity),
		None => registry.register_connection(handle.clone()),
	};

	let outcome = responder
		.serve(move |frame| {
			let commands = commands.clone();
			let app = app.clone();
			let context = ConnectionContext { connection, handle: handle.clone() };
			async move {
				if let Some(answer) = commands.answer(connection, &frame) {
					return answer;
				}
				app(context, frame).await
			}
		})
		.await;

	registry.drop_connection(connection);
	reader_task.abort();
	writer_task.abort();
	outcome
}
