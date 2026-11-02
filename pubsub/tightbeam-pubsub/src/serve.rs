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
use std::time::Duration;

use tightbeam::constants::DEFAULT_OPERATION_TIMEOUT;
use tightbeam::policy::TransitStatus;
use tightbeam::transport::io::{EnvelopeSink, EnvelopeSource};
use tightbeam::transport::multiplex::{MuxHandle, MuxTransport};
use tightbeam::transport::{ResponsePackage, TransportResult};
use tightbeam::Frame;

use crate::dispatch::PubsubCommands;
use crate::policy::SubscribePolicy;
use crate::registry::ConnectionId;

/// How often a served connection pings its peer: a third of the default
/// operation deadline, so one lost probe leaves the link inside the deadline.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(DEFAULT_OPERATION_TIMEOUT.as_secs() / 3);

/// Ping the peer of `handle` every `interval` until the connection ends, so an
/// idle link outlives the read deadline of both ends.
///
/// A probe and its ack each count as a read on the end that receives them, and
/// neither allocates a stream nor reaches the peer's application handler. An
/// operator that lowers the operation timeout passes an interval below it.
pub async fn keep_alive(handle: MuxHandle, interval: Duration) {
	let mut ticks = tokio::time::interval(interval);

	// The first tick completes at once, and a new link needs no probe.
	ticks.tick().await;

	loop {
		ticks.tick().await;
		if handle.ping().await.is_err() {
			return;
		}
	}
}

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
/// Wire commands answer through `commands`. Everything else goes to
/// `app`. The connection registers on entry and drops (with all its
/// subscriptions) on exit, whatever ended the serve loop.
///
/// # Errors
///
/// Returns a [`TransportError`](tightbeam::transport::TransportError)
/// when the mux drivers or responder fail. The connection is unregistered
/// before the error is returned.
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

/// Serve one mux connection as [`serve_connection`], but register the
/// peer under `identity` so [`crate::SubscribePolicy`] /
/// [`crate::PublishPolicy`] can authorize by caller.
///
/// Pass the mutual-auth peer certificate DER when the application uses
/// identity-based topic ACL. [`serve_connection`] alone leaves identity
/// as `None`.
///
/// # Errors
///
/// Same set as [`serve_connection`].
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
	let keepalive_task = tokio::spawn(keep_alive(handle.clone(), KEEPALIVE_INTERVAL));

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
	keepalive_task.abort();
	reader_task.abort();
	writer_task.abort();
	outcome
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use tokio::time::timeout;

	use super::*;
	use crate::testing::memory_mux_pair;

	/// A keepalive holds its task while the peer answers, and its task ends
	/// with the connection, so a served connection leaks no pinger.
	#[tokio::test]
	async fn keep_alive_runs_until_the_connection_ends() {
		let (client, server) = memory_mux_pair(4);
		let (_client_handle, client_reader, client_writer, _client_responder) = client.into_parts();
		let (server_handle, server_reader, server_writer, _server_responder) = server.into_parts();

		let peer_reader = tokio::spawn(client_reader.drive());
		let peer_writer = tokio::spawn(client_writer.drive());
		tokio::spawn(server_reader.drive());
		tokio::spawn(server_writer.drive());

		let mut pinger = tokio::spawn(keep_alive(server_handle, Duration::from_millis(1)));

		let held = timeout(Duration::from_millis(50), &mut pinger).await;
		assert!(held.is_err(), "the keepalive must run while the peer answers");

		peer_reader.abort();
		peer_writer.abort();
		drop(_client_handle);

		let ended = timeout(Duration::from_secs(5), pinger).await;
		assert!(ended.is_ok(), "the keepalive must end with the connection");
	}
}
