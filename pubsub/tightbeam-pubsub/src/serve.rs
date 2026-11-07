//! The application side of a served multiplexed pub/sub connection.
//!
//! [`PubsubCommands::serve`](crate::PubsubCommands::serve) answers the wire
//! commands and hands every other stream to an [`AppRoutes`] handler, with the
//! [`ConnectionContext`] of the connection the stream arrived on.

use core::future::{ready, Ready};
use std::sync::Arc;

use tightbeam::policy::{SessionContext, TransitStatus};
use tightbeam::transport::ResponsePackage;
use tightbeam::Frame;
use tightbeam_ws::serve::ServedMux;

use crate::emit::Emitter;
use crate::registry::ConnectionId;

/// What one served connection's application handler works with: its registry
/// id, its emitter, and the peer its handshake proved.
///
/// [`PubsubCommands::serve`](crate::PubsubCommands::serve) builds the context
/// from the served connection, so every part names the same connection.
#[derive(Clone)]
pub struct ConnectionContext {
	connection: ConnectionId,
	emitter: Emitter,
	session: SessionContext,
}

impl ConnectionContext {
	/// The context of `served`, which the registry admitted as `connection`.
	pub(crate) fn of(served: &ServedMux, connection: ConnectionId) -> Self {
		let emitter = Emitter::from(served.handle().clone());
		let session = served.session().clone();
		Self { connection, emitter, session }
	}

	/// The registry id this connection's subscriptions hang off.
	#[must_use]
	pub fn connection(&self) -> ConnectionId {
		self.connection
	}

	/// The emitter of the connection, for server-initiated streams.
	#[must_use]
	pub fn emitter(&self) -> &Emitter {
		&self.emitter
	}

	/// The peer that the handshake of the connection proved.
	#[must_use]
	pub fn session(&self) -> &SessionContext {
		&self.session
	}
}

/// The application handler for streams no wire command claims.
///
/// Every `async fn(ConnectionContext, Arc<Frame>) -> ResponsePackage` and every
/// closure of that shape is one. [`Unrouted`] serves a command-only
/// connection.
///
/// `Sync` because the responder shares one handler across the
/// connection's concurrent streams.
pub trait AppRoutes<F>: Clone + Send + Sync + 'static {
	/// Answer one stream that `context` received with `frame`.
	fn route(&self, context: ConnectionContext, frame: Arc<Frame>) -> F;
}

impl<A, F> AppRoutes<F> for A
where
	A: Fn(ConnectionContext, Arc<Frame>) -> F + Clone + Send + Sync + 'static,
{
	fn route(&self, context: ConnectionContext, frame: Arc<Frame>) -> F {
		self(context, frame)
	}
}

/// The command-only application: every stream no wire command claims answers
/// `Unimplemented`.
///
/// # Examples
///
/// ```
/// use tightbeam::transport::handshake::negotiation::MuxSettings;
/// use tightbeam_pubsub::testing::MemoryLink;
/// use tightbeam_pubsub::{AllowAll, PubsubCommands, TopicRegistry, Unrouted};
///
/// # async fn serve() -> Result<(), Box<dyn std::error::Error>> {
/// let (_client, server) = MemoryLink::default().served(MuxSettings::symmetric(4))?;
/// let commands = PubsubCommands::new(TopicRegistry::default(), AllowAll);
///
/// // The wire commands answer, and every other stream answers Unimplemented.
/// commands.serve(server, Unrouted).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct Unrouted;

impl AppRoutes<Ready<ResponsePackage>> for Unrouted {
	fn route(&self, _context: ConnectionContext, _frame: Arc<Frame>) -> Ready<ResponsePackage> {
		ready(ResponsePackage::new(TransitStatus::Unimplemented, None))
	}
}
