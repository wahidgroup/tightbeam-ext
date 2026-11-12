//! The application routes of a served connection, and what each route works
//! with. The page `docs/pubsub.md` (Connection serve) states both.

use core::future::{ready, Ready};
use std::sync::Arc;

use tightbeam::policy::{SessionContext, TransitStatus};
use tightbeam::transport::ResponsePackage;
use tightbeam::Frame;

use crate::emit::Emitter;
use crate::registry::Member;

/// What one served connection's application handler works with: its
/// emitter, and its standing in the registry that admitted it.
///
/// [`PubsubCommands::serve`] builds the context when the registry admits the
/// connection, so every part names the same connection of that registry.
///
/// [`PubsubCommands::serve`]: crate::PubsubCommands::serve
#[derive(Clone)]
pub struct ConnectionContext {
	member: Member,
	emitter: Emitter,
}

impl ConnectionContext {
	/// The context of the connection that `member` names, which emits through
	/// `emitter`.
	pub(crate) fn new(member: Member, emitter: Emitter) -> Self {
		Self { member, emitter }
	}

	/// The standing of the connection in the registry that admitted it.
	pub(crate) fn member(&self) -> &Member {
		&self.member
	}

	/// The emitter of the connection, for server-initiated streams. Each emit
	/// ends within the [`emit_deadline`](crate::RegistryOptions::emit_deadline)
	/// of the registry.
	#[must_use]
	pub fn emitter(&self) -> &Emitter {
		&self.emitter
	}

	/// The peer that the handshake of the connection proved, while the
	/// registry holds the connection. A connection that left or was expelled
	/// answers `None`, as the commands read it.
	#[must_use]
	pub fn session(&self) -> Option<SessionContext> {
		self.member.session()
	}
}

/// The application handler for the unary streams that no command claims.
///
/// - Every `async fn(ConnectionContext, Arc<Frame>) -> ResponsePackage` and every closure of
///   that shape is one.
/// - [`Unrouted`] serves a command-only connection.
/// - It is `Sync`, because the responder shares one handler across the concurrent streams of
///   the connection.
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

/// The command-only application: every stream no command claims answers
/// `Unimplemented`.
///
/// # Examples
///
/// ```
/// use tightbeam::transport::{EnvelopeSink, EnvelopeSource};
/// use tightbeam_pubsub::{AllowAll, PubsubCommands, TopicRegistry, Unrouted};
/// use tightbeam_ws::serve::AcceptedLink;
///
/// /// Serve `link` with the commands of `registry` alone.
/// async fn serve<R, W>(registry: TopicRegistry, link: AcceptedLink<R, W>) -> Result<(), Box<dyn std::error::Error>>
/// where
/// 	R: EnvelopeSource + Send + 'static,
/// 	W: EnvelopeSink + Send + 'static,
/// {
/// 	let commands = PubsubCommands::new(registry, AllowAll);
///
/// 	// The commands answer, and every other stream answers Unimplemented.
/// 	commands.serve(link, Unrouted).await?;
/// 	Ok(())
/// }
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct Unrouted;

impl AppRoutes<Ready<ResponsePackage>> for Unrouted {
	fn route(&self, _context: ConnectionContext, _frame: Arc<Frame>) -> Ready<ResponsePackage> {
		ready(ResponsePackage::new(TransitStatus::Unimplemented, None))
	}
}

#[cfg(test)]
mod tests {
	use crate::registry::TopicRegistry;
	use crate::testing::nodes::Admitted;

	#[tokio::test]
	async fn a_context_reads_no_session_once_its_connection_left() {
		let registry = TopicRegistry::default();
		let admitted = Admitted::to(&registry).await;
		let context = admitted.context().clone();
		let held = context.session();

		drop(admitted);

		assert!(held.is_some());
		assert!(context.session().is_none(), "a departed connection has no standing");
	}
}
