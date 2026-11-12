//! The `MuxService` path of a served link, as `docs/ws.md` (Accepted links)
//! states it.

use core::future::Future;
use std::sync::Arc;

use tightbeam::marker::MaybeSend;
use tightbeam::policy::{SessionContext, TransitStatus};
use tightbeam::transport::envelopes::GoAwayReason;
use tightbeam::transport::error::TransportError;
use tightbeam::transport::multiplex::{CallContext, MuxDispatch, MuxService, ReplySink, StreamBody, StreamRoute};
use tightbeam::transport::{ResponsePackage, TransportResult};
use tightbeam::{Frame, TightBeamError};

use crate::serve::{Audit, ServedMux};

impl ServedMux {
	/// Serve every peer stream with `service` behind the transport gate,
	/// until the connection ends.
	///
	/// - Each call passes the gate first, as [`serve_dispatch`](Self::serve_dispatch) states.
	/// - An admitted call reaches the method of its kind with a [`CallContext`]
	///   of the session that the handshake proved and the route of the stream.
	/// - A handler that fails with an error of its own answers the status of
	///   the failure, and the trace of the link records it as `HANDLER_FAILED`.
	/// - A default method of the service answers `Unimplemented`.
	///
	/// # Errors
	///
	/// - The errors of [`MuxResponder::serve_with`].
	///
	/// [`MuxResponder::serve_with`]: tightbeam::transport::multiplex::MuxResponder::serve_with
	pub async fn serve<S, E>(self, service: S, expulsion: E) -> TransportResult<()>
	where
		S: MuxService,
		E: Future<Output = GoAwayReason>,
	{
		let session = self.session().clone();
		let audit = self.audit();
		let calls = ServiceCalls { service, session, audit };

		self.serve_dispatch(calls, expulsion).await
	}
}

/// A [`MuxService`] as the dispatch of a served link: each call reaches the
/// method of its kind with the session of the link, and settles as upstream
/// settles a served call.
struct ServiceCalls<S> {
	service: S,
	session: SessionContext,
	/// The audit trail of the link, which records each handler failure.
	audit: Audit,
}

impl<S> ServiceCalls<S> {
	/// The context of a call on the stream of `route`.
	fn context(&self, route: StreamRoute) -> CallContext {
		let session = self.session.clone();
		CallContext::new(session, route)
	}
}

impl<S: MuxService> MuxDispatch for ServiceCalls<S> {
	fn unary(&self, frame: Arc<Frame>) -> impl Future<Output = TransportResult<ResponsePackage>> + MaybeSend {
		let request = Arc::try_unwrap(frame).unwrap_or_else(|shared| Frame::clone(&shared));
		let cx = self.context(StreamRoute::default());
		async move {
			let handled = Handled::of(self.service.unary(request, cx).await);
			let (status, reply) = handled.settle(&self.audit)?;
			Ok(ResponsePackage::new(status, reply.flatten()))
		}
	}

	fn streaming(
		&self,
		body: StreamBody,
		route: StreamRoute,
	) -> impl Future<Output = TransportResult<ResponsePackage>> + MaybeSend {
		let cx = self.context(route);
		async move {
			let handled = Handled::of(self.service.streaming(body, cx).await);
			let (status, reply) = handled.settle(&self.audit)?;
			Ok(ResponsePackage::new(status, reply.flatten()))
		}
	}

	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		route: StreamRoute,
	) -> impl Future<Output = TransportResult<TransitStatus>> + MaybeSend {
		let cx = self.context(route);
		async move {
			let handled = Handled::of(self.service.duplex(body, reply, cx).await);
			let (status, _closed) = handled.settle(&self.audit)?;
			Ok(status)
		}
	}
}

/// What the handler of one admitted call came to.
enum Handled<T> {
	/// The handler answered with its value.
	Answered(T),
	/// The handler failed with an error of its own, and the stream answers
	/// this status.
	Failed(TransitStatus),
	/// The handler is a default of the service, which leaves the kind of the
	/// call out.
	NotServed,
}

impl<T> Handled<T> {
	/// What a handler that returned `outcome` came to.
	///
	/// - A failure answers the status that it carries, and `Internal` when it
	///   carries none.
	/// - A carried `Unavailable` answers `Unknown`, because the handler ran,
	///   and a peer reads `Unavailable` as a refusal before any handler.
	fn of(outcome: Result<T, TightBeamError>) -> Self {
		let carried = match outcome {
			Ok(value) => return Self::Answered(value),
			Err(TightBeamError::TransportError(TransportError::NotServed)) => return Self::NotServed,
			Err(TightBeamError::TransportError(failure)) => failure.transit_status(),
			Err(_) => None,
		};

		let status = match carried {
			Some(TransitStatus::Unavailable) => TransitStatus::Unknown,
			Some(status) => status,
			None => TransitStatus::Internal,
		};
		Self::Failed(status)
	}

	/// The status that the stream reads, beside the value of an answered call.
	/// A failed handler records its status on `audit` as `HANDLER_FAILED`.
	///
	/// # Errors
	///
	/// - [`TransportError::NotServed`] -- the service leaves the kind out,
	///   which the responder records and answers `Unimplemented`.
	/// - The [`TransportError`] of a trace that refused the record of a failure.
	fn settle(self, audit: &Audit) -> TransportResult<(TransitStatus, Option<T>)> {
		match self {
			Self::Answered(value) => Ok((TransitStatus::Ok, Some(value))),
			Self::NotServed => Err(TransportError::NotServed),
			Self::Failed(status) => {
				audit.failed(status)?;
				Ok((status, None))
			}
		}
	}
}
