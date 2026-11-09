//! The owner of one accepted multiplexed connection: its transport gate, its
//! tasks, and the handle that a push-capable service emits on.
//!
//! Upstream [`MuxAcceptor::serve`] serves a connection behind its transport
//! gate, and lends its service no [`MuxHandle`]. A server that pushes streams
//! of its own serves through this module instead, in three steps:
//!
//! 1. [`AcceptedLink::accepted`] consumes a transport whose server handshake
//!    completed. It keeps the multiplexing settings, the rekey context, the
//!    peer, the gate, and the writer clock. A cleartext endpoint runs no
//!    handshake, so [`AcceptedLink::cleartext`] takes the settings that
//!    both ends agreed on, and refuses an endpoint provisioned for encryption.
//! 2. [`AcceptedLink::spawn`] spawns the mux drivers and a keepalive into the [`ServedMux`] that owns them.
//! 3. [`ServedMux::serve`] runs the responder until the connection ends, and every call passes the gate first.
//!
//! A server that pushes nothing serves through upstream [`MuxAcceptor::serve`],
//! which also keeps the gate spans of the audit trail.
//!
//! # Gate
//!
//! Each call evaluates the gate against the session that the handshake proved,
//! as upstream does for every gate that reads the peer. A renewal of a metered
//! session keeps that peer, so the call keeps serving in the same session.
//! Upstream also hands each call the receipt of the latest renewal, through a
//! crate-private constructor of [`SessionContext`]. A gate here therefore
//! reads the receipt of the handshake.
//!
//! The gate answers each call with the status upstream answers. Under the
//! `instrument` feature, each call records the verdict on the trace that the
//! mux of the link records on, as upstream records it: `GATE_ACCEPT` with
//! `Ok`, or `GATE_REJECT` with the status that the refused call answers, as
//! its label and its value.
//!
//! Upstream also names the peer key of the session as the evidence of each
//! verdict, injects trace faults at handler entry, and labels a handler
//! failure `HANDLER_FAILED`, all through crate-private traits. A verdict
//! recorded here therefore names its status alone, and a call served here
//! records none of the rest.

use core::convert::Infallible;
use core::future::{pending, poll_fn, Future};
use core::pin::pin;
use std::sync::Arc;

use tightbeam::clock::{Clock, Timer, Timing};
#[cfg(feature = "instrument")]
use tightbeam::instrumentation::events;
use tightbeam::marker::MaybeSend;
use tightbeam::policy::{GatePolicy, SessionContext, TransitStatus};
#[cfg(feature = "instrument")]
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::GoAwayReason;
use tightbeam::transport::error::TransportError;
use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::multiplex::{
	MuxAcceptor, MuxDispatch, MuxDrivers, MuxHandle, MuxRekeyContext, MuxResponder, MuxRole, MuxTransport, ReplySink,
	SpawnedMux, StreamBody, StreamRoute,
};
use tightbeam::transport::state::EncryptedProtocolState;
#[cfg(feature = "instrument")]
use tightbeam::transport::GateAudit;
use tightbeam::transport::{EnvelopeSink, EnvelopeSource, ResponsePackage, TransportResult};
#[cfg(feature = "instrument")]
use tightbeam::urn::Urn;
use tightbeam::{Errorizable, Frame, TightBeamError};
use tokio::task::JoinSet;

/// Why a transport cannot become an [`AcceptedLink`].
///
/// # Examples
///
/// ```
/// use tightbeam::transport::error::TransportError;
/// use tightbeam_ws::serve::LinkError;
///
/// let refused = LinkError::from(TransportError::InvalidState);
/// assert_eq!(refused.to_string(), "the transport refused the split: Invalid state");
/// ```
#[derive(Debug, Errorizable)]
pub enum LinkError {
	/// The handshake negotiated no multiplexing, so the connection serves
	/// single-flight.
	#[error("the peer negotiated no multiplexing")]
	NotMultiplexed,
	/// The endpoint is provisioned for encryption, so its handshake decides
	/// the multiplexing that [`AcceptedLink::accepted`] reads.
	#[error("the endpoint is provisioned for encryption")]
	Encrypted,
	/// The writer clock cannot race a wait on the calling thread, so no emit
	/// deadline and no keepalive could run on it.
	#[error("the writer clock cannot race a wait: {0:?}")]
	ClockCannotRace(Timing),
	/// The transport refused to detach its rekey context or to split.
	#[error("the transport refused the split: {0}")]
	#[from]
	Transport(TransportError),
}

/// A clock whose waits race the work beside them on the thread that proved
/// it ([`Timing::Races`]).
///
/// An emit deadline and the keepalive each race a wait on the clock of their
/// link. A clock that parks, or one that has no timer on the thread, would
/// leave every deadline unbounded, so the link refuses it.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
///
/// use tightbeam::clock::{Clock, SystemClock, Timing};
/// use tightbeam_ws::serve::{LinkError, RacingClock};
///
/// // The system clock has no timer off a tokio runtime.
/// let clock: Arc<dyn Clock> = Arc::new(SystemClock);
/// let refused = RacingClock::try_from(clock);
/// assert!(matches!(refused, Err(LinkError::ClockCannotRace(Timing::Absent))));
/// ```
#[derive(Clone, Debug)]
pub struct RacingClock(Arc<dyn Clock>);

impl TryFrom<Arc<dyn Clock>> for RacingClock {
	type Error = LinkError;

	/// The clock `clock`, once its timing on the calling thread races.
	///
	/// # Errors
	///
	/// - [`LinkError::ClockCannotRace`]: the clock parks the thread, or the thread has no timer for it.
	fn try_from(clock: Arc<dyn Clock>) -> Result<Self, Self::Error> {
		let timing = clock.timing();
		if timing != Timing::Races {
			return Err(LinkError::ClockCannotRace(timing));
		}

		Ok(Self(clock))
	}
}

impl RacingClock {
	/// A timer on this clock, for a party that bounds many waits.
	#[must_use]
	pub fn timer(&self) -> Timer {
		let clock = Arc::clone(&self.0);
		Timer::new(clock)
	}
}

/// What one served connection is built from: the halves of its transport,
/// its multiplexing settings, its rekey context, the transport gate, the peer
/// the handshake proved, and the clock of its writer.
///
/// Every field is private and a constructor sets each one from the transport
/// it consumes, so a link always carries its real gate, its real peer, and a
/// [`RacingClock`].
///
/// # Examples
///
/// ```
/// use tightbeam::transport::multiplex::MuxAcceptor;
/// use tightbeam_ws::serve::{AcceptedLink, LinkError};
///
/// /// The link of `transport`, once its server handshake negotiated
/// /// multiplexing.
/// async fn link<T: MuxAcceptor>(
///     mut transport: T,
/// ) -> Result<AcceptedLink<T::EnvelopeReader, T::EnvelopeWriter>, Box<dyn std::error::Error>> {
///     transport.negotiate_mux().await?;
///     let link = AcceptedLink::accepted(transport)?;
///     Ok(link)
/// }
/// ```
pub struct AcceptedLink<R, W> {
	reader: R,
	writer: W,
	settings: MuxSettings,
	rekey: Option<MuxRekeyContext>,
	gate: Box<dyn GatePolicy>,
	session: SessionContext,
	clock: RacingClock,
}

/// The audit trail of one served link: the trace that its mux records on,
/// under the `instrument` feature. A link with no trace, or a build without
/// the feature, records nothing.
struct Audit {
	#[cfg(feature = "instrument")]
	trace: Option<TraceCollector>,
}

impl Audit {
	/// The audit trail of the mux of `handle`, which is the trace of the
	/// transport that the link was accepted on.
	fn of(handle: &MuxHandle) -> Self {
		#[cfg(feature = "instrument")]
		let audit = Self { trace: handle.audit_trace().map(TraceCollector::share) };
		#[cfg(not(feature = "instrument"))]
		let audit = {
			let _ = handle;
			Self {}
		};

		audit
	}

	/// Record `verdict` on the trail.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace refused the event, the fault that the
	///   `testing-fault` feature of tightbeam injects.
	fn verdict(&self, verdict: &GateVerdict) -> Result<(), TightBeamError> {
		#[cfg(feature = "instrument")]
		if let Some(trace) = &self.trace {
			let (event, status) = verdict.audited();
			trace.emit_event_with_value(event, status.as_str(), status)?;
		}

		#[cfg(not(feature = "instrument"))]
		let _ = verdict;

		Ok(())
	}

	/// A share of the trace of the trail, when it has one.
	#[cfg(feature = "instrument")]
	fn trace(&self) -> Option<TraceCollector> {
		self.trace.as_ref().map(TraceCollector::share)
	}
}

impl<R: EnvelopeSource, W: EnvelopeSink> AcceptedLink<R, W> {
	/// The link of `transport`, whose server handshake negotiated
	/// multiplexing.
	///
	/// The link keeps the settings the handshake negotiated, the in-band rekey
	/// context of a metered session, the peer of
	/// [`MuxAcceptor::session_context`], and the transport gate. The writer
	/// keeps its clock across the split, and the link proves that it races on
	/// the calling thread.
	///
	/// # Errors
	///
	/// - [`LinkError::NotMultiplexed`]: the handshake negotiated no multiplexing.
	/// - [`LinkError::ClockCannotRace`]: the writer clock cannot race a wait on the calling thread.
	/// - [`LinkError::Transport`]: the errors of [`MuxAcceptor::take_rekey`] and
	///   [`MuxAcceptor::into_gated_halves`].
	pub fn accepted<T>(mut transport: T) -> Result<Self, LinkError>
	where
		T: MuxAcceptor<EnvelopeReader = R, EnvelopeWriter = W>,
	{
		let settings = transport.negotiated_mux().ok_or(LinkError::NotMultiplexed)?;
		let rekey = transport.take_rekey()?;
		let session = transport.session_context();
		let (gate, (reader, writer)) = transport.into_gated_halves()?;
		let clock = RacingClock::try_from(writer.clock())?;

		Ok(Self { reader, writer, settings, rekey, gate, session, clock })
	}

	/// The link of `transport`, a cleartext transport whose two ends agreed on
	/// `settings` out of band.
	///
	/// A cleartext transport has no handshake to negotiate in, so both ends
	/// configure the same settings ([`MuxSettings::symmetric`]). The link keeps
	/// the transport gate and the empty session of a cleartext peer, and proves
	/// the writer clock as [`accepted`](Self::accepted) does.
	///
	/// The link proves that the endpoint of `transport` holds no encryption
	/// provisioning ([`EncryptionConfig::is_provisioned`]), the rule by which
	/// the transport skips its handshake. An encrypted transport is refused
	/// whether its handshake negotiated multiplexing, negotiated a
	/// single-flight session, or has not run.
	///
	/// # Errors
	///
	/// - [`LinkError::Encrypted`]: the endpoint is provisioned for encryption.
	/// - [`LinkError::ClockCannotRace`]: the writer clock cannot race a wait on the calling thread.
	/// - [`LinkError::Transport`]: the errors of [`MuxAcceptor::into_gated_halves`].
	///
	/// [`EncryptionConfig::is_provisioned`]: tightbeam::transport::state::EncryptionConfig::is_provisioned
	pub fn cleartext<T>(transport: T, settings: MuxSettings) -> Result<Self, LinkError>
	where
		T: MuxAcceptor<EnvelopeReader = R, EnvelopeWriter = W> + EncryptedProtocolState,
	{
		let provisioned = transport.encryption().is_provisioned();
		if provisioned {
			return Err(LinkError::Encrypted);
		}

		let session = transport.session_context();
		let (gate, (reader, writer)) = transport.into_gated_halves()?;
		let clock = RacingClock::try_from(writer.clock())?;

		Ok(Self { reader, writer, settings, rekey: None, gate, session, clock })
	}

	/// The peer that the handshake proved. A cleartext or server-auth
	/// connection proves no peer.
	#[must_use]
	pub fn session(&self) -> &SessionContext {
		&self.session
	}
}

impl<R, W> AcceptedLink<R, W>
where
	R: EnvelopeSource + Send + 'static,
	W: EnvelopeSink + Send + 'static,
{
	/// Spawn the mux of this link in the server role, and a keepalive that
	/// paces its probes to the operation timeout of the link
	/// ([`MuxHandle::keep_alive`]).
	///
	/// A metered session assembles with its rekey context, so it renews in
	/// band as the mux of the transport does. The [`ServedMux`] owns both
	/// drivers and the keepalive, and its drop ends them.
	#[must_use]
	pub fn spawn(self) -> ServedMux {
		let Self { reader, writer, settings, rekey, gate, session, clock } = self;

		let mux = match rekey {
			Some(context) => MuxTransport::with_rekey(reader, writer, context, settings),
			None => MuxTransport::new(reader, writer, MuxRole::Server, settings),
		};

		let SpawnedMux { handle, responder, drivers } = mux.spawn();
		let audit = Audit::of(&handle);
		let mut keepalive = JoinSet::new();
		let probes = handle.clone().keep_alive();

		keepalive.spawn(probes);

		ServedMux { handle, responder, drivers, keepalive, gate, session, clock, audit }
	}
}

/// The parts of a link that runs no handshake, such as an in-memory test link.
///
/// The parts name any gate and any session, so a link built from them proves
/// neither. Only test support enables the `link-parts` feature, and a server
/// builds its links with [`AcceptedLink::accepted`].
///
/// # Examples
///
/// ```
/// use tightbeam::policy::{AcceptAllGate, SessionContext};
/// use tightbeam::transport::handshake::negotiation::MuxSettings;
/// use tightbeam_ws::serve::LinkParts;
///
/// /// The parts of a link over `reader` and `writer` that admits every call
/// /// from an anonymous peer.
/// fn parts<R, W>(reader: R, writer: W) -> LinkParts<R, W> {
///     let gate = Box::new(AcceptAllGate);
///     let settings = MuxSettings::symmetric(4);
///     LinkParts { reader, writer, settings, gate, session: SessionContext::default() }
/// }
/// ```
#[cfg(feature = "link-parts")]
pub struct LinkParts<R, W> {
	/// The read half of the link.
	pub reader: R,
	/// The write half of the link, whose clock runs every deadline.
	pub writer: W,
	/// The multiplexing settings that both ends configure.
	pub settings: MuxSettings,
	/// The gate that every call passes.
	pub gate: Box<dyn GatePolicy>,
	/// The peer that the policies of a served call read.
	pub session: SessionContext,
}

#[cfg(feature = "link-parts")]
impl<R: EnvelopeSource, W: EnvelopeSink> AcceptedLink<R, W> {
	/// The link of `parts`, with no rekey context.
	///
	/// # Errors
	///
	/// - [`LinkError::ClockCannotRace`]: the writer clock cannot race a wait on the calling thread.
	pub fn from_parts(parts: LinkParts<R, W>) -> Result<Self, LinkError> {
		let LinkParts { reader, writer, settings, gate, session } = parts;
		let clock = RacingClock::try_from(writer.clock())?;
		Ok(Self { reader, writer, settings, rekey: None, gate, session, clock })
	}
}

/// One served multiplexed connection, with its drivers and its keepalive
/// spawned.
///
/// The value owns every task of the connection, so the drop of the value, or
/// of the future of [`serve`](Self::serve), ends them all.
///
/// # Examples
///
/// ```
/// use core::future::pending;
///
/// use tightbeam::transport::multiplex::MuxDispatch;
/// use tightbeam::transport::TransportResult;
/// use tightbeam_ws::serve::ServedMux;
///
/// /// Refuses every interaction through the defaults of the trait.
/// struct Closed;
///
/// impl MuxDispatch for Closed {}
///
/// /// Serve `served` until the connection ends, with no expulsion.
/// async fn serve(served: ServedMux) -> TransportResult<()> {
///     served.serve(Closed, pending()).await
/// }
/// ```
pub struct ServedMux {
	handle: MuxHandle,
	responder: MuxResponder,
	drivers: MuxDrivers,
	keepalive: JoinSet<TransportError>,
	gate: Box<dyn GatePolicy>,
	session: SessionContext,
	clock: RacingClock,
	audit: Audit,
}

impl ServedMux {
	/// The handle that server-initiated streams emit on.
	#[must_use]
	pub fn handle(&self) -> &MuxHandle {
		&self.handle
	}

	/// The peer that the handshake proved, which the gate evaluates.
	#[must_use]
	pub fn session(&self) -> &SessionContext {
		&self.session
	}

	/// The clock of the writer, which every deadline of the connection runs
	/// on.
	#[must_use]
	pub fn clock(&self) -> &RacingClock {
		&self.clock
	}

	/// A share of the trace that the mux of the link records on, which is the
	/// trace of the transport that the link was accepted on. The service
	/// records its own audit trail there. `None` names a transport that
	/// records on no trace.
	#[cfg(feature = "instrument")]
	#[must_use]
	pub fn trace(&self) -> Option<TraceCollector> {
		self.audit.trace()
	}

	/// Serve every peer stream with `dispatch` behind the transport gate,
	/// until the connection ends.
	///
	/// - Each call evaluates the gate before `dispatch` sees it, as upstream
	///   [`MuxAcceptor::serve`] does. A gate that answers `Unknown` answers
	///   `Internal`, and any other refusal answers its own status. Under the
	///   `instrument` feature, the call records the verdict on the trace of
	///   the link first ([`trace`](Self::trace)).
	/// - When `expulsion` yields a reason, the connection drains with a GoAway
	///   of that reason ([`MuxHandle::shutdown_with`]) while the responder
	///   serves the streams in flight. A connection with no expulsion passes
	///   [`pending`].
	/// - The call returns when the responder ends, and ends the drivers and
	///   the keepalive. A dropped future ends them as well.
	///
	/// # Errors
	///
	/// - The terminal responder failures of [`MuxResponder::serve_with`].
	pub async fn serve<D, E>(self, dispatch: D, expulsion: E) -> TransportResult<()>
	where
		D: MuxDispatch + Send + Sync + 'static,
		E: Future<Output = GoAwayReason>,
	{
		let Self { handle, responder, drivers, keepalive, gate, session, clock: _, audit } = self;
		let _tasks = (drivers, keepalive);

		let drain = async {
			let reason = expulsion.await;
			// A link that already failed has nothing to drain, and the
			// responder reports how the connection ended.
			let _ = handle.shutdown_with(reason).await;
			pending::<Infallible>().await
		};

		let gated = GatedDispatch { dispatch, gate, session, audit };
		let mut served = pin!(responder.serve_with(gated));
		let mut drain = pin!(drain);

		poll_fn(|context| {
			let outcome = served.as_mut().poll(context);
			if outcome.is_pending() {
				let _ = drain.as_mut().poll(context);
			}

			outcome
		})
		.await
	}
}

/// What a transport gate decides for one call, normalized for the wire.
enum GateVerdict {
	/// The gate admits the call.
	Admitted,
	/// The gate refuses the call with a status that is neither `Ok` nor
	/// `Unknown`.
	Refused(TransitStatus),
}

impl GateVerdict {
	/// The verdict of `gate` on `frame` from the peer of `session`.
	///
	/// A gate that answers [`TransitStatus::Unknown`] reports a local bug, so
	/// the call answers [`TransitStatus::Internal`], which the peer reads as a
	/// server fault. This is the normalization of upstream
	/// `TransitStatus::normalized_verdict`, which is crate-private.
	fn of(gate: &dyn GatePolicy, frame: Option<&Frame>, session: &SessionContext) -> Self {
		let status = gate.evaluate(frame, session);
		match status {
			TransitStatus::Ok => Self::Admitted,
			TransitStatus::Unknown => Self::Refused(TransitStatus::Internal),
			refused => Self::Refused(refused),
		}
	}

	/// The event that the audit trail records this verdict under, and the
	/// status it records: `Ok` for an admitted call, and the status that a
	/// refused call answers.
	#[cfg(feature = "instrument")]
	fn audited(&self) -> (Urn<'static>, TransitStatus) {
		match self {
			Self::Admitted => (events::GATE_ACCEPT, TransitStatus::Ok),
			Self::Refused(status) => (events::GATE_REJECT, *status),
		}
	}
}

/// A [`MuxDispatch`] behind the transport gate of its connection.
///
/// Each call evaluates the gate at dispatch against the handshake session,
/// and records the verdict on the audit trail of its link. A refused call
/// answers the status of its verdict and never reaches the dispatch. Upstream
/// `GatedService` holds the same rule and is crate-private.
struct GatedDispatch<D> {
	dispatch: D,
	gate: Box<dyn GatePolicy>,
	session: SessionContext,
	audit: Audit,
}

impl<D> GatedDispatch<D> {
	/// The verdict of the gate on `frame`, or on a stream with no request
	/// frame, once the audit trail records it.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace refused the verdict, so the call fails
	///   as an upstream call does.
	fn verdict(&self, frame: Option<&Frame>) -> Result<GateVerdict, TightBeamError> {
		let verdict = GateVerdict::of(self.gate.as_ref(), frame, &self.session);
		self.audit.verdict(&verdict)?;
		Ok(verdict)
	}
}

impl<D: MuxDispatch + Sync> MuxDispatch for GatedDispatch<D> {
	fn unary(&self, frame: Arc<Frame>) -> impl Future<Output = TransportResult<ResponsePackage>> + MaybeSend {
		let verdict = self.verdict(Some(&frame));
		async move {
			match verdict? {
				GateVerdict::Admitted => self.dispatch.unary(frame).await,
				GateVerdict::Refused(status) => Ok(ResponsePackage::new(status, None)),
			}
		}
	}

	fn streaming(
		&self,
		body: StreamBody,
		route: StreamRoute,
	) -> impl Future<Output = TransportResult<ResponsePackage>> + MaybeSend {
		let verdict = self.verdict(None);
		async move {
			match verdict? {
				GateVerdict::Admitted => self.dispatch.streaming(body, route).await,
				GateVerdict::Refused(status) => Ok(ResponsePackage::new(status, None)),
			}
		}
	}

	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		route: StreamRoute,
	) -> impl Future<Output = TransportResult<TransitStatus>> + MaybeSend {
		let verdict = self.verdict(None);
		async move {
			match verdict? {
				GateVerdict::Admitted => self.dispatch.duplex(body, reply, route).await,
				GateVerdict::Refused(status) => Ok(status),
			}
		}
	}
}
