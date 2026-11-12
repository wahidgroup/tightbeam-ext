//! The owner of one accepted multiplexed connection, as `docs/ws.md`
//! (Accepted links) states it.

use core::convert::Infallible;
use core::future::{pending, poll_fn, Future};
use core::pin::pin;
use core::time::Duration;
use std::sync::Arc;

use tightbeam::clock::{Clock, Lapse, Timer, Timing};
use tightbeam::constants::KEEPALIVE_PROBES_PER_DEADLINE;
use tightbeam::marker::MaybeSend;
use tightbeam::policy::{GatePolicy, SessionContext, TransitStatus};
use tightbeam::transport::envelopes::GoAwayReason;
use tightbeam::transport::error::TransportError;
use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::multiplex::{
	MuxAcceptor, MuxDispatch, MuxDrivers, MuxHandle, MuxRekeyContext, MuxResponder, MuxRole, MuxTransport, ReplySink,
	SpawnedMux, StreamBody, StreamRoute,
};
use tightbeam::transport::state::EncryptedProtocolState;
use tightbeam::transport::{CheckedLimits, EnvelopeSink, EnvelopeSource, ResponsePackage, TransportResult};
use tightbeam::{Errorizable, Frame, TightBeamError};
use tokio::task::JoinSet;

#[cfg(feature = "instrument")]
use tightbeam::instrumentation::events;
#[cfg(feature = "instrument")]
use tightbeam::trace::TraceCollector;
#[cfg(feature = "instrument")]
use tightbeam::transport::GateAudit;
#[cfg(feature = "instrument")]
use tightbeam::urn::Urn;

/// The event that the audit trail of a served link records once per probe of
/// its keepalive that the peer answered.
#[cfg(feature = "instrument")]
pub const KEEPALIVE_ANSWERED: Urn<'static> = tightbeam::urn!("tightbeam-ws", "event:keepalive/answered");

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

/// A clock whose waits race the work beside them ([`Timing::Races`]) on the
/// thread that built the value.
///
/// - The check on the building thread is an early refusal. A clock that parks
///   parks on every thread, so that refusal holds everywhere.
/// - A [`Timer`] of this clock reads the timing again at the first wait of
///   each bound, on the thread that polls it. It refuses a thread with no
///   timer with `Lapse::NoTimer`.
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
	/// - [`LinkError::ClockCannotRace`] -- the clock parks the thread, or the thread has no timer for it.
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

/// One accepted connection before its tasks spawn: the halves of its
/// transport, and the settings, rekey context, gate, peer, and writer clock
/// that a transport constructor reads from the transport it consumes.
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
/// 	mut transport: T,
/// ) -> Result<AcceptedLink<T::EnvelopeReader, T::EnvelopeWriter>, Box<dyn std::error::Error>> {
/// 	transport.negotiate_mux().await?;
/// 	let link = AcceptedLink::accepted(transport)?;
/// 	Ok(link)
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
/// under the `instrument` feature.
pub(crate) struct Audit {
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

	/// Another handle on this trail, which records on the same trace.
	fn share(&self) -> Self {
		#[cfg(feature = "instrument")]
		let audit = Self { trace: self.trace() };
		#[cfg(not(feature = "instrument"))]
		let audit = Self {};

		audit
	}

	/// Record `verdict` on the trail.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a trace that refused the event, the fault
	///   that the `testing-fault` feature of tightbeam injects.
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

	/// Record on the trail that the peer answered a probe of the keepalive.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a trace that refused the event, the fault
	///   that the `testing-fault` feature of tightbeam injects.
	fn probe_answered(&self) -> Result<(), TightBeamError> {
		#[cfg(feature = "instrument")]
		if let Some(trace) = &self.trace {
			trace.emit_event(KEEPALIVE_ANSWERED)?;
		}

		Ok(())
	}

	/// Record on the trail that a handler failed with an error of its own,
	/// and that its stream answers `status`.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a trace that refused the event, the fault
	///   that the `testing-fault` feature of tightbeam injects.
	#[cfg(feature = "testing")]
	pub(crate) fn failed(&self, status: TransitStatus) -> Result<(), TightBeamError> {
		if let Some(trace) = &self.trace {
			trace.emit_event_with_value(events::HANDLER_FAILED, status.as_str(), status)?;
		}

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
	/// - The link keeps the negotiated settings, the in-band rekey context of a
	///   metered session, and the gate.
	/// - The peer is the one of [`MuxAcceptor::session_context`].
	///
	/// # Errors
	///
	/// - [`LinkError::NotMultiplexed`] -- the handshake negotiated no multiplexing.
	/// - [`LinkError::ClockCannotRace`] -- the writer clock cannot race a wait on the calling thread.
	/// - [`LinkError::Transport`] -- the errors of [`MuxAcceptor::take_rekey`]
	///   and [`MuxAcceptor::into_gated_halves`].
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
	/// `settings` out of band, such as [`MuxSettings::symmetric`].
	///
	/// - The link keeps the gate and the empty session of a cleartext peer.
	/// - The endpoint MUST hold no encryption provisioning ([`EncryptionConfig::is_provisioned`]),
	///   whatever its handshake negotiated.
	///
	/// # Errors
	///
	/// - [`LinkError::Encrypted`] -- the endpoint is provisioned for encryption.
	/// - [`LinkError::ClockCannotRace`] -- the writer clock cannot race a wait on the calling thread.
	/// - [`LinkError::Transport`] -- the errors of [`MuxAcceptor::into_gated_halves`].
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
}

impl<R, W> AcceptedLink<R, W>
where
	R: EnvelopeSource + Send + 'static,
	W: EnvelopeSink + Send + 'static,
{
	/// Spawn the mux of this link in the server role, with a keepalive, into
	/// the [`ServedMux`] that owns them.
	///
	/// - A metered session assembles with its rekey context, so it renews in band.
	/// - The keepalive probes the peer through [`MuxHandle::ping`]
	///   [`KEEPALIVE_PROBES_PER_DEADLINE`] times per read deadline of the link,
	///   on the writer clock. Under the `instrument` feature, the trail of the
	///   link records each answered probe as `KEEPALIVE_ANSWERED`.
	/// - The drop of the [`ServedMux`] ends both drivers and the keepalive.
	#[must_use]
	pub fn spawn(self) -> ServedMux {
		let Self { reader, writer, settings, rekey, gate, session, clock } = self;
		let interval = Keepalive::interval(&reader.limits());

		let mux = match rekey {
			Some(context) => MuxTransport::with_rekey(reader, writer, context, settings),
			None => MuxTransport::new(reader, writer, MuxRole::Server, settings),
		};

		let SpawnedMux { handle, responder, drivers } = mux.spawn();
		let audit = Audit::of(&handle);
		let probes = Keepalive { handle: handle.clone(), timer: clock.timer(), interval, audit: audit.share() };
		let mut keepalive = JoinSet::new();

		keepalive.spawn(probes.run());

		ServedMux { handle, responder, drivers, keepalive, gate, session, clock, audit }
	}
}

/// The keepalive of a served link, which probes the peer on the writer clock
/// and records each answered probe on the trail of the link.
struct Keepalive {
	handle: MuxHandle,
	timer: Timer,
	/// The span from one probe to the next.
	interval: Duration,
	audit: Audit,
}

impl Keepalive {
	/// The interval of a link whose reader reads under `limits`: the share of
	/// its read deadline, which [`CheckedLimits`] keeps above zero, that
	/// [`KEEPALIVE_PROBES_PER_DEADLINE`] divides out. A deadline with no whole
	/// share in nanoseconds paces by the whole deadline.
	fn interval(limits: &CheckedLimits) -> Duration {
		let deadline = limits.operation_timeout;
		let share = deadline.checked_div(KEEPALIVE_PROBES_PER_DEADLINE);
		share.filter(|share| !share.is_zero()).unwrap_or(deadline)
	}

	/// Probe the peer at once, and again one interval after each probe, until
	/// a probe fails, the polling thread has no timer for the clock, or the
	/// trail refuses a record. The answer is the error that ended the loop.
	///
	/// - A probe waits at most one interval for its answer. The keepalive then
	///   forgets the probe and sends the next one at once.
	/// - The wait for the next probe is armed before the trail records the
	///   answer, so a reader of the record that moves the clock moves it past
	///   an armed wait.
	async fn run(self) -> TightBeamError {
		let Self { handle, mut timer, interval, audit } = self;
		loop {
			let sent = timer.clock().monotonic();

			match timer.within(interval, pin!(handle.ping())).await {
				Ok(Ok(())) => {}
				Ok(Err(refusal)) => return refusal.into(),
				Err(Lapse::Passed) => continue,
				Err(lapse @ Lapse::NoTimer) => return TransportError::from(lapse).into(),
			}

			let waited = timer.clock().monotonic().saturating_duration_since(sent);
			let next = timer.sleep(interval.saturating_sub(waited));
			if let Err(refused) = audit.probe_answered() {
				return refused;
			}

			next.await;
		}
	}
}

/// One served multiplexed connection, with its drivers and its keepalive
/// spawned.
///
/// The value owns every task of the connection, so the drop of the value, or
/// of the future of a serve, ends them all.
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
/// 	served.serve_dispatch(Closed, pending()).await
/// }
/// ```
pub struct ServedMux {
	handle: MuxHandle,
	responder: MuxResponder,
	drivers: MuxDrivers,
	keepalive: JoinSet<TightBeamError>,
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

	/// A share of the trace of the transport that the link was accepted on,
	/// where the service records its own audit trail. `None` names a
	/// transport that records on no trace.
	#[cfg(feature = "instrument")]
	#[must_use]
	pub fn trace(&self) -> Option<TraceCollector> {
		self.audit.trace()
	}

	/// A share of the audit trail of the link, which the `MuxService` path
	/// records each handler failure on.
	#[cfg(feature = "testing")]
	pub(crate) fn audit(&self) -> Audit {
		self.audit.share()
	}

	/// Serve every peer stream with `dispatch` behind the transport gate,
	/// until the connection ends. A dispatch answers each call with a status
	/// of its own, so the trail records no handler failure for it.
	///
	/// - Each call evaluates the gate before `dispatch` sees it. A gate that
	///   answers `Unknown` answers `Internal`, and any other refusal answers its
	///   own status. Under the `instrument` feature, the call records the verdict
	///   on the trace of the link first ([`trace`](Self::trace)).
	/// - When `expulsion` yields a reason, the connection drains with a GoAway
	///   of that reason ([`MuxHandle::shutdown_with`]) while the responder
	///   serves the streams in flight. A connection with no expulsion passes
	///   [`pending`].
	/// - The call returns when the responder ends, and ends the drivers and
	///   the keepalive. A dropped future ends them as well. The writer stops
	///   at once, so envelopes that the responder queued last drop
	///   (`docs/ws.md`, Accepted links).
	///
	/// # Errors
	///
	/// - The errors of [`MuxResponder::serve_with`].
	pub async fn serve_dispatch<D, E>(self, dispatch: D, expulsion: E) -> TransportResult<()>
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

/// What a transport gate decides for one call, as the peer reads it.
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
	/// server fault. Upstream normalizes a verdict by the same rule.
	fn of(gate: &dyn GatePolicy, frame: Option<&Frame>, session: &SessionContext) -> Self {
		let status = gate.evaluate(frame, session);
		match status {
			TransitStatus::Ok => Self::Admitted,
			TransitStatus::Unknown => Self::Refused(TransitStatus::Internal),
			refused => Self::Refused(refused),
		}
	}

	/// The answer of the call: the answer of `admitted` when the gate admits
	/// the call, which runs only then, or the refusal of its status.
	///
	/// # Errors
	///
	/// - The [`TransportError`] of `admitted`.
	async fn answer<A, F>(self, admitted: impl FnOnce() -> F) -> TransportResult<A>
	where
		A: Answer,
		F: Future<Output = TransportResult<A>>,
	{
		match self {
			Self::Admitted => admitted().await,
			Self::Refused(status) => Ok(A::refused(status)),
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

/// The answer of one stream kind, as a refused call of that kind answers.
trait Answer {
	/// The answer of a call that the gate refused with `status`.
	fn refused(status: TransitStatus) -> Self;
}

/// A unary or streaming call answers its status with no reply frame.
impl Answer for ResponsePackage {
	fn refused(status: TransitStatus) -> Self {
		Self::new(status, None)
	}
}

/// A duplex call answers its status on the trailer of the stream.
impl Answer for TransitStatus {
	fn refused(status: TransitStatus) -> Self {
		status
	}
}

/// A [`MuxDispatch`] behind the transport gate of its connection.
///
/// Each call evaluates the gate against the handshake session and records
/// the verdict on the audit trail of its link, and only an admitted call
/// reaches the dispatch.
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
	/// - The [`TightBeamError`] of a trace that refused the verdict, so the
	///   call fails as an upstream call does.
	fn verdict(&self, frame: Option<&Frame>) -> Result<GateVerdict, TightBeamError> {
		let verdict = GateVerdict::of(self.gate.as_ref(), frame, &self.session);
		self.audit.verdict(&verdict)?;
		Ok(verdict)
	}
}

impl<D: MuxDispatch + Sync> MuxDispatch for GatedDispatch<D> {
	fn unary(&self, frame: Arc<Frame>) -> impl Future<Output = TransportResult<ResponsePackage>> + MaybeSend {
		let verdict = self.verdict(Some(&frame));
		async move { verdict?.answer(|| self.dispatch.unary(frame)).await }
	}

	fn streaming(
		&self,
		body: StreamBody,
		route: StreamRoute,
	) -> impl Future<Output = TransportResult<ResponsePackage>> + MaybeSend {
		let verdict = self.verdict(None);
		async move { verdict?.answer(|| self.dispatch.streaming(body, route)).await }
	}

	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		route: StreamRoute,
	) -> impl Future<Output = TransportResult<TransitStatus>> + MaybeSend {
		let verdict = self.verdict(None);
		async move { verdict?.answer(|| self.dispatch.duplex(body, reply, route)).await }
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use tightbeam::transport::TransportLimits;

	#[test]
	fn a_read_deadline_of_three_shares_paces_one_share() -> TransportResult<()> {
		let limits = TransportLimits { operation_timeout: Duration::from_secs(30), ..TransportLimits::default() };
		assert_eq!(Keepalive::interval(&limits.checked()?), Duration::from_secs(10));
		Ok(())
	}

	#[test]
	fn a_read_deadline_with_no_whole_share_paces_the_whole_deadline() -> TransportResult<()> {
		let limits = TransportLimits { operation_timeout: Duration::from_nanos(2), ..TransportLimits::default() };
		assert_eq!(Keepalive::interval(&limits.checked()?), Duration::from_nanos(2));
		Ok(())
	}
}
