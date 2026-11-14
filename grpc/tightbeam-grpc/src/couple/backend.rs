//! The outbound adapter to a stock gRPC server: it admits and grants a call,
//! calls the server, and then encodes and signs the reply.

use core::convert::Infallible;
use core::fmt;
use core::future::{pending, Future};
use core::pin::{pin, Pin};
use core::time::Duration;
use std::sync::Arc;

use tightbeam::clock::{Clock, Lapse};
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::der;
use tightbeam::transport::multiplex::{ReplySink, StreamBody};
use tightbeam::transport::TransportError;
use tightbeam::{Frame, TightBeamError};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::client::Grpc;
use tonic::codec::{CompressionEncoding, Streaming};
use tonic::transport::Channel;
use tonic::{Code, Status};

#[cfg(feature = "instrument")]
use tightbeam::trace::TraceCollector;

use super::admit::{AdmissionTrust, AdmittedCall, Origin};
use super::error::CoupleError;
use super::message::CoupledReply;
use super::method::MethodPath;
use super::routes::{Carriage, Grants, Policy, Routes};
use super::stream::{AdmittedStream, AdmittedStreamParts, StreamAnswers, StreamRefusal, StreamRequests};
use crate::deadline::Deadline;
use crate::edge::{DialTls, TlsEndpoint};
use crate::protocol::GrpcAddr;
use crate::tunnel::{EdgeAudit, TunnelCodec};

/// The channel of an adapter to its stock gRPC backend, which connects on its
/// first call, and connects again after a failure.
#[derive(Clone, Debug)]
pub struct BackendChannel {
	channel: Channel,
}

impl BackendChannel {
	/// A channel to the server at `addr` under `tls`, which carries the
	/// client identity of the adapter through [`DialTls::with_identity`].
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidAddress`] -- tonic refuses the URI of `addr`.
	pub fn new(addr: &GrpcAddr, tls: &DialTls) -> Result<Self, TransportError> {
		let TlsEndpoint { endpoint, dialer } = tls.endpoint(addr)?;
		let channel = endpoint.connect_with_connector_lazy(dialer);
		Ok(Self { channel })
	}

	/// The pivot: call `admitted` on the backend within `timeout`, or within
	/// what remains of the deadline of the call when that is sooner. The bound
	/// covers the wait for the channel as well as the call.
	///
	/// # Errors
	///
	/// - The [`der::Error`] of an answer that does not encode.
	async fn call(&self, admitted: &AdmittedCall, timeout: Duration) -> Result<CoupledReply, der::Error> {
		let deadline = admitted.origin().bounded(timeout);
		let exchanged = deadline.bound(self.exchange(admitted, &deadline)).await;

		let answered = exchanged.unwrap_or_else(|lapse| Err(Backend::lapsed(lapse)));
		match answered {
			Ok(body) => CoupledReply::ok(body),
			Err(status) => CoupledReply::of_status(&status, Vec::new()),
		}
	}

	/// Wait for the channel, then call `admitted` within `deadline`: the
	/// response body, or the status that ended the call.
	async fn exchange(&self, admitted: &AdmittedCall, deadline: &Deadline) -> Result<Vec<u8>, Status> {
		let mut grpc = self.ready().await?;
		let origin = admitted.origin();
		let path = origin.method().path_and_query();
		let request = origin.request(admitted.body().to_vec(), deadline);

		let response = grpc.unary(request, path, TunnelCodec).await?;
		Ok(response.into_inner())
	}

	/// The pivot of a stream: relay `requests` to the backend and each of its
	/// answers to `answers`, within `timeout` or what remains of the deadline
	/// of the stream when that is sooner, then end `answers` with the status
	/// of the backend, of its deadline, or of a part that does not admit or
	/// send.
	async fn stream(
		&self,
		head: &Origin,
		mut requests: StreamRequests,
		mut answers: StreamAnswers,
		timeout: Duration,
	) -> StreamEnd {
		let deadline = head.bounded(timeout);
		let relayed = self.exchange_stream(head, &mut requests, &mut answers, &deadline);
		let status = match deadline.bound(relayed).await {
			Ok(Ok(status)) => status,
			Ok(Err(refused)) => return StreamEnd::refused(refused.end(answers).await),
			Err(lapse) => Backend::lapsed(lapse),
		};

		StreamEnd::of_answer(status.code(), answers.close(&status).await)
	}

	/// Run the stream of `head` both ways at once within `deadline`: the
	/// status that ended it, or the refusal of a request part or of an answer
	/// part. A refused request part ends the relay between two answers, so
	/// no push of an answer stops before it lands.
	async fn exchange_stream(
		&self,
		head: &Origin,
		requests: &mut StreamRequests,
		answers: &mut StreamAnswers,
		deadline: &Deadline,
	) -> Result<Status, StreamRefusal> {
		let (sender, outbound) = mpsc::channel(1);
		let (refuse, refused) = oneshot::channel();
		let forward = async move {
			if let Err(refusal) = Self::forward(requests, sender).await {
				let _ = refuse.send(refusal);
			}

			pending::<Infallible>().await
		};

		let refusal = async move {
			match refused.await {
				Ok(refusal) => refusal,
				Err(_) => pending().await,
			}
		};

		tokio::select! {
			answered = self.answer(head, answers, outbound, refusal, deadline) => answered,
			never = forward => match never {},
		}
	}

	/// Send each request of `requests` on `sender` until they end. The drop
	/// of `sender` ends the requests of the backend, and the answer ends the
	/// stream.
	///
	/// # Errors
	///
	/// - The [`StreamRefusal`] of a request part.
	async fn forward(requests: &mut StreamRequests, sender: mpsc::Sender<Vec<u8>>) -> Result<(), StreamRefusal> {
		while let Some(message) = requests.next().await? {
			if sender.send(message).await.is_err() {
				break;
			}
		}

		Ok(())
	}

	/// Wait for the channel, call the backend with the requests of
	/// `outbound`, and send each of its answers on `answers`, until the
	/// backend ends the call, or `refusal` gives the refusal of a request
	/// part, before the call or between two answers.
	///
	/// # Errors
	///
	/// - The [`StreamRefusal`] of a request part, or of an answer part.
	async fn answer(
		&self,
		head: &Origin,
		answers: &mut StreamAnswers,
		outbound: mpsc::Receiver<Vec<u8>>,
		refusal: impl Future<Output = StreamRefusal>,
		deadline: &Deadline,
	) -> Result<Status, StreamRefusal> {
		let mut refusal = pin!(refusal);
		let called = Self::before(self.call_stream(head, outbound, deadline), refusal.as_mut());
		let mut inbound = match called.await? {
			Ok(inbound) => inbound,
			Err(status) => return Ok(status),
		};

		loop {
			match Self::before(inbound.message(), refusal.as_mut()).await? {
				Ok(Some(message)) => answers.send(message).await?,
				Ok(None) => return Ok(Status::new(Code::Ok, "")),
				Err(status) => return Ok(status),
			}
		}
	}

	/// What `work` gives, or as `Err` the refusal that `refusal` gives first.
	async fn before<T>(
		work: impl Future<Output = T>,
		refusal: Pin<&mut impl Future<Output = StreamRefusal>>,
	) -> Result<T, StreamRefusal> {
		tokio::select! {
			biased;
			refused = refusal => Err(refused),
			done = work => Ok(done),
		}
	}

	/// Wait for the channel, then call the method of `head` on the backend
	/// with the requests of `outbound` within `deadline`: its answers, or the
	/// status that refused the call.
	async fn call_stream(
		&self,
		head: &Origin,
		outbound: mpsc::Receiver<Vec<u8>>,
		deadline: &Deadline,
	) -> Result<Streaming<Vec<u8>>, Status> {
		let mut grpc = self.ready().await?;
		let path = head.method().path_and_query();
		let request = head.request(ReceiverStream::new(outbound), deadline);

		let response = grpc.streaming(request, path, TunnelCodec).await?;
		Ok(response.into_inner())
	}

	/// The client of the channel, once the channel is ready, which accepts
	/// gzip answers.
	async fn ready(&self) -> Result<Grpc<Channel>, Status> {
		let grpc = Grpc::new(self.channel.clone());
		let mut grpc = grpc.accept_compressed(CompressionEncoding::Gzip);
		let ready = grpc.ready().await;
		ready.map_err(|error| Status::unavailable(error.to_string()))?;
		Ok(grpc)
	}
}

/// The configuration of an adapter servlet: the backend it relays to, the
/// methods it routes, the principals it grants them, the trust it admits
/// calls under, and the identity it signs its replies with.
///
/// # Examples
///
/// ```
/// use tightbeam_grpc::couple::{AdmissionTrust, Assurance, Backend, BackendChannel, Grants, Principal, Routes};
/// # use tightbeam_grpc::testing::TlsAuthority;
/// # use tightbeam_ws::testing::Identity;
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let lifetime = core::time::Duration::from_secs(60);
/// # let dial = TlsAuthority::mint("CN=ledger root", lifetime)?.dial()?;
/// # let channel = BackendChannel::new(&"localhost:7443".parse()?, &dial)?;
/// # let (admission, signer) = (AdmissionTrust::new(), Identity::mint("CN=adapter", 1, lifetime)?.signing_identity());
///
/// let routes = Routes::new().unary("/ledger.v1.Ledger/Post", (), Assurance::Signed)?;
/// let grants = Grants::deny_all().grant(Principal::subject("CN=web,O=acme")?, "/ledger.v1.Ledger/Post")?;
/// let backend = Backend::new(channel, routes, grants, admission, signer)?;
/// # Ok(())
/// # }
/// ```
pub struct Backend {
	channel: BackendChannel,
	policy: Policy<()>,
	admission: AdmissionTrust,
	signer: SigningIdentity,
	timeout: Duration,
	/// The trail of each relay of the adapter, each call that its policy
	/// refuses, and each later part of a stream that its policy permits which
	/// fails to admit or to send, and so ends the stream.
	audit: EdgeAudit,
}

impl Backend {
	/// The deadline of a call of the backend, unless [`Backend::with_timeout`]
	/// sets one.
	pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

	/// An adapter that relays to `channel` the methods of `routes` that
	/// `grants` grant, admits calls under `admission`, and signs its replies
	/// under `signer`.
	///
	/// # Errors
	///
	/// - [`CoupleError::NoRoute`] -- `routes` routes no method.
	/// - [`CoupleError::Method`] -- a grant names a method that no route serves.
	pub fn new(
		channel: BackendChannel,
		routes: Routes<()>,
		grants: Grants,
		admission: AdmissionTrust,
		signer: SigningIdentity,
	) -> Result<Self, CoupleError> {
		let policy = Policy::new(routes, grants)?;
		Ok(Self {
			channel,
			policy,
			admission,
			signer,
			timeout: Self::DEFAULT_TIMEOUT,
			audit: EdgeAudit::default(),
		})
	}

	/// Give each call of the backend at most `timeout`, in place of
	/// [`Backend::DEFAULT_TIMEOUT`].
	#[must_use]
	pub fn with_timeout(mut self, timeout: Duration) -> Self {
		self.timeout = timeout;
		self
	}

	/// Run the timeout of each call of the backend, and the deadline that
	/// each admitted call carries, on `clock`, in place of
	/// [`SystemClock`](tightbeam::clock::SystemClock).
	#[must_use]
	pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
		self.admission = self.admission.with_clock(clock);
		self
	}

	/// Record on `trace` each relay of the adapter, each call that its policy
	/// refuses, and each later part of a stream that its policy permits which
	/// fails to admit or to send, and so ends the stream.
	#[cfg(feature = "instrument")]
	#[must_use]
	pub fn with_trace(mut self, trace: TraceCollector) -> Self {
		self.audit = EdgeAudit::on(Some(trace));
		self
	}

	/// Relay the coupled call of `frame` to the backend, and answer with the
	/// reply that the adapter signs: the answer of the backend, or the status
	/// that refused or ended the call.
	///
	/// # Errors
	///
	/// - [`TightBeamError::WorkRefused`] -- the call does not admit.
	/// - The [`TightBeamError`] of a reply that does not build or sign.
	pub async fn relay(&self, frame: &Frame) -> Result<Option<Frame>, TightBeamError> {
		let admitted = AdmittedCall::admit(frame, &self.admission)?;
		let origin = admitted.origin();
		let permitted = self
			.policy
			.permit(origin.principal(), origin.method(), Carriage::Unary, origin.assurance());
		if let Err(refusal) = permitted {
			self.audit.denied(refusal);
			let refused = CoupledReply::of_status(&refusal.status(), Vec::new())?;
			return admitted.answer(refused, &self.signer).await;
		}

		let answered = self.channel.call(&admitted, self.timeout).await?;
		self.audit.relayed(admitted.origin().method(), answered.code());

		admitted.answer(answered, &self.signer).await
	}

	/// Relay the coupled stream of `body`, which `reply` answers, to the
	/// backend: each request as it arrives, and each answer of the backend
	/// signed under the adapter. The answer ends with the status of the
	/// backend, or the status that refused or ended the stream.
	///
	/// # Errors
	///
	/// - The errors of [`AdmittedStream::admit`], which end the stream.
	/// - The [`TightBeamError`] of answers that broke, such as a push that the timeout cut.
	pub async fn relay_stream(&self, body: StreamBody, reply: ReplySink) -> Result<(), TightBeamError> {
		let stream = AdmittedStream::admit(body, reply, &self.admission, self.signer.clone()).await?;
		let carriage = Carriage::Stream(stream.shape());
		let AdmittedStreamParts { origin: head, requests, answers } = stream.split();
		let permitted = self.policy.permit(head.principal(), head.method(), carriage, head.assurance());
		if let Err(refusal) = permitted {
			self.audit.denied(refusal);
			return answers.end(&refusal.status()).await;
		}

		let relayed = self.channel.stream(&head, requests, answers, self.timeout).await;
		relayed.record(&self.audit, head.method())
	}

	/// The status of a call whose bound on the backend lapsed: 4 once its
	/// deadline passed, and 13 when the clock gave the wait no timer.
	fn lapsed(lapse: Lapse) -> Status {
		match lapse {
			Lapse::Passed => Status::deadline_exceeded("the backend passed the deadline"),
			Lapse::NoTimer => Status::internal("the clock of the adapter gave the call no timer"),
		}
	}
}

/// How the relay of a stream of the backend ended.
enum StreamEnd {
	/// A signed end part of this code ended the stream: the status of the
	/// backend, or of its timeout.
	Relayed(Code),
	/// A part that did not admit or send ended the stream with a signed end
	/// part of its status.
	Refused,
	/// The answers broke, so no end part followed.
	Broken(TightBeamError),
}

impl StreamEnd {
	/// The end of a stream that a refused part ended as `ended` answered.
	fn refused(ended: Result<(), TightBeamError>) -> Self {
		match ended {
			Ok(()) => Self::Refused,
			Err(broken) => Self::Broken(broken),
		}
	}

	/// The end of a stream that the adapter ended with a status of code
	/// `asked`, as `ended` answered with the code that ended it: relayed when
	/// the two agree, and refused when the end of `asked` did not send and
	/// another code ended the stream in its place.
	fn of_answer(asked: Code, ended: Result<Code, TightBeamError>) -> Self {
		match ended {
			Ok(code) if code == asked => Self::Relayed(code),
			Ok(_) => Self::Refused,
			Err(broken) => Self::Broken(broken),
		}
	}

	/// Record the end of a stream of `method` on `audit`, and give the result
	/// of its handler: `Ok` for a stream that a signed end part ended.
	///
	/// # Errors
	///
	/// - [`StreamEnd::Broken`] -- the error of the answers that broke.
	fn record(self, audit: &EdgeAudit, method: &MethodPath) -> Result<(), TightBeamError> {
		match self {
			Self::Relayed(code) => {
				audit.relayed(method, code);
				Ok(())
			}
			Self::Refused => {
				audit.part_refused();
				Ok(())
			}
			Self::Broken(broken) => {
				audit.part_refused();
				Err(broken)
			}
		}
	}
}

impl fmt::Debug for Backend {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Backend").finish_non_exhaustive()
	}
}
