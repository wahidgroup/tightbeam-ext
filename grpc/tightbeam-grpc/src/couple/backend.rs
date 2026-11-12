//! The outbound adapter to a stock gRPC server: it admits and grants a call,
//! calls the server, and then encodes and signs the reply.

use core::fmt;
use core::time::Duration;
use std::sync::Arc;

use tightbeam::clock::{Clock, Lapse};
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::der;
use tightbeam::transport::multiplex::{ReplySink, StreamBody};
use tightbeam::transport::TransportError;
use tightbeam::{Frame, TightBeamError};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::client::Grpc;
use tonic::codec::CompressionEncoding;
use tonic::transport::Channel;
use tonic::{Code, Status};

#[cfg(feature = "instrument")]
use tightbeam::trace::TraceCollector;

use super::admit::{AdmissionTrust, AdmittedCall, Origin};
use super::error::CoupleError;
use super::message::CoupledReply;
use super::routes::{Carriage, Grants, Policy, Routes};
use super::stream::{AdmittedStream, AdmittedStreamParts, StreamAnswers, StreamRequests};
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
	/// of the backend.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a request part that does not admit, which ends the stream.
	/// - The [`TightBeamError`] of an answer part that does not build, sign, or send, such as one past the
	///   count of its method or the part ceiling.
	async fn stream(
		&self,
		head: &Origin,
		mut requests: StreamRequests,
		mut answers: StreamAnswers,
		timeout: Duration,
	) -> Result<Code, TightBeamError> {
		let deadline = head.bounded(timeout);
		let relayed = self.exchange_stream(head, &mut requests, &mut answers, &deadline);
		let status = match deadline.bound(relayed).await {
			Ok(Ok(status)) => status,
			Ok(Err(refused)) => return Err(refused),
			Err(lapse) => Backend::lapsed(lapse),
		};

		answers.end(requests, &status).await?;
		Ok(status.code())
	}

	/// Wait for the channel, then run the stream of `head` both ways at once
	/// within `deadline`: the status that ended it, or the refusal of a
	/// request part or of an answer part.
	async fn exchange_stream(
		&self,
		head: &Origin,
		requests: &mut StreamRequests,
		answers: &mut StreamAnswers,
		deadline: &Deadline,
	) -> Result<Status, TightBeamError> {
		let (sender, outbound) = mpsc::channel(1);
		let forward = async move {
			while let Some(message) = requests.next().await? {
				if sender.send(message).await.is_err() {
					break;
				}
			}

			// The drop of the sender ends the requests, and the answer ends
			// the stream.
			drop(sender);
			core::future::pending::<Result<Status, TightBeamError>>().await
		};

		let answer = async {
			let mut grpc = match self.ready().await {
				Ok(grpc) => grpc,
				Err(status) => return Ok(status),
			};
			let path = head.method().path_and_query();
			let request = head.request(ReceiverStream::new(outbound), deadline);
			let response = match grpc.streaming(request, path, TunnelCodec).await {
				Ok(response) => response,
				Err(status) => return Ok(status),
			};

			let mut inbound = response.into_inner();
			loop {
				match inbound.message().await {
					Ok(Some(message)) => answers.send(message).await?,
					Ok(None) => return Ok(Status::new(Code::Ok, "")),
					Err(status) => return Ok(status),
				}
			}
		};

		tokio::select! {
			answered = answer => answered,
			refused = forward => refused,
		}
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
	/// - The errors of [`AdmittedStream::admit`] and [`StreamRequests::next`], which end the stream.
	/// - The [`TightBeamError`] of an answer part that does not build, sign, or send.
	pub async fn relay_stream(&self, body: StreamBody, reply: ReplySink) -> Result<(), TightBeamError> {
		let stream = AdmittedStream::admit(body, reply, &self.admission, self.signer.clone()).await?;
		let carriage = Carriage::Stream(stream.shape());
		let AdmittedStreamParts { origin: head, requests, answers } = stream.split();
		let permitted = self.policy.permit(head.principal(), head.method(), carriage, head.assurance());
		if let Err(refusal) = permitted {
			self.audit.denied(refusal);
			return answers.end(requests, &refusal.status()).await;
		}

		let relayed = self.channel.stream(&head, requests, answers, self.timeout).await;
		match relayed {
			Ok(code) => {
				self.audit.relayed(head.method(), code);
				Ok(())
			}
			Err(refused) => {
				self.audit.part_refused();
				Err(refused)
			}
		}
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

impl fmt::Debug for Backend {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Backend").finish_non_exhaustive()
	}
}
