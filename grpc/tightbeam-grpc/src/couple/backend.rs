//! The outbound adapter: tightbeam work to a stock gRPC backend.
//!
//! A [`Backend`] is the configuration of a servlet that relays each coupled
//! call it admits to one stock gRPC server, over mutual TLS under the identity
//! of the adapter. The backend reads the principal of each call in the binary
//! metadata [`Backend::PRINCIPAL_KEY`], and the claim that a signed call
//! forwards in [`CallClaim::METADATA_KEY`], so a backend that trusts the
//! adapter decides on the original caller, and a backend that verifies claims
//! checks the caller end to end.
//!
//! The relay of one call is a saga of four acts:
//!
//! | Step | Act | Refuses with |
//! | --- | --- | --- |
//! | 1 | `AdmittedCall::admit` | `WorkRefused(Unauthenticated)` |
//! | 2 | the grants and the route of the method | a signed reply of 12 or 7 |
//! | 3 | the call of the backend, the pivot | a signed reply of the status of the backend, 14, or 4 |
//! | 4 | the signed reply | 13 |
//!
//! The call of the backend is the one act that cannot be undone, and every act
//! that can refuse runs before it. An answer whose reply fails to sign leaves
//! the effect of the backend in place.

use core::fmt;
use core::time::Duration;

use http::uri::PathAndQuery;
use tightbeam::crypto::sign::SigningIdentity;
#[cfg(feature = "instrument")]
use tightbeam::trace::TraceCollector;
use tightbeam::transport::TransportError;
use tightbeam::{Frame, TightBeamError};
use tonic::client::Grpc;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::{Code, Request};

use super::admit::{AdmissionTrust, AdmittedCall};
use super::claim::CallClaim;
use super::routes::{Grants, Routes};
use crate::edge::{DialTls, EdgeError};
#[cfg(feature = "instrument")]
use crate::events::{BACKEND_CALL_REFUSED, BACKEND_CALL_RELAYED};
use crate::protocol::GrpcAddr;
use crate::tunnel::TunnelCodec;

/// The deadline of a call of the backend, unless [`Backend::with_timeout`]
/// sets one.
const DEFAULT_BACKEND_TIMEOUT: Duration = Duration::from_secs(30);

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
	/// - [`TransportError::InvalidAddress`] -- tonic refuses the URI of
	///   `addr`, or TLS cannot name its host.
	pub fn new(addr: &GrpcAddr, tls: &DialTls) -> Result<Self, TransportError> {
		let (endpoint, dialer) = tls.endpoint(addr)?;
		let channel = endpoint.connect_with_connector_lazy(dialer);
		Ok(Self { channel })
	}

	/// Step 3, the pivot: call `permitted` on the backend within `timeout`,
	/// with its principal and its forwarded claim in the metadata of the call.
	async fn call(&self, permitted: &Permitted, timeout: Duration) -> Answered {
		let mut grpc = Grpc::new(self.channel.clone());
		if let Err(error) = grpc.ready().await {
			return Answered::status(Code::Unavailable, error.to_string());
		}

		let admitted = &permitted.admitted;
		let Ok(path) = PathAndQuery::try_from(admitted.method()) else {
			return Answered::status(Code::Internal, "the method is no path".to_owned());
		};

		let mut request = Request::new(admitted.body().to_vec());
		request.set_timeout(timeout);

		let principal = admitted.principal().to_string();
		let metadata = request.metadata_mut();
		metadata.insert_bin(Backend::PRINCIPAL_KEY, MetadataValue::from_bytes(principal.as_bytes()));

		if let Some(claim) = admitted.claim() {
			metadata.insert_bin(CallClaim::METADATA_KEY, MetadataValue::from_bytes(claim));
		}

		let called = tokio::time::timeout(timeout, grpc.unary(request, path, TunnelCodec)).await;
		match called {
			Ok(Ok(response)) => Answered { code: Code::Ok, message: None, body: response.into_inner() },
			Ok(Err(status)) => Answered::status(status.code(), status.message().to_owned()),
			Err(_) => Answered::status(Code::DeadlineExceeded, "the backend passed the deadline".to_owned()),
		}
	}
}

/// Why the adapter refuses an admitted call before it calls the backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
	/// The backend routes no such method.
	Unrouted,
	/// No grant names the principal for the method, or the call proves less
	/// assurance than the route requires.
	Denied,
}

impl Refusal {
	/// The status of the signed reply that answers the refusal.
	const fn code(self) -> Code {
		match self {
			Self::Unrouted => Code::Unimplemented,
			Self::Denied => Code::PermissionDenied,
		}
	}

	/// The name that the audit trail records the refusal under.
	const fn as_str(self) -> &'static str {
		match self {
			Self::Unrouted => "unrouted",
			Self::Denied => "denied",
		}
	}
}

/// Step 2: a call that its principal may make on the backend.
struct Permitted {
	admitted: AdmittedCall,
}

/// Step 3: the answer of the backend, or the status that ended its call.
struct Answered {
	code: Code,
	message: Option<String>,
	body: Vec<u8>,
}

impl Answered {
	/// An answer of the status `code` with `message` and no body.
	fn status(code: Code, message: String) -> Self {
		Self { code, message: Some(message), body: Vec::new() }
	}
}

/// The configuration of an adapter servlet: the backend it relays to, the
/// methods it routes, the principals it grants them, the trust it admits
/// calls under, and the identity it signs its replies with.
///
/// # Examples
///
/// ```no_run
/// use tightbeam::crypto::sign::SigningIdentity;
/// use tightbeam_grpc::couple::{AdmissionTrust, Assurance, Backend, BackendChannel, Grants, Principal, Routes};
///
/// # fn backend(channel: BackendChannel, admission: AdmissionTrust, signer: SigningIdentity) -> Result<(), tightbeam_grpc::edge::EdgeError> {
/// let routes = Routes::new().unary("/ledger.v1.Ledger/Post", (), Assurance::Signed)?;
/// let grants = Grants::deny_all().grant(Principal::subject("CN=web,O=acme")?, "/ledger.v1.Ledger/Post");
/// let backend = Backend::new(channel, routes, grants, admission, signer)?;
/// # Ok(())
/// # }
/// ```
pub struct Backend {
	channel: BackendChannel,
	routes: Routes<()>,
	grants: Grants,
	admission: AdmissionTrust,
	signer: SigningIdentity,
	timeout: Duration,
	#[cfg(feature = "instrument")]
	trace: Option<TraceCollector>,
}

impl Backend {
	/// The binary metadata key that carries the principal of each call: the
	/// UTF-8 of its SPIFFE ID, or of its subject in the string form of
	/// RFC 4514.
	pub const PRINCIPAL_KEY: &'static str = "tightbeam-principal-bin";

	/// An adapter that relays to `channel` the methods of `routes` that
	/// `grants` grant, admits calls under `admission`, and signs its replies
	/// under `signer`.
	///
	/// # Errors
	///
	/// - [`EdgeError::NoRoute`] -- `routes` routes no method.
	/// - [`EdgeError::Method`] -- a grant names a method that no route serves.
	pub fn new(
		channel: BackendChannel,
		routes: Routes<()>,
		grants: Grants,
		admission: AdmissionTrust,
		signer: SigningIdentity,
	) -> Result<Self, EdgeError> {
		routes.cover(&grants)?;
		Ok(Self {
			channel,
			routes,
			grants,
			admission,
			signer,
			timeout: DEFAULT_BACKEND_TIMEOUT,
			#[cfg(feature = "instrument")]
			trace: None,
		})
	}

	/// Give each call of the backend at most `timeout`, in place of 30 seconds.
	#[must_use]
	pub fn with_timeout(mut self, timeout: Duration) -> Self {
		self.timeout = timeout;
		self
	}

	/// Record each relay and each refusal of the adapter on `trace`.
	#[cfg(feature = "instrument")]
	#[must_use]
	pub fn with_trace(mut self, trace: TraceCollector) -> Self {
		self.trace = Some(trace);
		self
	}

	/// The trust that the adapter admits its calls under.
	pub fn admission(&self) -> &AdmissionTrust {
		&self.admission
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
		if let Some(refusal) = self.refusal_of(&admitted) {
			self.record_refusal(refusal);
			let message = Some(refusal.as_str().to_owned());
			return admitted.answer(refusal.code(), message, Vec::new(), &self.signer).await;
		}

		let permitted = Permitted { admitted };
		let answered = self.channel.call(&permitted, self.timeout).await;

		self.record_relay(permitted.admitted.method(), answered.code);

		let Answered { code, message, body } = answered;
		permitted.admitted.answer(code, message, body, &self.signer).await
	}

	/// Step 2: why the adapter refuses `admitted`, or `None` when the backend
	/// routes its method, a grant names its principal for the method, and the
	/// route accepts what it proves.
	fn refusal_of(&self, admitted: &AdmittedCall) -> Option<Refusal> {
		let Some(route) = self.routes.route(admitted.method()) else {
			return Some(Refusal::Unrouted);
		};

		let granted = self.grants.permits(admitted.principal(), admitted.method());
		let accepted = route.accepts(admitted.assurance());
		(!granted || !accepted).then_some(Refusal::Denied)
	}

	#[cfg(feature = "instrument")]
	fn record_refusal(&self, refusal: Refusal) {
		if let Some(trace) = &self.trace {
			// The trace refuses an event only under the fault that the
			// `testing-fault` feature of tightbeam injects, and the relay
			// answers either way.
			let _ = trace.emit_event_with_value(BACKEND_CALL_REFUSED, refusal.as_str(), refusal.as_str());
		}
	}

	#[cfg(not(feature = "instrument"))]
	fn record_refusal(&self, _refusal: Refusal) {}

	#[cfg(feature = "instrument")]
	fn record_relay(&self, method: &str, code: Code) {
		if let Some(trace) = &self.trace {
			let _ = trace.emit_event_with_value(BACKEND_CALL_RELAYED, method.to_owned(), code as i32 as u32);
		}
	}

	#[cfg(not(feature = "instrument"))]
	fn record_relay(&self, _method: &str, _code: Code) {}
}

impl fmt::Debug for Backend {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Backend").finish_non_exhaustive()
	}
}
