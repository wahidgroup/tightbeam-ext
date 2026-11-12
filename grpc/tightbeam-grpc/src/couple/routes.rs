//! What a coupled edge serves, and to whom: the routes from a gRPC method to
//! the servlet that serves it, the grants of each method to principals, and
//! the one policy that decides each call by both.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::x509::{Certificate, ErasedSigning, KeyPurposes, PeerCertificate};
use tightbeam::der::Enumerated;
use tightbeam::urn::Urn;
use tightbeam::Frame;

use tonic::Status;

use super::error::CoupleError;
use super::limits::CallLimits;
use super::method::MethodPath;
use super::principal::Principal;
use crate::edge::EdgeError;
use crate::service::EdgePath;

/// How much a coupled call proves about its caller.
///
/// The variants are ordered, so a route that requires [`Assurance::Vouched`]
/// also admits a [`Assurance::Signed`] call, and refuses a
/// [`Assurance::Bearer`] call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Assurance {
	/// The edge verified a bearer token of the caller, which anyone who holds
	/// the token can present, and the coupler vouches for the call under its
	/// own identity.
	Bearer,
	/// The edge verified the TLS client chain of the caller, its own or one
	/// that a pinned proxy forwards, and the coupler vouches for the call
	/// under its own identity.
	Vouched,
	/// The caller also signed the call under its own tightbeam identity: a
	/// claim over the method, the body, and its TLS certificate, or the frame
	/// of a direct call that the caller signs itself.
	Signed,
}

impl Assurance {
	/// The name that the audit trail records the assurance under.
	#[cfg(feature = "instrument")]
	pub(crate) const fn as_str(self) -> &'static str {
		match self {
			Self::Bearer => "bearer",
			Self::Vouched => "vouched",
			Self::Signed => "signed",
		}
	}
}

/// The servlet that serves a routed method of a coupled edge, and the
/// certificate whose key signs its answers, which the coupler pins.
///
/// # Examples
///
/// ```
/// use tightbeam::urn;
/// use tightbeam_grpc::couple::Servlet;
/// # use tightbeam_ws::testing::Identity;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let place_signer = Identity::mint("CN=place", 1, core::time::Duration::from_secs(60))?.certificate().clone();
///
/// let place = Servlet::new(urn!("orders", "servlet:place"), place_signer)?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Servlet {
	urn: Urn<'static>,
	answered_by: Arc<PeerCertificate<ErasedSigning>>,
}

impl Servlet {
	/// The servlet type `urn`, whose answers the key of `answered_by` signs.
	///
	/// # Errors
	///
	/// - [`EdgeError::Trust`] -- `answered_by` is admitted for no signing.
	pub fn new(urn: Urn<'static>, answered_by: Certificate) -> Result<Self, EdgeError> {
		let answered_by = PeerCertificate::<ErasedSigning>::parse(answered_by, KeyPurposes::HOUSE.signer)?;
		Ok(Self { urn, answered_by: Arc::new(answered_by) })
	}

	pub(crate) fn urn(&self) -> &Urn<'static> {
		&self.urn
	}

	/// Whether `frame` is an answer of the servlet: it verifies under the
	/// pinned certificate, under the secp256k1 policy of tightbeam.
	pub(crate) fn verifies(&self, frame: &Frame) -> bool {
		frame.verify_under(&self.answered_by, &Secp256k1Policy::default()).is_ok()
	}
}

/// How many messages each side of a routed method sends.
#[derive(Enumerated, Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum Shape {
	/// One request and one response.
	Unary = 0,
	/// A stream of requests and one response.
	ClientStream = 1,
	/// One request and a stream of responses.
	ServerStream = 2,
	/// A stream each way.
	Bidi = 3,
}

impl Shape {
	/// The shape of a method that runs as a stream, or `None` for one unary
	/// exchange.
	pub(crate) fn streamed(self) -> Option<StreamShape> {
		match self {
			Self::Unary => None,
			Self::ClientStream => Some(StreamShape::ClientStream),
			Self::ServerStream => Some(StreamShape::ServerStream),
			Self::Bidi => Some(StreamShape::Bidi),
		}
	}

	/// How many request messages the caller sends.
	pub(crate) fn requests(self) -> Arity {
		match self {
			Self::Unary | Self::ServerStream => Arity::One,
			Self::ClientStream | Self::Bidi => Arity::Many,
		}
	}

	/// How many response messages the servlet answers.
	pub(crate) fn responses(self) -> Arity {
		match self {
			Self::Unary | Self::ClientStream => Arity::One,
			Self::ServerStream | Self::Bidi => Arity::Many,
		}
	}
}

/// The shape of a method that runs as a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamShape {
	/// A stream of requests and one response.
	ClientStream,
	/// One request and a stream of responses.
	ServerStream,
	/// A stream each way.
	Bidi,
}

impl From<StreamShape> for Shape {
	fn from(shape: StreamShape) -> Self {
		match shape {
			StreamShape::ClientStream => Self::ClientStream,
			StreamShape::ServerStream => Self::ServerStream,
			StreamShape::Bidi => Self::Bidi,
		}
	}
}

/// How many messages one side of a method sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Arity {
	/// Exactly one.
	One,
	/// Any number.
	Many,
}

impl Arity {
	/// Whether a side that sent `sent` messages may send another.
	pub(crate) fn admits_another(self, sent: u32) -> bool {
		match self {
			Self::One => sent == 0,
			Self::Many => true,
		}
	}

	/// Whether a side that sent `sent` messages may end with status 0.
	pub(crate) fn closes(self, sent: u32) -> bool {
		match self {
			Self::One => sent == 1,
			Self::Many => true,
		}
	}
}

/// How a call reaches its target: as one exchange, or as a stream of the
/// shape that its head fixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Carriage {
	Unary,
	Stream(StreamShape),
}

impl Carriage {
	/// Whether a method of `shape` arrives by this carriage.
	fn carries(self, shape: Shape) -> bool {
		match self {
			Self::Unary => shape.streamed().is_none(),
			Self::Stream(carried) => shape.streamed() == Some(carried),
		}
	}
}

/// One routed method: its target, its shape, and the assurance it requires.
#[derive(Clone, Debug)]
pub(crate) struct Route<T> {
	target: T,
	shape: Shape,
	required: Assurance,
}

impl<T> Route<T> {
	/// What serves the method.
	pub(crate) fn target(&self) -> &T {
		&self.target
	}
}

/// The methods that a coupler or a backend routes, each to the target `T`
/// that serves it: a [`Servlet`] on a coupled edge, and `()` on a
/// [`Backend`](super::Backend), whose one channel serves every method.
///
/// # Examples
///
/// ```
/// use tightbeam_grpc::couple::{Assurance, Routes, Servlet};
/// # use tightbeam_ws::testing::Identity;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let place_signer = Identity::mint("CN=place", 1, core::time::Duration::from_secs(60))?.certificate().clone();
/// # let place = Servlet::new(tightbeam::urn!("orders", "servlet:place"), place_signer)?;
///
/// let routes = Routes::new().unary("/orders.v1.Orders/Place", place, Assurance::Signed)?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Routes<T> {
	table: HashMap<MethodPath, Route<T>>,
}

impl<T> Default for Routes<T> {
	fn default() -> Self {
		Self { table: HashMap::new() }
	}
}

impl<T> Routes<T> {
	/// No route, so nothing is served until a route is added.
	#[must_use]
	pub fn new() -> Self {
		Self::default()
	}

	/// Route the unary method `method`, such as `/orders.v1.Orders/Place`, to
	/// `target`, for calls of `required` assurance or more.
	///
	/// # Errors
	///
	/// - [`CoupleError::Method`] -- `method` is no [`MethodPath`], names a path
	///   that the edge serves itself, or is routed already.
	pub fn unary<M>(self, method: M, target: T, required: Assurance) -> Result<Self, CoupleError>
	where
		M: TryInto<MethodPath>,
		CoupleError: From<M::Error>,
	{
		self.route_as(method.try_into()?, target, Shape::Unary, required)
	}

	/// Route `method` as `shape` to `target`, for calls of `required` assurance
	/// or more.
	fn route_as(
		mut self,
		method: MethodPath,
		target: T,
		shape: Shape,
		required: Assurance,
	) -> Result<Self, CoupleError> {
		let path = method.as_str();
		if EdgePath::of(path).is_some() || self.table.contains_key(&method) {
			return Err(CoupleError::Method(path.to_owned()));
		}

		self.table.insert(method, Route { target, shape, required });
		Ok(self)
	}
}

/// The streaming methods, which reach their servlet over a multiplexed
/// session. A servlet serves each one in its duplex arm, through
/// [`AdmittedStream`](super::AdmittedStream), and a backend through
/// [`Backend::relay_stream`](super::Backend::relay_stream).
impl<T> Routes<T> {
	/// Route the client-streaming method `method` to `target`, for calls of
	/// `required` assurance or more.
	///
	/// # Errors
	///
	/// - The errors of [`Routes::unary`].
	pub fn client_stream<M>(self, method: M, target: T, required: Assurance) -> Result<Self, CoupleError>
	where
		M: TryInto<MethodPath>,
		CoupleError: From<M::Error>,
	{
		self.route_as(method.try_into()?, target, Shape::ClientStream, required)
	}

	/// Route the server-streaming method `method` to `target`, for calls of
	/// `required` assurance or more.
	///
	/// # Errors
	///
	/// - The errors of [`Routes::unary`].
	pub fn server_stream<M>(self, method: M, target: T, required: Assurance) -> Result<Self, CoupleError>
	where
		M: TryInto<MethodPath>,
		CoupleError: From<M::Error>,
	{
		self.route_as(method.try_into()?, target, Shape::ServerStream, required)
	}

	/// Route the bidirectional streaming method `method` to `target`, for
	/// calls of `required` assurance or more.
	///
	/// # Errors
	///
	/// - The errors of [`Routes::unary`].
	pub fn bidi_stream<M>(self, method: M, target: T, required: Assurance) -> Result<Self, CoupleError>
	where
		M: TryInto<MethodPath>,
		CoupleError: From<M::Error>,
	{
		self.route_as(method.try_into()?, target, Shape::Bidi, required)
	}
}

/// The methods that each principal may call. A coupled edge denies every
/// call that no grant names.
///
/// # Examples
///
/// ```
/// use tightbeam_grpc::couple::{Grants, Principal};
///
/// let grants = Grants::deny_all().grant(Principal::spiffe("spiffe://acme/billing")?, "/orders.v1.Orders/Place")?;
/// # Ok::<(), tightbeam_grpc::couple::CoupleError>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct Grants {
	table: HashMap<MethodPath, HashSet<Principal>>,
}

impl Grants {
	/// No grant, so every call is denied.
	#[must_use]
	pub fn deny_all() -> Self {
		Self::default()
	}

	/// Grant `principal` the method `method`. `Coupler::new` and
	/// `Backend::new` refuse a grant of a method that no route serves.
	///
	/// # Errors
	///
	/// - [`CoupleError::Method`] -- `method` is no [`MethodPath`].
	pub fn grant<M>(mut self, principal: Principal, method: M) -> Result<Self, CoupleError>
	where
		M: TryInto<MethodPath>,
		CoupleError: From<M::Error>,
	{
		self.table.entry(method.try_into()?).or_default().insert(principal);
		Ok(self)
	}

	/// Whether `principal` may call `method`.
	fn permits(&self, principal: &Principal, method: &MethodPath) -> bool {
		self.table.get(method).is_some_and(|principals| principals.contains(principal))
	}
}

/// Why a policy refuses a call, which decides the status of its answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AccessRefusal {
	/// No route serves the method, or none serves it by the carriage of the
	/// call.
	Unrouted,
	/// No grant names the principal for the method, or the call proves less
	/// assurance than the route requires.
	Denied,
}

impl AccessRefusal {
	/// The name that an audit trail records the refusal under.
	#[cfg(feature = "instrument")]
	pub(crate) const fn as_str(self) -> &'static str {
		match self {
			Self::Unrouted => "unrouted",
			Self::Denied => "denied",
		}
	}

	/// The status that answers the refusal.
	pub(crate) fn status(self) -> Status {
		match self {
			Self::Unrouted => Status::unimplemented("no route serves the method"),
			Self::Denied => Status::permission_denied("the caller may not call the method"),
		}
	}
}

/// The routes and the grants of one coupler or backend, which decide every
/// call that it serves.
#[derive(Debug)]
pub(crate) struct Policy<T> {
	routes: Routes<T>,
	grants: Grants,
}

impl<T: Clone> Policy<T> {
	/// The policy of `routes` and `grants`.
	///
	/// # Errors
	///
	/// - [`CoupleError::NoRoute`] -- no method is routed.
	/// - [`CoupleError::Method`] -- a grant names a method that no route serves.
	pub(crate) fn new(routes: Routes<T>, grants: Grants) -> Result<Self, CoupleError> {
		if routes.table.is_empty() {
			return Err(CoupleError::NoRoute);
		}

		let unrouted = grants.table.keys().find(|method| !routes.table.contains_key(*method));
		if let Some(unrouted) = unrouted {
			return Err(CoupleError::Method(unrouted.as_str().to_owned()));
		}

		Ok(Self { routes, grants })
	}

	/// Whether `limits` carry the routes of the policy: they give open streams
	/// a share, or no route runs as a stream.
	pub(crate) fn carries(&self, limits: &CallLimits) -> bool {
		limits.relays().is_some() || !self.routes.table.values().any(|route| route.shape.streamed().is_some())
	}

	/// The route of `method` for `principal`, before what the call proves is
	/// known.
	///
	/// # Errors
	///
	/// - [`AccessRefusal::Unrouted`] -- no route serves `method`.
	/// - [`AccessRefusal::Denied`] -- no grant names `principal` for `method`.
	pub(crate) fn grant(&self, principal: &Principal, method: &MethodPath) -> Result<Granted<T>, AccessRefusal> {
		let route = self.routes.table.get(method).ok_or(AccessRefusal::Unrouted)?;
		if !self.grants.permits(principal, method) {
			return Err(AccessRefusal::Denied);
		}

		Ok(Granted(route.clone()))
	}

	/// The route of a call of `method` by `principal` that arrived by
	/// `carriage` and proves `assurance`.
	///
	/// # Errors
	///
	/// - [`AccessRefusal::Unrouted`] -- no route serves `method` by `carriage`.
	/// - [`AccessRefusal::Denied`] -- no grant names `principal` for `method`,
	///   or the route requires more than `assurance`.
	pub(crate) fn permit(
		&self,
		principal: &Principal,
		method: &MethodPath,
		carriage: Carriage,
		assurance: Assurance,
	) -> Result<Route<T>, AccessRefusal> {
		let route = self.routes.table.get(method);
		let carried = route.is_some_and(|route| carriage.carries(route.shape));
		if !carried {
			return Err(AccessRefusal::Unrouted);
		}

		self.grant(principal, method)?.accept(assurance)
	}

	/// Whether a grant names `principal` for any method.
	pub(crate) fn names(&self, principal: &Principal) -> bool {
		self.grants.table.values().any(|principals| principals.contains(principal))
	}

	pub(crate) fn methods(&self) -> impl Iterator<Item = &MethodPath> {
		self.routes.table.keys()
	}
}

/// A route whose grant names the caller of a call, before what the call
/// proves is known.
#[derive(Debug)]
pub(crate) struct Granted<T>(Route<T>);

impl<T> Granted<T> {
	/// How many messages each side of the method sends.
	pub(crate) fn shape(&self) -> Shape {
		self.0.shape
	}

	/// The route, once it accepts a call that proves `assurance`.
	///
	/// # Errors
	///
	/// - [`AccessRefusal::Denied`] -- the route requires more than `assurance`.
	pub(crate) fn accept(self, assurance: Assurance) -> Result<Route<T>, AccessRefusal> {
		if assurance < self.0.required {
			return Err(AccessRefusal::Denied);
		}

		Ok(self.0)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::protocol::TUNNEL_PATH;

	tightbeam::tb_cases! {
		fn a_reserved_or_malformed_path_is_refused(path: &str) {
			let refused = Routes::new().unary(path, (), Assurance::Vouched);
			assert!(refused.is_err());
		}

		cases {
			the_tunnel => TUNNEL_PATH,
			the_health_check => "/grpc.health.v1.Health/Check",
			the_health_watch => "/grpc.health.v1.Health/Watch",
			reflection => "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
			reflection_v1alpha => "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
			no_slash => "orders",
		}
	}

	#[test]
	fn a_repeated_method_is_refused() {
		let routed = Routes::new().unary("/orders.v1.Orders/Get", (), Assurance::Vouched);
		let repeated = routed.and_then(|routes| routes.unary("/orders.v1.Orders/Get", (), Assurance::Vouched));
		assert!(repeated.is_err());
	}

	tightbeam::tb_cases! {
		fn each_shape_counts_its_messages((shape, expected): (Shape, (Arity, Arity))) {
			assert_eq!((shape.requests(), shape.responses()), expected);
		}

		cases {
			unary => (Shape::Unary, (Arity::One, Arity::One)),
			client_stream => (Shape::ClientStream, (Arity::Many, Arity::One)),
			server_stream => (Shape::ServerStream, (Arity::One, Arity::Many)),
			bidi => (Shape::Bidi, (Arity::Many, Arity::Many)),
		}
	}

	tightbeam::tb_cases! {
		fn an_arity_admits_and_closes_by_its_count((arity, sent, expected): (Arity, u32, (bool, bool))) {
			assert_eq!((arity.admits_another(sent), arity.closes(sent)), expected);
		}

		cases {
			one_before_its_message => (Arity::One, 0, (true, false)),
			one_after_its_message => (Arity::One, 1, (false, true)),
			many_before_any => (Arity::Many, 0, (true, true)),
			many_after_several => (Arity::Many, 9, (true, true)),
		}
	}

	/// The principal of the billing caller, which the policy grants.
	fn billing() -> Principal {
		Principal::spiffe("spiffe://acme/billing").expect("the billing caller is a SPIFFE ID")
	}

	/// A policy that routes `Get` as a vouched unary call and `Watch` as a
	/// vouched server stream, and grants both to the billing caller.
	fn policy() -> Policy<()> {
		let routes = Routes::new().unary("/orders.v1.Orders/Get", (), Assurance::Vouched);
		let routes = routes.and_then(|routes| routes.server_stream("/orders.v1.Orders/Watch", (), Assurance::Vouched));
		let grants = Grants::deny_all().grant(billing(), "/orders.v1.Orders/Get");
		let grants = grants.and_then(|grants| grants.grant(billing(), "/orders.v1.Orders/Watch"));
		let policy = Policy::new(routes.expect("the routes parse"), grants.expect("the grants parse"));
		policy.expect("every grant names a routed method")
	}

	tightbeam::tb_cases! {
		fn the_policy_decides_each_call((caller, method, carriage, assurance, expected): (Principal, &str, Carriage, Assurance, Result<(), AccessRefusal>)) -> Result<(), CoupleError> {
			let decided = policy().permit(&caller, &method.parse()?, carriage, assurance).map(|_| ());
			assert_eq!(decided, expected);
			Ok(())
		}

		cases {
			a_granted_call_that_proves_enough => (billing(), "/orders.v1.Orders/Get", Carriage::Unary, Assurance::Vouched, Ok(())),
			a_signed_call_on_a_vouched_route => (billing(), "/orders.v1.Orders/Get", Carriage::Unary, Assurance::Signed, Ok(())),
			an_unrouted_method => (billing(), "/orders.v1.Orders/Cancel", Carriage::Unary, Assurance::Signed, Err(AccessRefusal::Unrouted)),
			a_unary_method_as_a_stream => (billing(), "/orders.v1.Orders/Get", Carriage::Stream(StreamShape::Bidi), Assurance::Signed, Err(AccessRefusal::Unrouted)),
			a_stream_as_a_unary_call => (billing(), "/orders.v1.Orders/Watch", Carriage::Unary, Assurance::Signed, Err(AccessRefusal::Unrouted)),
			a_principal_with_no_grant => (Principal::subject("CN=web").expect("a subject"), "/orders.v1.Orders/Get", Carriage::Unary, Assurance::Signed, Err(AccessRefusal::Denied)),
			a_bearer_call_on_a_vouched_route => (billing(), "/orders.v1.Orders/Get", Carriage::Unary, Assurance::Bearer, Err(AccessRefusal::Denied)),
		}
	}

	#[test]
	fn a_grant_of_a_method_that_no_route_serves_is_refused() -> Result<(), CoupleError> {
		let routes = Routes::new().unary("/orders.v1.Orders/Get", (), Assurance::Vouched)?;
		let grants = Grants::deny_all().grant(billing(), "/orders.v1.Orders/Cancel")?;
		assert!(matches!(Policy::new(routes, grants), Err(CoupleError::Method(_))));
		Ok(())
	}
}
