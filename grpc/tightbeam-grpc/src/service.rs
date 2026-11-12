//! The service of an edge: the one parse of each call head, and the arm that
//! serves it.

use core::convert::Infallible;
use core::marker::PhantomData;
use core::num::NonZeroU32;
use core::task::{Context, Poll};

#[cfg(feature = "couple")]
use std::sync::Arc;

use http::header::CONTENT_TYPE;
use http::request::Parts;
use http::{HeaderValue, Method, Request as HttpRequest, Response as HttpResponse};
use tonic::body::Body;
use tonic::metadata::GRPC_CONTENT_TYPE;
use tower_service::Service;

use tightbeam::transport::handshake::HandshakeProvider;

#[cfg(feature = "couple")]
use tokio::sync::Semaphore;

use crate::health::{HealthStatus, WatchTerms, HEALTH_CHECK_PATH, HEALTH_WATCH_PATH};
use crate::tunnel::{BoxFuture, CallRefusal, EdgeAudit, HeadRefusal, TunnelCall, TunnelService, TUNNEL_PATH};

#[cfg(feature = "couple")]
use crate::couple::{LiveCoupler, WebCall};

/// Whether `content_type` is `application/grpc`, in any case, alone, with a
/// `+` subtype, or with `;` parameters after optional whitespace (RFC 9110
/// section 8.3.1).
fn is_grpc(content_type: &[u8]) -> bool {
	let grpc_type = GRPC_CONTENT_TYPE;
	let grpc = grpc_type.as_bytes();
	let Some((media, rest)) = content_type.split_at_checked(grpc.len()) else {
		return false;
	};
	if !media.eq_ignore_ascii_case(grpc) {
		return false;
	}

	let parameters = rest.trim_ascii_start();
	rest.starts_with(b"+") || parameters.is_empty() || parameters.starts_with(b";")
}

/// A path that the edge serves ahead of the routes of its coupler, so no
/// route takes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EdgePath {
	/// The tunnel.
	Tunnel,
	/// The health check.
	HealthCheck,
	/// The health watch.
	HealthWatch,
	/// A method of server reflection, which a coupled edge serves when it is
	/// configured.
	Reflection(ReflectionVersion),
}

/// The version of server reflection that a path calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReflectionVersion {
	/// Version 1.
	V1,
	/// Version 1alpha, which older clients call.
	V1Alpha,
}

/// One value for each version of server reflection.
#[cfg(feature = "couple")]
#[derive(Clone)]
pub(crate) struct Versions<T> {
	/// The value of version 1.
	pub(crate) v1: T,
	/// The value of version 1alpha.
	pub(crate) v1alpha: T,
}

impl ReflectionVersion {
	/// The value of `versions` that this version calls.
	#[cfg(feature = "couple")]
	pub(crate) fn of<T>(self, versions: &Versions<T>) -> &T {
		match self {
			Self::V1 => &versions.v1,
			Self::V1Alpha => &versions.v1alpha,
		}
	}
}

impl EdgePath {
	/// The path prefix of server reflection, version 1.
	const REFLECTION_V1: &'static str = "/grpc.reflection.v1.ServerReflection/";

	/// The path prefix of server reflection, version 1alpha.
	const REFLECTION_V1ALPHA: &'static str = "/grpc.reflection.v1alpha.ServerReflection/";

	/// The edge path of `path`, or `None` for a path that a route may take.
	pub(crate) fn of(path: &str) -> Option<Self> {
		match path {
			TUNNEL_PATH => Some(Self::Tunnel),
			HEALTH_CHECK_PATH => Some(Self::HealthCheck),
			HEALTH_WATCH_PATH => Some(Self::HealthWatch),
			_ if path.starts_with(Self::REFLECTION_V1) => Some(Self::Reflection(ReflectionVersion::V1)),
			_ if path.starts_with(Self::REFLECTION_V1ALPHA) => Some(Self::Reflection(ReflectionVersion::V1Alpha)),
			_ => None,
		}
	}
}

/// What an edge serves beside its tunnel.
pub(crate) enum Served<P: HandshakeProvider + Send + Sync + 'static> {
	/// The tunnel alone.
	Tunnel(PhantomData<fn() -> P>),
	/// The tunnel and the routed methods of its coupler.
	#[cfg(feature = "couple")]
	Coupled(Arc<LiveCoupler<P>>),
}

impl<P: HandshakeProvider + Send + Sync + 'static> Clone for Served<P> {
	fn clone(&self) -> Self {
		match self {
			Self::Tunnel(_) => Self::Tunnel(PhantomData),
			#[cfg(feature = "couple")]
			Self::Coupled(coupler) => Self::Coupled(Arc::clone(coupler)),
		}
	}
}

/// The arm of one call, which the one parse of its head picks.
enum Arm {
	Tunnel(TunnelCall),
	Health(HealthStatus),
	Watch(WatchTerms),
	/// A path other than the tunnel and the two health calls, which the coupler
	/// of a coupled edge serves, with the version of server reflection that
	/// the path calls.
	Routed(Option<ReflectionVersion>),
	/// A request that is no gRPC call.
	Head(HeadRefusal),
	/// A tunnel call that the edge refuses.
	Refused(CallRefusal),
}

impl<P: HandshakeProvider + Send + Sync + 'static> Served<P> {
	/// The one parse of `head`.
	fn arm(&self, head: &Parts) -> Arm {
		if head.method != Method::POST {
			return Arm::Head(HeadRefusal::Method);
		}

		let content_type = head.headers.get(CONTENT_TYPE).map(HeaderValue::as_bytes);
		if !content_type.is_some_and(is_grpc) {
			return Arm::Head(HeadRefusal::MediaType);
		}

		match EdgePath::of(head.uri.path()) {
			Some(EdgePath::Tunnel) => TunnelCall::claim(head).map_or_else(Arm::Refused, Arm::Tunnel),
			Some(EdgePath::HealthCheck) => Arm::Health(self.health()),
			Some(EdgePath::HealthWatch) => Arm::Watch(self.watch(head)),
			Some(EdgePath::Reflection(version)) => Arm::Routed(Some(version)),
			None => Arm::Routed(None),
		}
	}

	/// The terms of a health watch on the connection of `head`: the status of
	/// a tunnel edge, which stays fixed, or the serving state of a coupled
	/// edge.
	#[cfg_attr(not(feature = "couple"), allow(unused_variables))]
	fn watch(&self, head: &Parts) -> WatchTerms {
		match self {
			Self::Tunnel(_) => WatchTerms::steady(HealthStatus::Serving),
			#[cfg(feature = "couple")]
			Self::Coupled(coupler) => coupler.watch(head),
		}
	}

	/// The HTTP/2 streams that a connection of the edge admits at once: one
	/// for a tunnel edge, which carries one tunnel per connection, and the
	/// stream limit of the coupler for a coupled edge.
	pub(crate) fn streams(&self) -> NonZeroU32 {
		match self {
			Self::Tunnel(_) => NonZeroU32::MIN,
			#[cfg(feature = "couple")]
			Self::Coupled(coupler) => coupler.streams(),
		}
	}

	/// The permits of the coupled connections of the edge, which only a
	/// coupled edge holds.
	#[cfg(feature = "couple")]
	pub(crate) fn lanes(&self) -> Option<Arc<Semaphore>> {
		match self {
			Self::Tunnel(_) => None,
			Self::Coupled(coupler) => Some(coupler.lanes()),
		}
	}

	/// The health of the edge: a tunnel edge serves while it listens, and a
	/// coupled edge while its loopback session is open.
	fn health(&self) -> HealthStatus {
		match self {
			Self::Tunnel(_) => HealthStatus::Serving,
			#[cfg(feature = "couple")]
			Self::Coupled(coupler) => HealthStatus::of(coupler.health()),
		}
	}

	/// Serve a call on a routed path, which calls the version `reflection` of
	/// server reflection when it is `Some`: the coupler on a coupled edge, and
	/// a refusal of the path otherwise, which `audit` records.
	#[cfg_attr(not(feature = "couple"), allow(unused_variables))]
	async fn route(
		&self,
		audit: &EdgeAudit,
		reflection: Option<ReflectionVersion>,
		request: HttpRequest<Body>,
	) -> HttpResponse<Body> {
		match self {
			Self::Tunnel(_) => audit.status(CallRefusal::Path).into_http(),
			#[cfg(feature = "couple")]
			Self::Coupled(coupler) => Arc::clone(coupler).route(reflection, request).await,
		}
	}

	/// What `request` is to the gRPC-Web arm of the edge: every call of an
	/// edge with no gRPC-Web is native.
	#[cfg(feature = "couple")]
	fn web_call(&self, request: &HttpRequest<Body>) -> WebCall {
		match self {
			Self::Tunnel(_) => WebCall::Native,
			Self::Coupled(coupler) => coupler.web_call(request.method(), request.headers()),
		}
	}
}

/// The service of an edge server.
pub(crate) struct EdgeService<P: HandshakeProvider + Send + Sync + 'static> {
	tunnel: TunnelService,
	audit: EdgeAudit,
	served: Served<P>,
}

impl<P: HandshakeProvider + Send + Sync + 'static> Clone for EdgeService<P> {
	fn clone(&self) -> Self {
		Self {
			tunnel: self.tunnel.clone(),
			audit: self.audit.clone(),
			served: self.served.clone(),
		}
	}
}

impl<P: HandshakeProvider + Send + Sync + 'static> EdgeService<P> {
	/// The service that serves `tunnel` and what `served` names, and records
	/// each refusal of a head on `audit`.
	pub(crate) fn new(tunnel: TunnelService, audit: EdgeAudit, served: Served<P>) -> Self {
		Self { tunnel, audit, served }
	}
}

impl<P: HandshakeProvider + Send + Sync + 'static> EdgeService<P> {
	/// Serve `request` by the arm that the one parse of its head picks.
	async fn serve(self, request: HttpRequest<Body>) -> Result<HttpResponse<Body>, Infallible> {
		let (head, body) = request.into_parts();
		let arm = self.served.arm(&head);
		let request = HttpRequest::from_parts(head, body);

		let response = match arm {
			Arm::Tunnel(call) => self.tunnel.serve(call, request).await,
			Arm::Health(status) => status.serve(request).await,
			Arm::Watch(terms) => terms.serve(request).await,
			Arm::Routed(reflection) => self.served.route(&self.audit, reflection, request).await,
			Arm::Head(refusal) => self.audit.answer(refusal),
			Arm::Refused(refusal) => self.audit.status(refusal).into_http(),
		};
		Ok(response)
	}
}

/// The native arm of an edge, which a gRPC-Web call reaches once tonic-web
/// translates it. It serves each call as native, so each call translates
/// once.
#[cfg(feature = "couple")]
struct NativeEdge<P: HandshakeProvider + Send + Sync + 'static>(EdgeService<P>);

#[cfg(feature = "couple")]
impl<P: HandshakeProvider + Send + Sync + 'static> Service<HttpRequest<Body>> for NativeEdge<P> {
	type Response = HttpResponse<Body>;
	type Error = Infallible;
	type Future = BoxFuture<Result<Self::Response, Infallible>>;

	fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
		Poll::Ready(Ok(()))
	}

	fn call(&mut self, request: HttpRequest<Body>) -> Self::Future {
		Box::pin(self.0.clone().serve(request))
	}
}

impl<P: HandshakeProvider + Send + Sync + 'static> Service<HttpRequest<Body>> for EdgeService<P> {
	type Response = HttpResponse<Body>;
	type Error = Infallible;
	type Future = BoxFuture<Result<Self::Response, Infallible>>;

	fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
		Poll::Ready(Ok(()))
	}

	fn call(&mut self, request: HttpRequest<Body>) -> Self::Future {
		let service = self.clone();

		#[cfg(feature = "couple")]
		{
			let call = service.served.web_call(&request);
			call.serve(request, NativeEdge(service))
		}

		#[cfg(not(feature = "couple"))]
		Box::pin(service.serve(request))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_grpc_media_type_matches_in_any_case_with_a_subtype_or_parameters() {
		let admitted: [&[u8]; 7] = [
			b"application/grpc",
			b"application/grpc+proto",
			b"application/grpc;charset=utf-8",
			b"Application/gRPC",
			b"APPLICATION/GRPC+der",
			b"application/grpc ; charset=utf-8",
			b"application/grpc ",
		];
		let refused: [&[u8]; 5] = [
			b"application/grpc-web",
			b"application/grpc2",
			b"application/json",
			b"application/grp",
			b"",
		];

		assert!(admitted.into_iter().all(is_grpc));
		assert!(!refused.into_iter().any(is_grpc));
	}

	/// The head of a call with `method`, on `path`, under `application/grpc`.
	fn head(method: Method, path: &str) -> Result<Parts, http::Error> {
		let request = HttpRequest::builder().method(method).uri(path);
		let request = request.header(CONTENT_TYPE, "application/grpc").body(())?;
		let (head, ()) = request.into_parts();
		Ok(head)
	}

	#[test]
	fn a_head_the_edge_cannot_carry_is_refused_before_it_claims_a_lane() -> Result<(), http::Error> {
		type Default = tightbeam::crypto::profiles::DefaultCryptoProvider;
		let served = Served::<Default>::Tunnel(PhantomData);
		let mut text = head(Method::POST, TUNNEL_PATH)?;
		text.headers.insert(CONTENT_TYPE, http::HeaderValue::from_static("text/plain"));
		let cases = [
			(head(Method::GET, TUNNEL_PATH)?, HeadRefusal::Method),
			(text, HeadRefusal::MediaType),
		];

		for (head, expected) in cases {
			let refused = match served.arm(&head) {
				Arm::Head(refusal) => Some(refusal),
				_ => None,
			};
			assert_eq!(refused, Some(expected));
		}

		let unconnected = head(Method::POST, TUNNEL_PATH)?;
		assert!(matches!(served.arm(&unconnected), Arm::Refused(CallRefusal::Unconnected)));

		let other = head(Method::POST, "/other.v1.Service/Call")?;
		assert!(matches!(served.arm(&other), Arm::Routed(None)));
		Ok(())
	}

	tightbeam::tb_cases! {
		fn a_reflection_path_routes_with_its_version((path, version): (&'static str, ReflectionVersion)) {
			type Default = tightbeam::crypto::profiles::DefaultCryptoProvider;
			let served = Served::<Default>::Tunnel(PhantomData);
			let reflected = head(Method::POST, path).expect("a head builds");
			assert!(matches!(served.arm(&reflected), Arm::Routed(Some(routed)) if routed == version));
		}

		cases {
			version_one => ("/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", ReflectionVersion::V1),
			version_one_alpha => ("/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", ReflectionVersion::V1Alpha),
		}
	}

	#[test]
	fn a_tunnel_edge_answers_its_health_check() -> Result<(), http::Error> {
		type Default = tightbeam::crypto::profiles::DefaultCryptoProvider;
		let served = Served::<Default>::Tunnel(PhantomData);
		let check = head(Method::POST, HEALTH_CHECK_PATH)?;
		assert!(matches!(served.arm(&check), Arm::Health(HealthStatus::Serving)));
		Ok(())
	}
}
