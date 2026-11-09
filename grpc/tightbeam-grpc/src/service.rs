//! The service of an edge: the one parse of each call head, and the arm that
//! serves it.

use core::convert::Infallible;
use core::marker::PhantomData;
use core::task::{Context, Poll};

#[cfg(feature = "couple")]
use std::sync::Arc;

use http::header::CONTENT_TYPE;
use http::request::Parts;
use http::{HeaderValue, Method, Request as HttpRequest, Response as HttpResponse};
use tonic::body::Body;
use tonic::metadata::GRPC_CONTENT_TYPE;
use tonic::server::{Grpc, UnaryService};
use tonic::{Request, Response, Status};
use tower_service::Service;

use tightbeam::transport::handshake::HandshakeProvider;

use crate::health::{HealthStatus, HEALTH_CHECK_PATH};
use crate::tunnel::{BoxFuture, Refusal, RefusalAudit, TunnelCall, TunnelCodec, TunnelService, TUNNEL_PATH};

#[cfg(feature = "couple")]
use crate::couple::{CallFault, LiveCoupler};
#[cfg(feature = "couple")]
use crate::incoming::GrpcConnectInfo;

/// The largest health check request an edge decodes: the request names a
/// service, and the edge answers for the empty one alone.
const HEALTH_CEILING: usize = 1024;

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
	/// A path other than the tunnel and the health check, which the coupler
	/// of a coupled edge serves.
	Routed,
	Refused(Refusal),
}

impl<P: HandshakeProvider + Send + Sync + 'static> Served<P> {
	/// The one parse of `head`.
	fn arm(&self, head: &Parts) -> Arm {
		if head.method != Method::POST {
			return Arm::Refused(Refusal::Method);
		}

		let content_type = head.headers.get(CONTENT_TYPE).map(HeaderValue::as_bytes);
		if !content_type.is_some_and(is_grpc) {
			return Arm::Refused(Refusal::MediaType);
		}

		match head.uri.path() {
			TUNNEL_PATH => TunnelCall::claim(head).map_or_else(Arm::Refused, Arm::Tunnel),
			HEALTH_CHECK_PATH => Arm::Health(self.health()),
			_ => Arm::Routed,
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

	/// Serve a call on a routed path: steps 1 and 2 of the coupler, then its
	/// unary call, on a coupled edge, and a refusal of the path otherwise.
	#[cfg_attr(not(feature = "couple"), allow(unused_variables))]
	async fn route(&self, refusals: &RefusalAudit, request: HttpRequest<Body>) -> HttpResponse<Body> {
		match self {
			Self::Tunnel(_) => {
				refusals.refused(&Refusal::Path);
				Refusal::Path.into()
			}
			#[cfg(feature = "couple")]
			Self::Coupled(coupler) => Self::couple(Arc::clone(coupler), request).await,
		}
	}

	/// Steps 1 and 2 of the coupler on `request`, then the unary call that
	/// runs the rest of its saga once tonic decodes the body.
	#[cfg(feature = "couple")]
	async fn couple(coupler: Arc<LiveCoupler<P>>, request: HttpRequest<Body>) -> HttpResponse<Body> {
		let (head, body) = request.into_parts();
		let parsed = match coupler.head(&head) {
			Ok(parsed) => parsed,
			Err(fault) => return coupler.refused(fault).into_http(),
		};

		let lane = head.extensions.get::<GrpcConnectInfo>().map(|connection| &connection.lane);
		let Some(slot) = lane.and_then(crate::incoming::Lane::open_coupled) else {
			return coupler.refused(CallFault::Unavailable).into_http();
		};

		let opened = parsed.opened(slot);
		let request = HttpRequest::from_parts(head, body);
		let ceiling = coupler.ceiling();

		let grpc = Grpc::new(TunnelCodec).max_decoding_message_size(ceiling);
		let mut grpc = grpc.max_encoding_message_size(ceiling);
		grpc.unary(CoupledCall { coupler, opened: Some(opened) }, request).await
	}
}

/// The service of an edge server.
pub(crate) struct EdgeService<P: HandshakeProvider + Send + Sync + 'static> {
	tunnel: TunnelService,
	refusals: RefusalAudit,
	served: Served<P>,
}

impl<P: HandshakeProvider + Send + Sync + 'static> Clone for EdgeService<P> {
	fn clone(&self) -> Self {
		Self {
			tunnel: self.tunnel.clone(),
			refusals: self.refusals.clone(),
			served: self.served.clone(),
		}
	}
}

impl<P: HandshakeProvider + Send + Sync + 'static> EdgeService<P> {
	/// The service that serves `tunnel` and what `served` names, and records
	/// each refusal of a head on `refusals`.
	pub(crate) fn new(tunnel: TunnelService, refusals: RefusalAudit, served: Served<P>) -> Self {
		Self { tunnel, refusals, served }
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

		Box::pin(async move {
			let (head, body) = request.into_parts();
			let arm = service.served.arm(&head);
			let request = HttpRequest::from_parts(head, body);

			let response = match arm {
				Arm::Tunnel(call) => service.tunnel.serve(call, request).await,
				Arm::Health(status) => {
					let mut grpc = Grpc::new(TunnelCodec).max_decoding_message_size(HEALTH_CEILING);
					grpc.unary(HealthCall(status), request).await
				}
				Arm::Routed => service.served.route(&service.refusals, request).await,
				Arm::Refused(refusal) => {
					service.refusals.refused(&refusal);
					refusal.into()
				}
			};
			Ok(response)
		})
	}
}

/// The unary health check of one call.
struct HealthCall(HealthStatus);

impl UnaryService<Vec<u8>> for HealthCall {
	type Response = Vec<u8>;
	type Future = core::future::Ready<Result<Response<Vec<u8>>, Status>>;

	fn call(&mut self, request: Request<Vec<u8>>) -> Self::Future {
		let answer = self.0.answer(request.get_ref());
		core::future::ready(answer)
	}
}

/// The unary call that the coupler serves: steps 3 to 9 of its saga, once
/// tonic decodes the body.
#[cfg(feature = "couple")]
struct CoupledCall<P: HandshakeProvider + Send + Sync + 'static> {
	coupler: Arc<LiveCoupler<P>>,
	/// tonic calls the service once, but its trait takes `&mut self`, so the
	/// call moves out of an option.
	opened: Option<crate::couple::Opened>,
}

#[cfg(feature = "couple")]
impl<P: HandshakeProvider + Send + Sync + 'static> UnaryService<Vec<u8>> for CoupledCall<P> {
	type Response = Vec<u8>;
	type Future = BoxFuture<Result<Response<Vec<u8>>, Status>>;

	fn call(&mut self, request: Request<Vec<u8>>) -> Self::Future {
		let coupler = Arc::clone(&self.coupler);
		let opened = self.opened.take();

		Box::pin(async move {
			let opened = opened.ok_or_else(|| Status::internal("the coupler serves one call"))?;
			let served = coupler.serve(opened, request.into_inner()).await;
			served.map_err(|fault| fault.status())?.into_response()
		})
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

	/// The head of a call with `method`, on `path`, under `content_type`.
	fn head(method: Method, path: &str, content_type: &str) -> Result<Parts, http::Error> {
		let request = HttpRequest::builder().method(method).uri(path);
		let request = request.header(CONTENT_TYPE, content_type).body(())?;
		let (head, ()) = request.into_parts();
		Ok(head)
	}

	#[test]
	fn a_head_the_edge_cannot_carry_is_refused_before_it_claims_a_lane() -> Result<(), http::Error> {
		type Default = tightbeam::crypto::profiles::DefaultCryptoProvider;
		let served = Served::<Default>::Tunnel(PhantomData);
		let cases = [
			(head(Method::GET, TUNNEL_PATH, "application/grpc")?, Refusal::Method),
			(head(Method::POST, TUNNEL_PATH, "text/plain")?, Refusal::MediaType),
			(head(Method::POST, TUNNEL_PATH, "application/grpc")?, Refusal::Unconnected),
		];

		for (head, expected) in cases {
			let refused = match served.arm(&head) {
				Arm::Refused(refusal) => Some(refusal),
				_ => None,
			};
			assert_eq!(refused, Some(expected));
		}

		let other = head(Method::POST, "/other.v1.Service/Call", "application/grpc")?;
		assert!(matches!(served.arm(&other), Arm::Routed));
		Ok(())
	}

	#[test]
	fn a_tunnel_edge_answers_its_health_check() -> Result<(), http::Error> {
		type Default = tightbeam::crypto::profiles::DefaultCryptoProvider;
		let served = Served::<Default>::Tunnel(PhantomData);
		let check = head(Method::POST, HEALTH_CHECK_PATH, "application/grpc")?;
		assert!(matches!(served.arm(&check), Arm::Health(HealthStatus::Serving)));
		Ok(())
	}
}
