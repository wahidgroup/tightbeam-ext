//! The tonic service of a coupled call: unary, or a stream relayed both ways.

use core::pin::Pin;
use core::task::{ready, Context, Poll};
use std::sync::Arc;

use bytes::Bytes;
use http::{Request as HttpRequest, Response as HttpResponse};
use http_body::{Frame, SizeHint};
use tightbeam::transport::handshake::HandshakeProvider;
use tonic::body::Body;
use tonic::codec::{CompressionEncoding, Streaming};
use tonic::server::{Grpc, StreamingService, UnaryService};
use tonic::{Request, Response, Status};

use super::fault::CallFault;
use super::routes::StreamShape;
use super::saga::{CallEnding, LiveCoupler, Opened, OpenedCall, Unary};
use super::stream::RelayStream;
use crate::tunnel::{BoxFuture, TunnelCodec};

impl OpenedCall {
	/// Serve the call on `request` under the ceiling of the edge, in gzip when
	/// the caller sends or accepts it. The deadline of the call bounds a unary
	/// call and the opening of a stream. The ending of the call records its
	/// end, or the refusal of tonic that the response carries.
	pub(crate) async fn serve<P: HandshakeProvider + Send + Sync + 'static>(
		self,
		coupler: Arc<LiveCoupler<P>>,
		request: HttpRequest<Body>,
	) -> HttpResponse<Body> {
		let expires = self.expires().clone();
		let ending = coupler.ending(&self);
		let ceiling = coupler.ceiling();
		let gzip = CompressionEncoding::Gzip;
		let grpc = Grpc::new(TunnelCodec).max_decoding_message_size(ceiling);
		let grpc = grpc.max_encoding_message_size(ceiling);
		let mut grpc = grpc.accept_compressed(gzip).send_compressed(gzip);

		let response = match self {
			Self::Unary(opened) => {
				let request = request.map(|body| Body::new(UnaryBody { body, ending: ending.clone() }));
				let call = UnaryCall { coupler, opened: Some((opened, ending.clone())) };
				ending.within(&expires, grpc.unary(call, request)).await
			}
			Self::Stream(opened) => {
				let call = StreamCall { coupler, opened: Some((opened, ending.clone())) };
				ending.within(&expires, grpc.streaming(call, request)).await
			}
		};

		ending.settle(&response);
		response
	}
}

/// The request body of a unary call, which tonic decodes before the saga
/// runs. A body that fails, such as one that its caller resets, ends the
/// call with the fault of its status before tonic reads the failure.
struct UnaryBody {
	body: Body,
	ending: CallEnding,
}

impl http_body::Body for UnaryBody {
	type Data = Bytes;
	type Error = Status;

	fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
		let this = self.get_mut();
		let polled = ready!(Pin::new(&mut this.body).poll_frame(cx));
		if let Some(Err(status)) = &polled {
			this.ending.end(Err(CallFault::from(status.clone())));
		}

		Poll::Ready(polled)
	}

	fn is_end_stream(&self) -> bool {
		self.body.is_end_stream()
	}

	fn size_hint(&self) -> SizeHint {
		self.body.size_hint()
	}
}

/// The unary call that tonic serves once. Its trait takes `&mut self`, so
/// the call moves out of an option.
struct UnaryCall<P: HandshakeProvider + Send + Sync + 'static> {
	coupler: Arc<LiveCoupler<P>>,
	opened: Option<(Opened<Unary>, CallEnding)>,
}

/// The saga of a unary call, once tonic decodes its body.
impl<P: HandshakeProvider + Send + Sync + 'static> UnaryService<Vec<u8>> for UnaryCall<P> {
	type Response = Vec<u8>;
	type Future = BoxFuture<Result<Response<Vec<u8>>, Status>>;

	fn call(&mut self, request: Request<Vec<u8>>) -> Self::Future {
		let coupler = Arc::clone(&self.coupler);
		let opened = self.opened.take();

		Box::pin(async move {
			let (opened, ending) = opened.ok_or_else(|| Status::internal("tonic serves a unary call once"))?;
			let served = coupler.serve(opened, request.into_inner(), &ending).await;
			let answered = served.map_err(|fault| fault.status())?.into_result();
			answered.map(Response::new)
		})
	}
}

/// The streaming call that tonic serves once. Its trait takes `&mut self`,
/// so the call moves out of an option.
struct StreamCall<P: HandshakeProvider + Send + Sync + 'static> {
	coupler: Arc<LiveCoupler<P>>,
	opened: Option<(Opened<StreamShape>, CallEnding)>,
}

/// The saga of a streaming call up to its head, then the relay of its stream.
impl<P: HandshakeProvider + Send + Sync + 'static> StreamingService<Vec<u8>> for StreamCall<P> {
	type Response = Vec<u8>;
	type ResponseStream = RelayStream;
	type Future = BoxFuture<Result<Response<RelayStream>, Status>>;

	fn call(&mut self, request: Request<Streaming<Vec<u8>>>) -> Self::Future {
		let coupler = Arc::clone(&self.coupler);
		let opened = self.opened.take();

		Box::pin(async move {
			let (opened, ending) = opened.ok_or_else(|| Status::internal("tonic serves a streaming call once"))?;
			let relay = coupler.open_stream(opened, request.into_inner(), ending).await;
			let relay = relay.map_err(|fault| fault.status())?;
			Ok(Response::new(relay.spawn()))
		})
	}
}
