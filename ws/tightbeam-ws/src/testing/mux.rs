//! Shared behavior for the multiplexed echo server examples.
//!
//! Compiled only under the `testing` feature.
//!
//! Progressive-body echoes stamp the Open route onto the response frame
//! id as `routed:<target>:<hops>` (empty target when unrouted) so Node
//! e2e can assert `openStream` / `openStreamTo` without a colony.

use core::error::Error;
use core::fmt;
use core::future::{pending, Future};
use core::str::{from_utf8, FromStr};
use std::sync::Arc;

use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::crypto::profiles::TightbeamProfile;
use tightbeam::der::{Any, Decode, Encode, EncodeValue, Length, Reader, Tag, Tagged, Writer};
use tightbeam::marker::MaybeSend;
use tightbeam::policy::TransitStatus;
use tightbeam::transport::envelopes::GoAwayReason;
use tightbeam::transport::error::TransportError;
use tightbeam::transport::multiplex::{MuxDispatch, MuxHandle, ReplySink, StreamBody, StreamRoute};
use tightbeam::transport::{ResponsePackage, TransportResult};
use tightbeam::urn::Urn;
use tightbeam::{Frame, Message, TightBeamError};

use super::env::{EnvError, EnvVar};
use crate::serve::ServedMux;

/// The variable that names the [`EchoBody`] of an echo server.
const ECHO_BODY: EnvVar = EnvVar::new("TBWS_ECHO_BODY");

/// The handler an echo server runs on every stream, as `TBWS_ECHO_BODY` names
/// it.
///
/// # Examples
///
/// ```
/// use tightbeam_ws::testing::EchoBody;
///
/// assert_eq!("duplex".parse(), Ok(EchoBody::Duplex));
/// assert!("anything else".parse::<EchoBody>().is_err());
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EchoBody {
	/// Unary frame echo plus progressive-body echo for `openStream`, which
	/// `streaming` names. This is the body when the variable is unset.
	Streaming,
	/// Chunk echo for `openDuplex`, which `duplex` names.
	Duplex,
	/// Reassembled frame echo alone, which `unary` names.
	Unary,
}

impl FromStr for EchoBody {
	type Err = UnknownBody;

	/// The body that `name` names.
	///
	/// # Errors
	///
	/// - [`UnknownBody`]: `name` is not `streaming`, `duplex`, or `unary`.
	fn from_str(name: &str) -> Result<Self, Self::Err> {
		match name {
			"streaming" => Ok(Self::Streaming),
			"duplex" => Ok(Self::Duplex),
			"unary" => Ok(Self::Unary),
			_ => Err(UnknownBody(name.to_owned())),
		}
	}
}

impl EchoBody {
	/// The body that `TBWS_ECHO_BODY` names, or [`EchoBody::Streaming`] when
	/// it is unset.
	///
	/// # Errors
	///
	/// - [`EnvError::Unparsed`]: the variable holds a value that names no
	///   body, which [`UnknownBody`] describes.
	pub fn from_env() -> Result<Self, EnvError> {
		ECHO_BODY.parsed_or(Self::Streaming)
	}

	/// Serve every stream of `served` with this handler, behind the gate of
	/// its transport, until the connection ends.
	///
	/// In the [`Streaming`](Self::Streaming) and [`Unary`](Self::Unary)
	/// bodies, a frame id can select an [`EchoCommand`] in place of the echo,
	/// and the handle of `served` runs those commands. A stream of a kind the
	/// body does not serve answers `Unimplemented`.
	///
	/// # Errors
	///
	/// Returns the [`TransportError`] that ends the responder.
	pub async fn serve(self, served: ServedMux) -> TransportResult<()> {
		let link = EchoLink(served.handle().clone());
		let dispatch = EchoDispatch { body: self, link };
		served.serve(dispatch, pending()).await
	}
}

/// A name that names no [`EchoBody`].
///
/// # Examples
///
/// ```
/// use tightbeam_ws::testing::{EchoBody, UnknownBody};
///
/// let refused: Result<EchoBody, UnknownBody> = "echo".parse();
/// assert!(refused.is_err());
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownBody(String);

impl fmt::Display for UnknownBody {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{:?} names no echo body", self.0)
	}
}

impl Error for UnknownBody {}

/// A command that a frame id selects in place of the echo.
///
/// Each command is a prefix of the id, so a client can tag the rest of the id.
/// A prefix that extends another prefix is read first, so `call-me-stream:`
/// and `call-me-duplex` win over `call-me`.
///
/// # Examples
///
/// ```
/// use tightbeam_ws::testing::EchoCommand;
///
/// let command = EchoCommand::from(b"call-me-stream:urn:demo".as_slice());
/// assert_eq!(command, EchoCommand::CallMeStream(b"urn:demo"));
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EchoCommand<'a> {
	/// `call-me-stream:<urn>` opens a progressive body to the client, routed
	/// to the URN that follows the prefix, and relays the client's reply.
	CallMeStream(&'a [u8]),
	/// `call-me-duplex` opens a duplex stream to the client, pushes the frame
	/// DER as its body, and answers with the status the client's duplex
	/// handler settled with.
	CallMeDuplex,
	/// `call-me` answers the stream with the client's own reply to the frame.
	CallMe,
	/// `drain-calm` drains the session with a
	/// [`GoAwayReason::EnhanceYourCalm`] GoAway, so a client can surface the
	/// reason.
	DrainCalm,
	/// `sink` accepts the frame without a response frame, so a client can
	/// exercise its empty-response path.
	Sink,
	/// Any other id echoes the frame.
	Echo,
}

impl<'a> From<&'a [u8]> for EchoCommand<'a> {
	fn from(id: &'a [u8]) -> Self {
		if let Some(target) = id.strip_prefix(b"call-me-stream:") {
			return Self::CallMeStream(target);
		}
		if id.starts_with(b"call-me-duplex") {
			return Self::CallMeDuplex;
		}
		if id.starts_with(b"call-me") {
			return Self::CallMe;
		}
		if id.starts_with(b"drain-calm") {
			return Self::DrainCalm;
		}
		if id.starts_with(b"sink") {
			return Self::Sink;
		}

		Self::Echo
	}
}

impl EchoCommand<'_> {
	/// Run this command for `frame` over the connection that `handle` drives.
	pub async fn run(self, handle: MuxHandle, frame: &Frame) -> ResponsePackage {
		let link = EchoLink(handle);
		match self {
			Self::CallMeStream(target) => link.call_me_stream(frame, target).await,
			Self::CallMeDuplex => link.call_me_duplex(frame).await,
			Self::CallMe => link.call_me(frame).await,
			Self::DrainCalm => link.drain().await,
			Self::Sink => ResponsePackage::new(TransitStatus::Ok, None),
			Self::Echo => ResponsePackage::new(TransitStatus::Ok, Some(frame.clone())),
		}
	}
}

/// A frame body held as the DER it arrived as, so a rebuilt frame carries the
/// same octets under any message schema.
#[derive(Clone, Debug, PartialEq)]
struct RawBody(Any);

impl Tagged for RawBody {
	fn tag(&self) -> Tag {
		self.0.tag()
	}
}

impl EncodeValue for RawBody {
	fn value_len(&self) -> tightbeam::der::Result<Length> {
		self.0.value_len()
	}

	fn encode_value(&self, writer: &mut impl Writer) -> tightbeam::der::Result<()> {
		self.0.encode_value(writer)
	}
}

impl<'a> Decode<'a> for RawBody {
	fn decode<R: Reader<'a>>(reader: &mut R) -> tightbeam::der::Result<Self> {
		Any::decode(reader).map(Self)
	}
}

impl Message for RawBody {
	type Profile = TightbeamProfile;
}

/// The streams of one echo connection, served by the kinds its body names.
///
/// The [`Streaming`](EchoBody::Streaming) body serves unary and streaming
/// streams, so a demo echo covers frame RPC and streamed bodies on one
/// connection. The [`Unary`](EchoBody::Unary) body serves unary streams, and
/// the [`Duplex`](EchoBody::Duplex) body serves duplex streams. Every other
/// kind answers [`TransportError::NotServed`], which the responder answers
/// `Unimplemented`.
struct EchoDispatch {
	body: EchoBody,
	link: EchoLink,
}

impl MuxDispatch for EchoDispatch {
	fn unary(&self, frame: Arc<Frame>) -> impl Future<Output = TransportResult<ResponsePackage>> + MaybeSend {
		let body = self.body;
		let link = self.link.clone();
		async move {
			match body {
				EchoBody::Streaming | EchoBody::Unary => {
					let echoed = link.echo(frame).await;
					Ok(echoed)
				}
				EchoBody::Duplex => Err(TransportError::NotServed),
			}
		}
	}

	fn streaming(
		&self,
		body: StreamBody,
		route: StreamRoute,
	) -> impl Future<Output = TransportResult<ResponsePackage>> + MaybeSend {
		let served = self.body;
		let link = self.link.clone();
		async move {
			match served {
				EchoBody::Streaming => {
					let echoed = link.echo_streaming(body, route).await;
					Ok(echoed)
				}
				EchoBody::Duplex | EchoBody::Unary => Err(TransportError::NotServed),
			}
		}
	}

	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		_route: StreamRoute,
	) -> impl Future<Output = TransportResult<TransitStatus>> + MaybeSend {
		let served = self.body;
		async move {
			match served {
				EchoBody::Duplex => {
					let echo = ChunkEcho { body, reply };
					let status = echo.run().await;
					Ok(status)
				}
				EchoBody::Streaming | EchoBody::Unary => Err(TransportError::NotServed),
			}
		}
	}
}

/// The connection an echo server serves, and the commands it runs on it.
#[derive(Clone)]
struct EchoLink(MuxHandle);

impl EchoLink {
	/// Echo `frame`, or run the [`EchoCommand`] its id selects.
	async fn echo(self, frame: Arc<Frame>) -> ResponsePackage {
		let command = EchoCommand::from(frame.metadata().id());
		command.run(self.0, &frame).await
	}

	/// Progressive-body echo: reassemble via [`StreamBody::into_frame`],
	/// stamp the Open route onto the frame id ([`RouteStamp`]), then
	/// [`echo`](Self::echo).
	///
	/// Transport drain failures answer [`TransitStatus::Cancelled`]. Invalid
	/// DER answers [`TransitStatus::InvalidArgument`].
	async fn echo_streaming(self, body: StreamBody, route: StreamRoute) -> ResponsePackage {
		let stamp = RouteStamp(&route);
		match body.into_frame().await {
			Ok(frame) => match stamp.restamp(&frame) {
				Ok(stamped) => self.echo(Arc::new(stamped)).await,
				Err(_) => ResponsePackage::new(TransitStatus::InvalidArgument, None),
			},
			Err(TransportError::DerError(_)) => ResponsePackage::new(TransitStatus::InvalidArgument, None),
			Err(_) => ResponsePackage::new(TransitStatus::Cancelled, None),
		}
	}

	/// Answer the stream with the client's own reply to `frame`.
	async fn call_me(&self, frame: &Frame) -> ResponsePackage {
		match self.0.emit_on_stream(frame).await {
			Ok(answer) => ResponsePackage::new(TransitStatus::Ok, answer),
			Err(error) => {
				eprintln!("[echo-mux] call-back stream failed: {error}");
				ResponsePackage::new(Self::relayed_status(&error), None)
			}
		}
	}

	/// Open a progressive body to the peer with `target` stamped on the Open,
	/// push the request frame DER as the body, and relay the peer's Frame
	/// reply.
	async fn call_me_stream(&self, frame: &Frame, target: &[u8]) -> ResponsePackage {
		let Ok(target) = from_utf8(target) else {
			return ResponsePackage::new(TransitStatus::InvalidArgument, None);
		};
		let Ok(urn) = Urn::from_str(target) else {
			return ResponsePackage::new(TransitStatus::InvalidArgument, None);
		};
		let Ok(der) = frame.to_der() else {
			return ResponsePackage::new(TransitStatus::Internal, None);
		};

		let opened = self.0.open_stream_to(urn);
		let Ok((sink, response)) = opened else {
			return ResponsePackage::new(TransitStatus::Internal, None);
		};

		if sink.close_with(der).await.is_err() {
			return ResponsePackage::new(TransitStatus::Cancelled, None);
		}

		match response.await {
			Ok(answer) => ResponsePackage::new(TransitStatus::Ok, answer),
			Err(error) => {
				eprintln!("[echo-mux] routed call-back stream failed: {error}");
				ResponsePackage::new(Self::relayed_status(&error), None)
			}
		}
	}

	/// Open a duplex stream to the peer, push the request frame DER as its
	/// body, read the peer's reply to its trailer, and answer with the status
	/// the peer's duplex handler settled with.
	///
	/// A handler may settle before it reads the body, so a push or a close
	/// that meets the ended stream still leaves the trailer to answer.
	async fn call_me_duplex(&self, frame: &Frame) -> ResponsePackage {
		let Ok(der) = frame.to_der() else {
			return ResponsePackage::new(TransitStatus::Internal, None);
		};
		let Ok((mut sink, mut reply)) = self.0.open_duplex() else {
			return ResponsePackage::new(TransitStatus::Internal, None);
		};

		let _ = sink.push(&der).await;
		let _ = sink.close().await;

		loop {
			match reply.chunk().await {
				Ok(Some(_)) => {}
				Ok(None) => return ResponsePackage::new(TransitStatus::Ok, None),
				Err(error) => return ResponsePackage::new(Self::relayed_status(&error), None),
			}
		}
	}

	/// The status that `error`, a call-back failure, relays to the requester.
	///
	/// A peer refusal keeps its status, so the requester observes the exact
	/// code the call-back handler answered with. A transport fault or a local
	/// failure is the server's own trouble and answers
	/// [`TransitStatus::Internal`].
	fn relayed_status(error: &TransportError) -> TransitStatus {
		let TransportError::OperationFailed(failure) = error else {
			return TransitStatus::Internal;
		};

		TransitStatus::try_from(*failure).unwrap_or(TransitStatus::Internal)
	}

	/// Drain the session with a [`GoAwayReason::EnhanceYourCalm`] GoAway.
	///
	/// The GoAway and the writer stop are queued ahead of this stream's
	/// response, so the requester observes the drain rather than an echo.
	async fn drain(&self) -> ResponsePackage {
		if let Err(error) = self.0.shutdown_with(GoAwayReason::EnhanceYourCalm).await {
			eprintln!("[echo-mux] drain failed: {error}");
		}

		ResponsePackage::new(TransitStatus::Ok, None)
	}
}

/// The Open route of a progressive body, stamped onto the frame id as
/// `routed:<target>:<hops>` (an empty target when unrouted) for e2e
/// assertions.
struct RouteStamp<'a>(&'a StreamRoute);

impl RouteStamp<'_> {
	/// The frame id that carries the route.
	fn id(&self) -> Vec<u8> {
		let hops = self.0.hops_remaining();
		match self.0.target() {
			Some(target) => format!("routed:{target}:{hops}").into_bytes(),
			None => format!("routed::{hops}").into_bytes(),
		}
	}

	/// `frame` rebuilt under the id of the route.
	///
	/// A frame keeps its fields private, so the id cannot change in place.
	/// The echo carries the version, order, and body the client sent, which
	/// is all a progressive echo asserts.
	fn restamp(&self, frame: &Frame) -> Result<Frame, TightBeamError> {
		let body = RawBody(Any::from_der(frame.message())?);
		let builder = FrameBuilder::<RawBody>::from(frame.version())
			.with_id(self.id())
			.with_order(frame.metadata().order());

		builder.with_message(body).build()
	}
}

/// One duplex stream an echo pushes every chunk of straight back.
struct ChunkEcho {
	body: StreamBody,
	reply: ReplySink,
}

impl ChunkEcho {
	/// Echo every chunk until the body ends.
	async fn run(mut self) -> TransitStatus {
		loop {
			match self.body.chunk().await {
				Ok(Some(chunk)) => {
					if self.reply.push(&chunk).await.is_err() {
						return TransitStatus::Cancelled;
					}
				}
				Ok(None) => return TransitStatus::Ok,
				Err(_) => return TransitStatus::Cancelled,
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use tightbeam::transport::error::TransportFailure;

	#[test]
	fn relayed_status_keeps_peer_refusal_code() {
		let error = TransportError::OperationFailed(TransportFailure::Unavailable);
		assert_eq!(EchoLink::relayed_status(&error), TransitStatus::Unavailable);
	}

	#[test]
	fn an_unknown_echo_body_is_refused() {
		let parsed = "echo".parse::<EchoBody>();
		assert_eq!(parsed, Err(UnknownBody("echo".to_owned())));
	}

	#[test]
	fn a_duplex_call_back_id_wins_over_call_me() {
		let command = EchoCommand::from(b"call-me-duplex".as_slice());
		assert_eq!(command, EchoCommand::CallMeDuplex);
	}

	#[test]
	fn relayed_status_maps_non_operation_to_internal() {
		let error = TransportError::ConnectionClosed;
		assert_eq!(EchoLink::relayed_status(&error), TransitStatus::Internal);
	}
}
