//! The echo bodies and commands of the multiplexed echo servers, as
//! `docs/ws.md` (Demo servers) states it.

use core::error::Error;
use core::fmt;
use core::future::{pending, Future};
use core::str::{from_utf8, FromStr};
use std::sync::Arc;

use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::crypto::profiles::TightbeamProfile;
use tightbeam::der::{Any, Decode, Encode, EncodeValue, Length, Reader, Tag, Tagged, Writer};
use tightbeam::policy::TransitStatus;
use tightbeam::transport::envelopes::GoAwayReason;
use tightbeam::transport::error::TransportError;
use tightbeam::transport::multiplex::{
	CallContext, MuxDispatch, MuxHandle, MuxService, ReplySink, StreamBody, StreamRoute,
};
use tightbeam::transport::{ResponsePackage, TransportResult};
use tightbeam::urn::Urn;
use tightbeam::{Frame, Message, TightBeamError};

use super::echo::EchoService;
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
	/// - The [`UnknownBody`] of a `name` that is not `streaming`, `duplex`, or `unary`.
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
	/// - [`EnvError::Unparsed`] -- the variable holds a value that names no
	///   body, which [`UnknownBody`] describes.
	pub fn from_env() -> Result<Self, EnvError> {
		ECHO_BODY.parsed_or(Self::Streaming)
	}

	/// Serve every stream of `served` with this handler, behind the gate of
	/// its transport, until the connection ends.
	///
	/// - In the [`Streaming`](Self::Streaming) and [`Unary`](Self::Unary)
	///   bodies, a frame id can select a command in place of the echo, and the
	///   handle of `served` runs those commands.
	/// - The [`Duplex`](Self::Duplex) body runs the duplex echo of
	///   [`EchoService`].
	/// - A stream of a kind the body does not serve answers `Unimplemented`.
	///
	/// # Errors
	///
	/// - The [`TransportError`] of the failure that ends the responder.
	pub async fn serve(self, served: ServedMux) -> TransportResult<()> {
		let link = EchoLink(served.handle().clone());
		match self {
			Self::Streaming => served.serve_dispatch(StreamingEcho(link), pending()).await,
			Self::Unary => served.serve_dispatch(UnaryEcho(link), pending()).await,
			Self::Duplex => served.serve(DuplexEcho, pending()).await,
		}
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

/// A command that a frame id selects in place of the echo, parsed once from
/// the id.
///
/// - Each command is a prefix of the id, so a client can tag the rest of the id.
/// - A prefix that extends another one is read first, so `call-me-stream:`
///   and `call-me-duplex` win over `call-me`.
#[derive(Clone, Debug, Eq, PartialEq)]
enum EchoCommand {
	/// `call-me-stream:<urn>` opens a progressive body to the client, routed
	/// to the URN that follows the prefix, and relays the client's reply.
	CallMeStream(Urn<'static>),
	/// `call-me-stream:` followed by no URN answers `InvalidArgument`.
	InvalidTarget,
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

impl From<&[u8]> for EchoCommand {
	fn from(id: &[u8]) -> Self {
		if let Some(target) = id.strip_prefix(b"call-me-stream:") {
			let parsed = from_utf8(target).ok().and_then(|target| Urn::from_str(target).ok());
			return parsed.map_or(Self::InvalidTarget, Self::CallMeStream);
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

impl EchoCommand {
	/// Run this command for `frame` over the connection that `handle` drives.
	async fn run(self, handle: MuxHandle, frame: &Frame) -> ResponsePackage {
		let link = EchoLink(handle);
		match self {
			Self::CallMeStream(target) => link.call_me_stream(frame, target).await,
			Self::InvalidTarget => ResponsePackage::new(TransitStatus::InvalidArgument, None),
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

/// The unary streams of the [`Unary`](EchoBody::Unary) body: each echoes its
/// frame, or runs the [`EchoCommand`] its id selects. Every other kind answers
/// through the defaults of [`MuxDispatch`].
struct UnaryEcho(EchoLink);

impl MuxDispatch for UnaryEcho {
	async fn unary(&self, frame: Arc<Frame>) -> TransportResult<ResponsePackage> {
		let link = self.0.clone();
		let echoed = link.echo(frame).await;
		Ok(echoed)
	}
}

/// The unary and streaming streams of the [`Streaming`](EchoBody::Streaming)
/// body, so a demo echo covers frame RPC and streamed bodies on one
/// connection. A unary stream answers as on the [`Unary`](EchoBody::Unary)
/// body.
struct StreamingEcho(EchoLink);

impl MuxDispatch for StreamingEcho {
	async fn unary(&self, frame: Arc<Frame>) -> TransportResult<ResponsePackage> {
		let link = self.0.clone();
		let echoed = link.echo(frame).await;
		Ok(echoed)
	}

	async fn streaming(&self, body: StreamBody, route: StreamRoute) -> TransportResult<ResponsePackage> {
		let link = self.0.clone();
		let echoed = link.echo_streaming(body, route).await;
		Ok(echoed)
	}
}

/// The duplex streams of the [`Duplex`](EchoBody::Duplex) body, which run the
/// duplex echo of [`EchoService`]. Every other kind answers through the
/// defaults of [`MuxService`].
struct DuplexEcho;

impl MuxService for DuplexEcho {
	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		cx: CallContext,
	) -> impl Future<Output = Result<(), TightBeamError>> + Send {
		EchoService.duplex(body, reply, cx)
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

	/// The echo of a progressive body, under the id that [`RouteStamp`] gives
	/// its route.
	///
	/// - A body that fails to drain answers [`TransitStatus::Cancelled`].
	/// - A body that holds no DER frame answers [`TransitStatus::InvalidArgument`].
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
				ResponsePackage::new(Self::relayed(&error), None)
			}
		}
	}

	/// Open a progressive body to the peer with `target` stamped on the Open,
	/// push the request frame DER as the body, and relay the peer's Frame
	/// reply.
	async fn call_me_stream(&self, frame: &Frame, target: Urn<'static>) -> ResponsePackage {
		let Ok(der) = frame.to_der() else {
			return ResponsePackage::new(TransitStatus::Internal, None);
		};

		let opened = self.0.open_stream_to(target);
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
				ResponsePackage::new(Self::relayed(&error), None)
			}
		}
	}

	/// Open a duplex stream to the peer with the request frame DER as its
	/// body, and answer the status that the duplex handler of the peer settled
	/// with.
	///
	/// - A handler may settle before it reads the body, so a push that meets
	///   the ended stream still reads the trailer.
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
				Err(error) => return ResponsePackage::new(Self::relayed(&error), None),
			}
		}
	}

	/// The status that `error`, a call-back failure, relays to the requester:
	/// the status of a peer refusal, or [`TransitStatus::Internal`] for a
	/// failure of the server.
	fn relayed(error: &TransportError) -> TransitStatus {
		error.transit_status().unwrap_or(TransitStatus::Internal)
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
	/// A frame keeps its fields private, so the echo builds a copy under the
	/// new id. The copy carries the version, order, and body the client sent,
	/// which is all a progressive echo asserts.
	fn restamp(&self, frame: &Frame) -> Result<Frame, TightBeamError> {
		let body = RawBody(Any::from_der(frame.message())?);
		let builder = FrameBuilder::<RawBody>::from(frame.version())
			.with_id(self.id())
			.with_order(frame.metadata().order());

		builder.with_message(body).build()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn an_unknown_echo_body_is_refused() {
		let parsed = "echo".parse::<EchoBody>();
		assert_eq!(parsed, Err(UnknownBody("echo".to_owned())));
	}

	#[test]
	fn a_call_back_stream_id_routes_to_its_urn() -> Result<(), tightbeam::urn::UrnValidationError> {
		let command = EchoCommand::from(b"call-me-stream:urn:tb:echo".as_slice());
		let target: Urn<'static> = "urn:tb:echo".parse()?;
		assert_eq!(command, EchoCommand::CallMeStream(target));

		let unrouted = EchoCommand::from(b"call-me-stream:no urn".as_slice());
		assert_eq!(unrouted, EchoCommand::InvalidTarget);
		Ok(())
	}

	#[test]
	fn a_duplex_call_back_id_wins_over_call_me() {
		let command = EchoCommand::from(b"call-me-duplex".as_slice());
		assert_eq!(command, EchoCommand::CallMeDuplex);
	}

	#[test]
	fn a_call_back_target_that_is_not_utf8_is_invalid() {
		let command = EchoCommand::from(b"call-me-stream:\xff".as_slice());
		assert_eq!(command, EchoCommand::InvalidTarget);
	}
}
