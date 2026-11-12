//! The multiplexed browser client that the bindings expose, as the browser
//! transport section of `docs/ws-wasm.md` describes.

use core::future::Future;
use core::mem;
use std::rc::Rc;

use futures_util::future::{abortable, AbortHandle};
use js_sys::{Function, Promise, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{future_to_promise, spawn_local};

use tightbeam::colony::work::{ClusterWorkRequest, ClusterWorkResponse};
use tightbeam::der::Decode;
use tightbeam::transport::handshake::HandshakeProvider;
use tightbeam::transport::multiplex::{
	MultiplexedProtocol, MuxDispatch, MuxHandle, MuxResponder, MuxRole, MuxTransport,
};
use tightbeam::transport::{EnvelopeSink, EnvelopeSource, TransportResult};
use tightbeam::{Frame, TightBeamError};

use crate::dial::{Dial, Dialed};
use crate::fault::{JsFault, RefusalCode};
use crate::goaway::GoAwayLabel;
use crate::promise::{AbortRace, Callback, JsBytes, JsResponse, Signal, StartNow, Text};
use crate::protocol::Session;
use crate::socket::SocketMonitor;
use crate::streaming::{MuxDuplexStream, MuxRequestStream, ServeHandler, StreamTarget};

/// Peer-serve dispatch shape claimed by the first `serve*` call.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ServeMode {
	Unary,
	Streaming,
	Duplex,
}

impl ServeMode {
	/// The stable name of this mode in error messages.
	fn label(self) -> &'static str {
		match self {
			Self::Unary => "unary",
			Self::Streaming => "streaming",
			Self::Duplex => "duplex",
		}
	}

	/// Start the serve loop of this mode over `responder` on `connection`. Each
	/// stream the loop dispatches reads the function that `handler` holds at
	/// that moment.
	fn start(self, responder: MuxResponder, handler: ServeHandler, connection: Rc<Connection>) {
		match self {
			Self::Unary => Self::run(responder, handler.unary(), connection),
			Self::Streaming => Self::run(responder, handler.streaming(), connection),
			Self::Duplex => Self::run(responder, handler.duplex(), connection),
		}
	}

	/// Run the serve loop of `responder` over `dispatch` on the browser
	/// executor.
	///
	/// - The loop holds `connection` as a WebSocket with listeners holds its socket.
	/// - A serving client therefore stays open after the application frees or drops it, until `close()`, the
	///   peer's close, or a GoAway ends the connection.
	/// - The loop then ends once the streams in flight settle.
	fn run(responder: MuxResponder, dispatch: impl MuxDispatch + 'static, connection: Rc<Connection>) {
		spawn_local(async move {
			// The terminal status of the loop already reached the peer
			// (GoAway), so nothing is left to report.
			let _ = responder.serve_with(dispatch).await;
			drop(connection);
		});
	}

	/// Admit a later claim in `requested` on the loop that this mode started.
	///
	/// # Errors
	///
	/// - `ServeModeConflict` -- `requested` is another mode.
	fn admits(self, requested: Self) -> Result<(), JsFault> {
		if self == requested {
			return Ok(());
		}

		let current = self.label();
		let requested = requested.label();
		let message = format!("peer serve mode is {current}. Cannot switch to {requested} after the responder started");
		Err(RefusalCode::ServeModeConflict.because(message))
	}
}

/// How a `serve*` call claims the stream dispatch: `shared`, the default,
/// lets a later call in the same mode swap the handler, and `exclusive`
/// refuses every later call.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServeClaim {
	/// A later claim in the same mode swaps the handler.
	Shared = "shared",
	/// Every later claim refuses, because one owner dispatches the streams
	/// and composes the routes of the application under itself.
	Exclusive = "exclusive",
}

impl ServeClaim {
	/// The claim as JavaScript passes it: a label, or `undefined` for
	/// `shared`. The glue hands any other value over as the hidden invalid
	/// variant.
	///
	/// # Errors
	///
	/// - `InvalidServeClaim` -- the value is neither `undefined` nor a label of `ServeClaim`.
	fn admit(claim: Option<Self>) -> Result<Claim, JsFault> {
		match claim {
			None | Some(Self::Shared) => Ok(Claim::Shared),
			Some(Self::Exclusive) => Ok(Claim::Exclusive),
			Some(Self::__Invalid) => {
				Err(RefusalCode::InvalidServeClaim.because("a serve claim is \"shared\" or \"exclusive\""))
			}
		}
	}
}

/// How a started serve loop holds the stream dispatch, as
/// [`ServeClaim::admit`] reads it.
#[derive(Clone, Copy)]
enum Claim {
	/// A later claim in the same mode swaps the handler.
	Shared,
	/// Every later claim refuses.
	Exclusive,
}

impl Claim {
	/// Admit a `later` claim on the loop that this claim started.
	///
	/// # Errors
	///
	/// - `ServeDispatchClaimed` -- this claim is exclusive and owns the dispatch.
	/// - `ServeDispatchShared` -- a `later` exclusive claim meets this shared claim.
	fn admits(self, later: Self) -> Result<(), JsFault> {
		match (self, later) {
			(Self::Exclusive, _) => {
				let message = "stream dispatch is exclusively claimed on this client (a SubscriptionManager?). Route \
				               application streams through the claimant instead of calling serve again";
				Err(RefusalCode::ServeDispatchClaimed.because(message))
			}
			(Self::Shared, Self::Exclusive) => {
				let message = "a shared handler already serves this client, so an exclusive claim would replace it";
				Err(RefusalCode::ServeDispatchShared.because(message))
			}
			(Self::Shared, Self::Shared) => Ok(()),
		}
	}
}

/// The peer-serve state of a client.
enum Serving {
	/// No `serve*` call has run, so the responder waits for the first one.
	Idle(MuxResponder),
	/// The first `serve*` call claimed `mode` under `claim` and started its
	/// loop, which reads the function in `handler` for each stream it
	/// dispatches.
	Started { mode: ServeMode, handler: ServeHandler, claim: Claim },
}

impl Serving {
	/// Serve peer streams of `connection` in `mode` with `handler` under
	/// `claim`.
	///
	/// - The first claim starts the serve loop of `mode`.
	/// - A later shared claim in the same mode swaps the handler of a shared loop for the streams
	///   dispatched after it.
	///
	/// # Errors
	///
	/// - The errors of [`Claim::admits`] and [`ServeMode::admits`].
	fn claim(
		&mut self,
		mode: ServeMode,
		handler: Function,
		claim: Claim,
		connection: &Rc<Connection>,
	) -> Result<(), JsFault> {
		let slot = match self {
			Self::Started { mode: current, handler: slot, claim: held } => {
				held.admits(claim)?;
				current.admits(mode)?;
				slot.replace(handler);
				return Ok(());
			}
			Self::Idle(_) => ServeHandler::new(handler),
		};

		let started = Self::Started { mode, handler: slot.clone(), claim };
		if let Self::Idle(responder) = mem::replace(self, started) {
			mode.start(responder, slot, Rc::clone(connection));
		}

		Ok(())
	}
}

/// A transport that splits into a multiplexed session on the browser
/// executor.
///
/// - The split spawns the reader and writer pumps and the keepalive, and hands them back as a [`MuxTasks`]
///   set that ends them when it drops.
/// - Pump failures reach callers as `ConnectionClosed` on their pending streams.
pub trait BrowserMux {
	/// Split into a stream handle, a responder, and the tasks that drive them.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidState`](tightbeam::transport::TransportError::InvalidState) --
	///   the peer did not negotiate multiplexing.
	/// - The [`TransportError`](tightbeam::transport::TransportError) of a transport that fails
	///   to split into its halves.
	fn split(self) -> TransportResult<SessionParts>;
}

/// The split parts of one session.
pub struct SessionParts {
	/// The handle that opens and emits streams.
	pub handle: MuxHandle,
	/// The responder that serves the streams the peer opens.
	pub responder: MuxResponder,
	/// The tasks that drive the handle and the responder.
	pub tasks: MuxTasks,
}

impl<R, W> BrowserMux for MuxTransport<R, W>
where
	R: EnvelopeSource + 'static,
	W: EnvelopeSink + 'static,
{
	fn split(self) -> TransportResult<SessionParts> {
		let (handle, reader_driver, writer_driver, responder) = self.into_parts();

		// The drivers have nowhere to report, because each failure reaches
		// the callers whose streams it ends.
		let reader = MuxTasks::spawn(async move {
			let _ = reader_driver.drive().await;
		});
		let writer = MuxTasks::spawn(async move {
			let _ = writer_driver.drive().await;
		});

		// An idle session outlives the read deadline of a native peer. The
		// keepalive ends with the first failed ping, and the connection's own
		// failure reaches callers on their pending streams.
		let pings = handle.clone().keep_alive();
		let keepalive = MuxTasks::spawn(async move {
			let _ = pings.await;
		});

		let tasks = MuxTasks { reader, writer, keepalive };
		Ok(SessionParts { handle, responder, tasks })
	}
}

impl<P: HandshakeProvider> BrowserMux for Session<P> {
	/// Split a handshaken session. The handshake decides whether the peer
	/// negotiated multiplexing, and the split admits only a session whose peer
	/// negotiated it.
	fn split(self) -> TransportResult<SessionParts> {
		self.into_transport().into_mux(MuxRole::Client)?.split()
	}
}

/// The tasks that drive one split session: the reader and writer pumps and
/// the keepalive.
///
/// The tasks run on the browser executor until the set drops, or until the
/// connection ends on its own.
#[must_use = "dropping the set ends the tasks that carry the session"]
pub struct MuxTasks {
	reader: AbortHandle,
	writer: AbortHandle,
	keepalive: AbortHandle,
}

impl MuxTasks {
	/// Spawn `task` on the browser executor, and return the handle that ends
	/// it.
	fn spawn(task: impl Future<Output = ()> + 'static) -> AbortHandle {
		let (task, handle) = abortable(task);
		spawn_local(async move {
			// An ended task has nothing to report.
			let _ = task.await;
		});

		handle
	}
}

/// Dropping the set ends each task at its next poll, which drops the drivers
/// and fails every stream still pending on the session.
impl Drop for MuxTasks {
	fn drop(&mut self) {
		self.reader.abort();
		self.writer.abort();
		self.keepalive.abort();
	}
}

/// One live connection of a client: its stream handle, its socket, and the
/// tasks that drive them.
///
/// - The client, each stream it opens, each call in flight, and a started serve loop hold the connection.
/// - The socket closes and the tasks end when the last holder drops, so a freed client leaves the socket to
///   the work that still uses it.
pub(crate) struct Connection {
	handle: MuxHandle,
	monitor: SocketMonitor,
	/// Usable outbound credits for this epoch, as the handshake negotiated
	/// them, or `None` when unmetered. tightbeam resets a renewal to the
	/// initial grant, so the figure holds for every epoch.
	usable_send_budget: Option<u64>,
	/// Ends the pumps and the keepalive as the connection drops.
	_tasks: MuxTasks,
}

impl Connection {
	/// The stream handle, for a stream that opens on this connection and
	/// holds it.
	pub(crate) fn handle(&self) -> &MuxHandle {
		&self.handle
	}

	/// Emit `frame_der` on a fresh stream and encode the optional response
	/// for JavaScript.
	async fn emit(&self, frame_der: Vec<u8>) -> Result<JsValue, JsFault> {
		let frame = Frame::from_der(&frame_der)?;
		let response = self.handle.emit_on_stream(&frame).await?;

		JsValue::try_from(JsResponse(response))
	}

	/// Submit `work_frame_der` to `target` through the gateway on a fresh
	/// stream and resolve with the servlet frame's DER.
	///
	/// - The carrier nests the caller's DER and reads its id in place.
	/// - The reply hands back the servlet's DER as it arrived.
	/// - The end-to-end frame crosses the boundary untouched in both directions, and the servlet parses it.
	async fn submit_work(&self, target: StreamTarget, work_frame_der: Vec<u8>) -> Result<JsValue, JsFault> {
		let StreamTarget(servlet_type) = target;
		let carrier = ClusterWorkRequest::transport_frame_from_der(servlet_type, &work_frame_der)?;

		let reply = self.handle.emit_on_stream(&carrier).await?;
		let reply = reply.ok_or(TightBeamError::MissingResponse);
		let response = reply.and_then(|reply| reply.decode_message::<ClusterWorkResponse>());
		let (_, served_der) = response.and_then(ClusterWorkResponse::into_served_der)?;

		Ok(Uint8Array::from(served_der.as_slice()).into())
	}
}

/// The last holder's drop closes the socket. The task set then ends the pumps
/// and the keepalive as it drops.
impl Drop for Connection {
	fn drop(&mut self) {
		self.monitor.close();
	}
}

/// A multiplexed tightbeam client over a single browser WebSocket session.
///
/// - Concurrent unary [`request`](Self::request) calls share the connection.
/// - Progressive bodies use [`open_stream`](Self::open_stream) and
///   [`open_stream_to`](Self::open_stream_to).
/// - Duplex bodies use [`open_duplex`](Self::open_duplex) and
///   [`open_duplex_to`](Self::open_duplex_to).
/// - [`serve`](Self::serve), [`serve_streaming`](Self::serve_streaming), and
///   [`serve_duplex`](Self::serve_duplex) answer peer-initiated work. The first
///   claim picks the mode.
///
/// # Lifetime
///
/// The connection lives as long as its last holder, as a WebSocket does.
///
/// - Each call in flight and each stream the client opens hold the connection.
/// - A started serve loop holds it, so a serving client stays open until it closes.
/// - `free()` releases the hold of the client alone.
/// - [`close`](Self::close) consumes the client and closes the socket at once, whatever still
///   holds the connection.
#[wasm_bindgen]
pub struct MuxWsClient {
	connection: Rc<Connection>,
	serving: Serving,
}

#[wasm_bindgen]
impl MuxWsClient {
	/// Open a server-authenticated multiplexed session to `url`, pinning
	/// `server_cert_der` as the sole trusted server certificate.
	///
	/// - `options.maxPeerStreams` caps the server-initiated streams. The server's own
	///   advertisement caps the requests of this client.
	/// - `options.signal` aborts the dial and the handshake. The socket closes and the promise
	///   rejects with the abort reason of the signal.
	/// - The call reads `server_cert_der` and `options` before it returns, so the caller may reuse the
	///   buffer at once.
	///
	/// # Errors
	///
	/// The call throws these:
	///
	/// - `InvalidBytes` -- `server_cert_der` is not a `Uint8Array`.
	/// - `InvalidCertificate` -- `server_cert_der` is no DER certificate.
	/// - `InvalidText` -- `url` is not a string.
	/// - The errors of the options parse, among them `InvalidStreamCap` and
	///   `SessionOfferRequiresMutual`.
	///
	/// The promise rejects with these:
	///
	/// - The errors of `connectMutual` for a server dial.
	#[wasm_bindgen(js_name = connect, unchecked_return_type = "Promise<MuxWsClient>")]
	pub fn connect(
		#[wasm_bindgen(unchecked_param_type = "string")] url: JsValue,
		#[wasm_bindgen(unchecked_param_type = "Uint8Array")] server_cert_der: JsValue,
		#[wasm_bindgen(unchecked_param_type = "ConnectOptions | undefined")] options: JsValue,
	) -> Result<Promise, JsFault> {
		let url = Text::read(&url, "url")?;
		let dial = Dial::server(&server_cert_der, &options)?;
		Ok(Self::dial(url, dial))
	}

	/// Open a cleartext multiplexed session to `url`.
	///
	/// - The promise resolves once the socket is open, so a failed dial rejects here with `ConnectionClosed`
	///   rather than on the first emit.
	/// - `options.signal` aborts the dial. The socket closes and the promise rejects with the signal's abort
	///   reason.
	///
	/// # Errors
	///
	/// The call throws these:
	///
	/// - `InvalidText` -- `url` is not a string.
	/// - The errors of the options parse.
	///
	/// The promise rejects with these:
	///
	/// - `InvalidUrl` -- the browser refuses to open a socket to `url`.
	/// - `ConnectionClosed` -- the socket closes before it opens.
	/// - The abort reason of `options.signal`.
	#[wasm_bindgen(js_name = connectCleartext, unchecked_return_type = "Promise<MuxWsClient>")]
	pub fn connect_cleartext(
		#[wasm_bindgen(unchecked_param_type = "string")] url: JsValue,
		#[wasm_bindgen(unchecked_param_type = "CleartextConnectOptions | undefined")] options: JsValue,
	) -> Result<Promise, JsFault> {
		let url = Text::read(&url, "url")?;
		let dial = Dial::cleartext(&options)?;
		Ok(Self::dial(url, dial))
	}

	/// As [`connect`](Self::connect), and present a client certificate for
	/// mutual authentication.
	///
	/// - `identity` names the pinned server certificate, the client certificate, and the key that proves it:
	///   the raw 32-byte secp256k1 scalar, or an external `TransportSigner` (WebAuthn, wallet, KMS bridge).
	/// - The wasm copy of a raw scalar wipes as the dial drops it.
	/// - The key of a `TransportSigner` stays in its JavaScript backend.
	/// - The call reads `identity` and `options` before it returns, so the caller may reuse their buffers at
	///   once.
	///
	/// # Errors
	///
	/// The call throws these:
	///
	/// - `InvalidText` -- `url` is not a string.
	/// - The errors of the options parse, among them `InvalidStreamCap`.
	/// - `InvalidBytes` -- a certificate or `options.authorization` is not a `Uint8Array`.
	/// - `InvalidCertificate` -- a certificate is no DER certificate.
	/// - `InvalidClientKey` -- the key is neither a `Uint8Array` nor an object.
	/// - `InvalidSigningKey` -- the scalar is not 32 octets, or names no key.
	/// - `InvalidCallback` at `signer.signPrehash` -- the signer's `signPrehash` is not a function.
	/// - `InvalidOid` -- the signer's `algorithmOid` is no object identifier.
	/// - `InvalidBudgets` -- a budget in `options.budgets` is no whole, non-negative number.
	/// - `InvalidAuthorization` -- `options.authorization` does not fit an `OCTET STRING`.
	/// - `InvalidCallback` at `options.approveReceipt` -- `options.approveReceipt` is not a function.
	///
	/// The promise rejects with these:
	///
	/// - `Signer` -- the client certificate carries another key than the signer's, or the signer
	///   names another algorithm than the profile.
	/// - `CertificateValidationError` -- the client certificate is refused for signing.
	/// - `InvalidUrl` -- the browser refuses to open a socket to `url`.
	/// - `InvalidCertificate` -- the trust store refuses the pinned server certificate, such as one outside
	///   its validity on the host clock.
	/// - `PeerClosedBeforeHandshake` -- the socket closes before the handshake completes.
	/// - The `TransportError` of a failed handshake, by its variant.
	/// - `InvalidState` -- the server does not negotiate multiplexing.
	/// - The abort reason of `options.signal`.
	#[wasm_bindgen(js_name = connectMutual, unchecked_return_type = "Promise<MuxWsClient>")]
	pub fn connect_mutual(
		#[wasm_bindgen(unchecked_param_type = "string")] url: JsValue,
		#[wasm_bindgen(unchecked_param_type = "MutualIdentity")] identity: JsValue,
		#[wasm_bindgen(unchecked_param_type = "MutualConnectOptions | undefined")] options: JsValue,
	) -> Result<Promise, JsFault> {
		let url = Text::read(&url, "url")?;
		let dial = Dial::mutual(&identity, &options)?;
		Ok(Self::dial(url, dial))
	}

	/// Dial `url` as `dial` describes, and resolve with the client once its
	/// session is ready. Every argument is already read, so the future holds
	/// no reference to the caller's values.
	fn dial(url: String, dial: Dial) -> Promise {
		future_to_promise(async move {
			let Dialed { parts, usable_send_budget, monitor } = dial.connect(&url).await?;
			let client = Self::assemble(parts, monitor, usable_send_budget);
			Ok(client.into())
		})
	}

	/// Send a DER-encoded tightbeam [`Frame`] on a fresh stream and resolve
	/// with the DER-encoded response frame, or `undefined` when the server
	/// returned no payload.
	///
	/// - The stream takes its slot of the cap before the call returns, so a
	///   caller reads `hasPendingStreams` as `true` at once.
	/// - Concurrent calls interleave on the connection, and responses
	///   correlate by stream ID.
	/// - An abort of `signal` cancels the stream and rejects with the abort
	///   reason of the signal. Timeouts compose as `AbortSignal.timeout(ms)`.
	#[wasm_bindgen(js_name = request, unchecked_return_type = "Promise<Uint8Array | undefined>")]
	pub fn request(
		&self,
		frame_der: JsBytes,
		#[wasm_bindgen(unchecked_param_type = "AbortSignal | undefined")] signal: JsValue,
	) -> Promise {
		let frame_der = frame_der.read();
		let signal = Signal::read(&signal, "signal");
		let connection = Rc::clone(&self.connection);

		// Dropping the emit future is the cancellation: tightbeam frees the
		// stream and notifies the peer from the drop guard.
		let requesting = async move {
			let frame_der = frame_der?;
			let signal = signal?;
			let emitted = async { Ok(connection.emit(frame_der).await?) };
			signal.race(emitted).await.outcome()
		};
		requesting.start_now()
	}

	/// Submit a signed end-to-end work frame to the servlet type addressed
	/// by `target` (`urn:<nid>:<nss>`) through a cluster gateway, and
	/// resolve with the DER of the servlet's complete response frame.
	///
	/// - The work frame's DER bytes nest in the routing envelope untouched, so its signature stays
	///   verifiable at the servlet, and the returned bytes are the servlet's envelope with the same
	///   fidelity.
	/// - A served work always carries a frame, so the promise always resolves with bytes.
	/// - A gateway refusal rejects with code `WorkRefused` and the refusal's transit status name on
	///   `status`.
	/// - The stream takes its slot as [`request`](Self::request) does, and `signal` aborts it as
	///   it aborts a request.
	#[wasm_bindgen(js_name = submitWork, unchecked_return_type = "Promise<Uint8Array>")]
	pub fn submit_work(
		&self,
		#[wasm_bindgen(unchecked_param_type = "string")] target: JsValue,
		work_frame_der: JsBytes,
		#[wasm_bindgen(unchecked_param_type = "AbortSignal | undefined")] signal: JsValue,
	) -> Promise {
		let target = StreamTarget::read(&target, "target");
		let work_frame_der = work_frame_der.read();
		let signal = Signal::read(&signal, "signal");
		let connection = Rc::clone(&self.connection);

		let submitting = async move {
			let target = target?;
			let work_frame_der = work_frame_der?;
			let signal = signal?;
			let submitted = async { Ok(connection.submit_work(target, work_frame_der).await?) };
			signal.race(submitted).await.outcome()
		};
		submitting.start_now()
	}

	/// Serve server-initiated streams with `handler`.
	///
	/// - The first `serve*` call starts the loop and picks its mode.
	/// - The call is repeatable. The latest handler serves every stream that dispatches after the call, and a
	///   stream in flight finishes on its own handler.
	/// - Handlers for distinct streams run concurrently.
	///
	/// The handler answers the request DER, a `Uint8Array`, with one of these:
	///
	/// - The response frame DER.
	/// - `undefined` or `null`, which accepts the stream without a body.
	/// - A throw or a rejection with a `TransitRefusal` label, which answers with that status.
	///   The client's `StreamRefusal` decides that label.
	/// - Any other throw or rejection, which answers `Unknown`.
	///
	/// # Errors
	///
	/// The call refuses with these:
	///
	/// - `InvalidCallback` -- `handler` is not a function.
	/// - `InvalidServeClaim` -- `claim` is neither `undefined`, `shared`, nor `exclusive`.
	///
	/// A later call refuses with these:
	///
	/// - `ServeModeConflict` -- the loop serves another mode.
	/// - `ServeDispatchClaimed` -- an `exclusive` claim owns the dispatch.
	/// - `ServeDispatchShared` -- an `exclusive` claim meets a running shared handler.
	#[wasm_bindgen(js_name = serve)]
	pub fn serve(
		&mut self,
		#[wasm_bindgen(unchecked_param_type = "UnaryServeHandler")] handler: JsValue,
		claim: Option<ServeClaim>,
	) -> Result<(), JsFault> {
		self.serve_in(ServeMode::Unary, &handler, claim)
	}

	/// Progressive request body: push chunks, then close for a Frame reply.
	///
	/// # Errors
	///
	/// - `StreamsExhausted` -- the local stream cap is full.
	/// - `Draining` -- either side sent a GoAway, or the stream ID space is exhausted.
	/// - `ConnectionClosed` -- the connection failed.
	#[wasm_bindgen(js_name = openStream)]
	pub fn open_stream(&self) -> Result<MuxRequestStream, JsFault> {
		MuxRequestStream::open(Rc::clone(&self.connection))
	}

	/// Progressive request routed to a servlet URN (`urn:<nid>:<nss>`).
	///
	/// The Open carries the origin hop-budget sentinel so the first
	/// gateway applies its `max_hops` clamp.
	///
	/// # Errors
	///
	/// - `InvalidStreamRoute` at `target` -- `target` is no URN string.
	/// - `StreamsExhausted` -- the local stream cap is full.
	/// - `Draining` -- either side sent a GoAway, or the stream ID space is exhausted.
	/// - `ConnectionClosed` -- the connection failed.
	#[wasm_bindgen(js_name = openStreamTo)]
	pub fn open_stream_to(
		&self,
		#[wasm_bindgen(unchecked_param_type = "string")] target: JsValue,
	) -> Result<MuxRequestStream, JsFault> {
		let target = StreamTarget::read(&target, "target")?;
		MuxRequestStream::open_to(Rc::clone(&self.connection), target)
	}

	/// Full-duplex body streaming on one stream id.
	///
	/// Pushes reach the socket eagerly, so awaiting a reply chunk
	/// between pushes (a chunk-for-chunk conversation) is sound.
	///
	/// # Errors
	///
	/// - `StreamsExhausted` -- the local stream cap is full.
	/// - `Draining` -- either side sent a GoAway, or the stream ID space is exhausted.
	/// - `ConnectionClosed` -- the connection failed.
	#[wasm_bindgen(js_name = openDuplex)]
	pub fn open_duplex(&self) -> Result<MuxDuplexStream, JsFault> {
		MuxDuplexStream::open(Rc::clone(&self.connection))
	}

	/// Duplex stream routed to a servlet URN (`urn:<nid>:<nss>`).
	///
	/// As [`open_stream_to`](Self::open_stream_to): the Open carries the
	/// origin hop-budget sentinel for the first gateway's `max_hops` clamp.
	///
	/// # Errors
	///
	/// - `InvalidStreamRoute` at `target` -- `target` is no URN string.
	/// - `StreamsExhausted` -- the local stream cap is full.
	/// - `Draining` -- either side sent a GoAway, or the stream ID space is exhausted.
	/// - `ConnectionClosed` -- the connection failed.
	#[wasm_bindgen(js_name = openDuplexTo)]
	pub fn open_duplex_to(
		&self,
		#[wasm_bindgen(unchecked_param_type = "string")] target: JsValue,
	) -> Result<MuxDuplexStream, JsFault> {
		let target = StreamTarget::read(&target, "target")?;
		MuxDuplexStream::open_to(Rc::clone(&self.connection), target)
	}

	/// Serve peer streams as progressive bodies. The handler receives a
	/// [`MuxStreamBody`](crate::streaming::MuxStreamBody) and the Open's
	/// route (`{ target?, hopsRemaining }`), and returns a Frame DER (or
	/// `undefined`).
	///
	/// # Errors
	///
	/// - The errors of `serve`.
	#[wasm_bindgen(js_name = serveStreaming)]
	pub fn serve_streaming(
		&mut self,
		#[wasm_bindgen(unchecked_param_type = "StreamingServeHandler")] handler: JsValue,
		claim: Option<ServeClaim>,
	) -> Result<(), JsFault> {
		self.serve_in(ServeMode::Streaming, &handler, claim)
	}

	/// Serve peer streams as duplex bodies. The handler receives a
	/// [`MuxStreamBody`](crate::streaming::MuxStreamBody),
	/// [`MuxReplySink`](crate::streaming::MuxReplySink), and the Open's
	/// route, and resolves with a gRPC status name or `undefined` (`Ok`).
	///
	/// # Errors
	///
	/// - The errors of `serve`.
	#[wasm_bindgen(js_name = serveDuplex)]
	pub fn serve_duplex(
		&mut self,
		#[wasm_bindgen(unchecked_param_type = "DuplexServeHandler")] handler: JsValue,
		claim: Option<ServeClaim>,
	) -> Result<(), JsFault> {
		self.serve_in(ServeMode::Duplex, &handler, claim)
	}

	/// Connection-level liveness probe, the analog of RFC 9113 § 6.7: resolves
	/// when the peer's ack arrives.
	///
	/// - The probe runs on the connection, outside every stream and every application handler of the peer.
	/// - A client already pings on its own to hold an idle session open, so call this to measure the link.
	/// - `signal` composes deadlines. An abort rejects with the signal's abort reason, and the client drops a
	///   late ack.
	#[wasm_bindgen(js_name = ping, unchecked_return_type = "Promise<void>")]
	pub fn ping(&self, #[wasm_bindgen(unchecked_param_type = "AbortSignal | undefined")] signal: JsValue) -> Promise {
		let signal = Signal::read(&signal, "signal");
		let connection = Rc::clone(&self.connection);

		future_to_promise(async move {
			let signal = signal?;
			let ping = async move {
				connection.handle.ping().await.map_err(JsFault::from)?;
				Ok(JsValue::UNDEFINED)
			};

			let raced = signal.race(ping).await;
			raced.outcome()
		})
	}

	/// Whether a new locally-initiated stream would be admitted now.
	///
	/// Advisory: a concurrent emit can take the last slot after this
	/// returns, so callers still handle the `StreamsExhausted` rejection.
	#[wasm_bindgen(getter, js_name = hasStreamHeadroom)]
	pub fn has_stream_headroom(&self) -> bool {
		self.connection.handle.has_stream_headroom()
	}

	/// Whether any locally-initiated stream still awaits its response.
	///
	/// Advisory like [`hasStreamHeadroom`](Self::has_stream_headroom): a
	/// pre-close check, not a synchronization primitive.
	#[wasm_bindgen(getter, js_name = hasPendingStreams)]
	pub fn has_pending_streams(&self) -> bool {
		self.connection.handle.has_pending_streams()
	}

	/// Resolves once a new locally-initiated stream would be admitted.
	/// Replaces polling `hasStreamHeadroom` in a loop, with the same
	/// advisory caveat.
	///
	/// - The promise rejects with `Draining` or `ConnectionClosed` once the connection admits no further
	///   stream.
	/// - It rejects with the abort reason of `signal` when the caller gives up first.
	#[wasm_bindgen(js_name = waitForStreamSlot, unchecked_return_type = "Promise<void>")]
	pub fn wait_for_stream_slot(
		&self,
		#[wasm_bindgen(unchecked_param_type = "AbortSignal | undefined")] signal: JsValue,
	) -> Promise {
		let signal = Signal::read(&signal, "signal");
		let connection = Rc::clone(&self.connection);
		future_to_promise(async move {
			let signal = signal?;
			let admitted = async move {
				connection.handle.wait_for_stream_slot().await.map_err(JsFault::from)?;
				Ok(JsValue::UNDEFINED)
			};

			let raced = signal.race(admitted).await;
			raced.outcome()
		})
	}

	/// Reason carried by the peer's GoAway, or `undefined` while the
	/// connection is live or was shut down locally. Reconnect policies branch
	/// on it:
	///
	/// - `shutdown` invites an immediate reconnect.
	/// - `enhance-your-calm` calls for backoff.
	/// - `protocol-error` points at a bug rather than a transient fault.
	#[wasm_bindgen(getter, js_name = goawayReason)]
	pub fn goaway_reason(&self) -> Option<GoAwayLabel> {
		self.connection.handle.goaway_reason().map(GoAwayLabel::from)
	}

	/// Numeric code behind [`goawayReason`](Self::goaway_reason), or
	/// `undefined` when that getter is `undefined`. Distinguishes
	/// application-defined codes that all label as `"application"`.
	#[wasm_bindgen(getter, js_name = goawayCode)]
	pub fn goaway_code(&self) -> Option<u32> {
		self.connection.handle.goaway_reason().map(u32::from)
	}

	/// Gracefully shut the connection down: sends GoAway, lets in-flight
	/// streams drain, then stops the writer.
	#[wasm_bindgen(js_name = shutdown, unchecked_return_type = "Promise<void>")]
	pub fn shutdown(&self) -> Promise {
		let connection = Rc::clone(&self.connection);

		future_to_promise(async move {
			connection.handle.shutdown().await.map_err(JsFault::from)?;
			Ok(JsValue::UNDEFINED)
		})
	}

	/// As [`shutdown`](Self::shutdown), advertising `reason` in the GoAway
	/// so the peer's reconnect policy can branch on it.
	///
	/// - `reason` is a label or a numeric code, and a code outside the reserved range is application-defined.
	/// - The label `"application"` alone carries no code, so the call rejects it.
	#[wasm_bindgen(js_name = shutdownWith, unchecked_return_type = "Promise<void>")]
	pub fn shutdown_with(
		&self,
		#[wasm_bindgen(unchecked_param_type = "Exclude<GoAwayReason, \"application\"> | number")] reason: JsValue,
	) -> Promise {
		let connection = Rc::clone(&self.connection);
		let reason = GoAwayLabel::shutdown_reason(&reason);

		future_to_promise(async move {
			connection.handle.shutdown_with(reason?).await.map_err(JsFault::from)?;
			Ok(JsValue::UNDEFINED)
		})
	}

	/// The negotiated cap on concurrent locally-initiated streams.
	#[wasm_bindgen(getter, js_name = maxConcurrentStreams)]
	pub fn max_concurrent_streams(&self) -> u32 {
		self.connection.handle.max_concurrent_streams()
	}

	/// Usable outbound session-budget credits for this epoch, or
	/// `undefined` when the session is unmetered. Invoice sizing uses
	/// this figure (grant minus drain reserve). There is no live
	/// remaining-balance getter.
	#[wasm_bindgen(getter, js_name = usableSendBudget)]
	pub fn usable_send_budget(&self) -> Option<f64> {
		self.connection.usable_send_budget.map(|credits| credits as f64)
	}

	/// DER of the current epoch's dual-signed session receipt, or
	/// `undefined` on unmetered sessions. Rotates after each successful
	/// in-band renewal.
	#[wasm_bindgen(getter, js_name = sessionReceiptDer, unchecked_return_type = "Uint8Array | undefined")]
	pub fn session_receipt_der(&self) -> Option<Uint8Array> {
		let stored = self.connection.handle.session_receipt()?;
		let der = stored.to_der().ok()?;
		Some(Uint8Array::from(der.as_slice()))
	}

	/// A promise resolving with a `SocketCloseInfo` when the socket closes.
	#[wasm_bindgen(getter, js_name = closed, unchecked_return_type = "Promise<SocketCloseInfo>")]
	pub fn closed(&self) -> Promise {
		self.connection.monitor.closed()
	}

	/// The socket's readyState (0 CONNECTING, 1 OPEN, 2 CLOSING, 3 CLOSED).
	#[wasm_bindgen(getter, js_name = readyState)]
	pub fn ready_state(&self) -> u16 {
		self.connection.monitor.ready_state()
	}

	/// Close the underlying socket without a graceful drain (see
	/// [`shutdown`](Self::shutdown)). The `closed` promise resolves once
	/// the close completes.
	///
	/// The close consumes the client, so read `closed` before the call.
	#[wasm_bindgen(js_name = close)]
	pub fn close(self) {
		self.connection.monitor.close();
	}

	/// Serve peer streams in `mode` with the function at `handler`, under the
	/// label `claim`.
	///
	/// # Errors
	///
	/// - `InvalidCallback` -- `handler` is not a function.
	/// - The errors of [`ServeClaim::admit`].
	/// - The errors of [`Serving::claim`].
	fn serve_in(&mut self, mode: ServeMode, handler: &JsValue, claim: Option<ServeClaim>) -> Result<(), JsFault> {
		let handler = Callback::read(handler, "handler")?;
		let claim = ServeClaim::admit(claim)?;
		self.serving.claim(mode, handler, claim, &self.connection)
	}

	/// Assemble a client over the split `parts` and the socket that `monitor`
	/// observes. Its responder waits for the first `serve*` call.
	fn assemble(parts: SessionParts, monitor: SocketMonitor, usable_send_budget: Option<u64>) -> Self {
		let SessionParts { handle, responder, tasks } = parts;
		let connection = Rc::new(Connection { handle, monitor, usable_send_budget, _tasks: tasks });
		let serving = Serving::Idle(responder);

		Self { connection, serving }
	}
}

#[cfg(test)]
mod tests {
	use futures_util::future::ready;
	use futures_util::FutureExt;
	use js_sys::{Function, Object, Reflect, Uint8Array};
	use tightbeam::der::Encode;
	use tightbeam::testing::{TestCertificate, TestFrame, TestKey};
	use tightbeam::transport::multiplex::{MuxHandle, MuxRole};
	use tightbeam::transport::TransportError;
	use wasm_bindgen::{JsCast, JsValue};
	use wasm_bindgen_futures::JsFuture;
	use wasm_bindgen_test::wasm_bindgen_test;
	use web_sys::{AbortSignal, WebSocket as Socket};

	use super::{MuxWsClient, ServeClaim};
	use crate::dial::Dial;
	use crate::fault::Refused;
	use crate::loopback::{settled, Served};
	use crate::promise::JsBytes;
	use crate::protocol::BrowserSocket;
	use crate::socket::tests::UNREACHED_URL;
	use crate::socket::{Opened, OpeningSocket, SocketMonitor, SocketParts};
	use crate::streaming::MuxRequestStream;

	/// The monitor that `opening` hands over for a step that settles at once
	/// under no signal.
	fn monitor_of(opening: OpeningSocket) -> SocketMonitor {
		let no_signal: Option<AbortSignal> = None;
		let step = ready(Ok::<(), JsValue>(()));
		let settled = opening.within(&no_signal, step).now_or_never();

		let ready_step = settled.expect("a race under no signal settles at once");
		let Opened { value: (), monitor } = ready_step.expect("a ready step settles Ok");
		monitor
	}

	/// A cleartext client over a socket that is still connecting, the monitor
	/// of that socket, and a handle that holds no part of the connection.
	fn connecting_client() -> (MuxWsClient, SocketMonitor, MuxHandle) {
		let SocketParts { opening, carrier } = OpeningSocket::open(UNREACHED_URL).expect("the socket should construct");
		let monitor = monitor_of(opening);
		let session = BrowserSocket::cleartext_session(carrier, MuxRole::Client, 1);
		let parts = session.expect("the cleartext session should split");
		let probe = parts.handle.clone();
		let client = MuxWsClient::assemble(parts, monitor.clone(), None);

		(client, monitor, probe)
	}

	/// A cleartext client over a socket that the loopback server accepted, a
	/// handle that holds no part of the connection, and the server.
	async fn open_client() -> (MuxWsClient, MuxHandle, Served) {
		let served = Served::listening().await;
		let SocketParts { opening, carrier } = OpeningSocket::open(&served.url()).expect("the socket should construct");
		let no_signal: Option<AbortSignal> = None;
		let opened = opening.opened();
		let open = settled(opening.within(&no_signal, opened)).await;
		let Opened { value: (), monitor } = open.expect("the server should accept the socket");

		let session = BrowserSocket::cleartext_session(carrier, MuxRole::Client, 1);
		let parts = session.expect("the cleartext session should split");
		let probe = parts.handle.clone();
		let client = MuxWsClient::assemble(parts, monitor, None);

		(client, probe, served)
	}

	/// A progressive request stream on `client`.
	fn open_stream(client: &MuxWsClient) -> MuxRequestStream {
		client.open_stream().expect("a client with headroom should open a stream")
	}

	/// A serve handler that accepts each stream without a body.
	fn accepting() -> JsValue {
		Function::new_no_args("return undefined").into()
	}

	/// The exclusive serve claim.
	fn exclusive() -> Option<ServeClaim> {
		Some(ServeClaim::Exclusive)
	}

	/// The options object `{ [field]: value }`.
	fn options(field: &str, value: JsValue) -> JsValue {
		let object = Object::new();
		let set = Reflect::set(&object, &JsValue::from_str(field), &value);
		set.expect("a fresh object should take the field");

		object.into()
	}

	/// The identity a mutual dial presents, with a raw scalar for its key.
	fn identity() -> JsValue {
		let object = Object::new();
		let certificate = certificate();
		let scalar = Uint8Array::from([1u8; 32].as_slice());
		for (field, value) in [
			("serverCertDer", &certificate),
			("clientCertDer", &certificate),
			("clientKey", &scalar),
		] {
			let set = Reflect::set(&object, &JsValue::from_str(field), value);
			set.expect("a fresh object should take the field");
		}

		object.into()
	}

	/// The DER of a self-signed test certificate.
	fn certificate() -> Uint8Array {
		let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let der = certificate.to_der().expect("the test certificate should encode");
		Uint8Array::from(der.as_slice())
	}

	/// The code each connector throws for the options `{ [field]: value }`, in
	/// the order connect, connectMutual, connectCleartext.
	fn dial_codes(value: f64) -> [Option<String>; 3] {
		let server = MuxWsClient::connect(url(), certificate().into(), options("maxPeerStreams", value.into()));
		let mutual = MuxWsClient::connect_mutual(url(), identity(), options("maxPeerStreams", value.into()));
		let cleartext = MuxWsClient::connect_cleartext(url(), options("streams", value.into()));

		[server.code(), mutual.code(), cleartext.code()]
	}

	/// The url of a dial that no server answers.
	fn url() -> JsValue {
		JsValue::from_str(UNREACHED_URL)
	}

	/// `octets` as a JavaScript byte parameter.
	fn bytes(octets: &[u8]) -> JsBytes {
		Uint8Array::from(octets).unchecked_into()
	}

	/// Start the unary serve loop of `client` with a handler that accepts each
	/// stream without a body.
	fn serve(client: &mut MuxWsClient) {
		let handler = accepting();
		let served = client.serve(handler, None);
		served.expect("an idle client should start its serve loop");
	}

	/// The DER of a frame, as JavaScript hands it to a request.
	fn frame_der() -> JsBytes {
		let der = TestFrame::v0(None, None).to_der().expect("the test frame should encode");
		bytes(&der)
	}

	#[wasm_bindgen_test]
	fn a_request_takes_its_stream_slot_before_it_returns() {
		let (client, _monitor, probe) = connecting_client();
		// The future handles the rejection that the failed dial settles the
		// call with.
		let _pending = JsFuture::from(client.request(frame_der(), JsValue::UNDEFINED));
		assert!(probe.has_pending_streams());
	}

	#[wasm_bindgen_test]
	fn a_work_submission_takes_its_stream_slot_before_it_returns() {
		let (client, _monitor, probe) = connecting_client();
		let target = JsValue::from_str("urn:tightbeam::servlet:probe");
		let _pending = JsFuture::from(client.submit_work(target, frame_der(), JsValue::UNDEFINED));
		assert!(probe.has_pending_streams());
	}

	#[wasm_bindgen_test]
	fn a_freed_client_closes_its_socket() {
		let (client, monitor, _probe) = connecting_client();
		drop(client);
		assert_eq!(monitor.ready_state(), Socket::CLOSING);
	}

	#[wasm_bindgen_test]
	fn a_freed_serving_client_keeps_its_socket() {
		let (mut client, monitor, _probe) = connecting_client();
		serve(&mut client);
		drop(client);
		assert_eq!(monitor.ready_state(), Socket::CONNECTING);
		monitor.close();
	}

	#[wasm_bindgen_test]
	fn a_closed_serving_client_closes_its_socket() {
		let (mut client, monitor, _probe) = connecting_client();
		serve(&mut client);
		client.close();
		assert_eq!(monitor.ready_state(), Socket::CLOSING);
	}

	#[wasm_bindgen_test]
	async fn a_freed_client_ends_its_tasks() {
		let (client, probe, served) = open_client().await;
		let _hold = served.hold().await;
		let opened = probe.open_stream().expect("a session with headroom should open a stream");
		let (_sink, response) = opened;
		drop(client);

		// The hold keeps the close of the socket open, so only the drop of the
		// tasks ends the stream.
		let answered = settled(response).await;
		assert!(matches!(answered, Err(TransportError::ConnectionClosed)));
		assert!(matches!(probe.open_stream(), Err(TransportError::ConnectionClosed)));
	}

	#[wasm_bindgen_test]
	async fn a_live_stream_keeps_the_socket_of_a_freed_client() {
		let (client, monitor, _probe) = connecting_client();
		let stream = open_stream(&client);
		drop(client);

		let chunk = Uint8Array::from([1u8].as_slice());
		let pushed = settled(JsFuture::from(stream.push(chunk.unchecked_into()))).await;
		assert!(pushed.is_ok());
		assert_eq!(monitor.ready_state(), Socket::CONNECTING);
	}

	#[wasm_bindgen_test]
	fn the_last_stream_of_a_freed_client_closes_its_socket() {
		let (client, monitor, _probe) = connecting_client();
		let stream = open_stream(&client);
		drop(client);
		drop(stream);
		assert_eq!(monitor.ready_state(), Socket::CLOSING);
	}

	#[wasm_bindgen_test]
	fn an_exclusive_claim_refuses_a_later_serve() {
		let (mut client, _monitor, _probe) = connecting_client();
		let _claimed = client.serve(accepting(), exclusive());

		let later = client.serve(accepting(), None);
		assert_eq!(later.code().as_deref(), Some("ServeDispatchClaimed"));
	}

	#[wasm_bindgen_test]
	fn an_exclusive_claim_refuses_another_mode() {
		let (mut client, _monitor, _probe) = connecting_client();
		let _claimed = client.serve(accepting(), exclusive());

		let later = client.serve_streaming(accepting(), None);
		assert_eq!(later.code().as_deref(), Some("ServeDispatchClaimed"));
	}

	#[wasm_bindgen_test]
	fn an_exclusive_claim_refuses_a_second_exclusive_claim() {
		let (mut client, _monitor, _probe) = connecting_client();
		let _claimed = client.serve(accepting(), exclusive());

		let later = client.serve(accepting(), exclusive());
		assert_eq!(later.code().as_deref(), Some("ServeDispatchClaimed"));
	}

	#[wasm_bindgen_test]
	fn an_exclusive_claim_refuses_to_replace_a_shared_handler() {
		let (mut client, _monitor, _probe) = connecting_client();
		serve(&mut client);

		let later = client.serve(accepting(), exclusive());
		assert_eq!(later.code().as_deref(), Some("ServeDispatchShared"));
	}

	#[wasm_bindgen_test]
	fn a_shared_claim_takes_a_later_handler_in_its_mode() {
		let (mut client, _monitor, _probe) = connecting_client();
		serve(&mut client);

		let later = client.serve(accepting(), Some(ServeClaim::Shared));
		assert!(later.is_ok());
	}

	#[wasm_bindgen_test]
	fn a_claim_in_another_mode_conflicts() {
		let (mut client, _monitor, _probe) = connecting_client();
		serve(&mut client);

		let later = client.serve_streaming(accepting(), None);
		assert_eq!(later.code().as_deref(), Some("ServeModeConflict"));
	}

	#[wasm_bindgen_test]
	fn a_stream_cap_of_zero_fraction_negative_or_nan_is_refused() {
		let codes = [dial_codes(0.0), dial_codes(1.5), dial_codes(-1.0), dial_codes(f64::NAN)];
		let refused = [
			Some(String::from("InvalidStreamCap")),
			Some(String::from("InvalidStreamCap")),
			Some(String::from("InvalidStreamCap")),
		];
		assert_eq!(codes, [refused.clone(), refused.clone(), refused.clone(), refused]);
	}

	#[wasm_bindgen_test]
	fn null_dial_options_take_the_defaults_and_a_number_is_refused() {
		let absent = [JsValue::UNDEFINED, JsValue::NULL].map(|options| Dial::cleartext(&options).code());
		let positional = Dial::cleartext(&JsValue::from_f64(8.0)).code();
		assert_eq!((absent, positional.as_deref()), ([None, None], Some("InvalidConnectOptions")));
	}

	#[wasm_bindgen_test]
	async fn a_signal_that_is_no_abort_signal_refuses_the_request() {
		let (client, _monitor, _probe) = connecting_client();
		let requested = client.request(frame_der(), Object::new().into());

		let code = settled(JsFuture::from(requested)).await.code();
		assert_eq!(code.as_deref(), Some("InvalidSignal"));
	}

	#[wasm_bindgen_test]
	fn a_handler_that_is_no_function_is_refused() {
		let (mut client, _monitor, _probe) = connecting_client();
		let unary = client.serve(JsValue::from_f64(7.0), None);
		let streaming = client.serve_streaming(JsValue::from_f64(7.0), None);
		let duplex = client.serve_duplex(JsValue::from_f64(7.0), None);

		let refused = [unary.code(), streaming.code(), duplex.code()];
		assert_eq!(
			refused,
			[
				Some(String::from("InvalidCallback")),
				Some(String::from("InvalidCallback")),
				Some(String::from("InvalidCallback"))
			]
		);
	}

	#[wasm_bindgen_test]
	fn a_dial_signal_that_is_no_abort_signal_is_refused_at_its_member() {
		let cleartext = MuxWsClient::connect_cleartext(url(), options("signal", Object::new().into()));
		assert_eq!(
			cleartext.refusal(),
			Some((String::from("InvalidSignal"), String::from("options.signal")))
		);
	}

	#[wasm_bindgen_test]
	fn a_session_knob_refusal_names_its_member() {
		let budgets = MuxWsClient::connect_mutual(url(), identity(), options("budgets", JsValue::from_f64(7.0)));
		let approver =
			MuxWsClient::connect_mutual(url(), identity(), options("approveReceipt", JsValue::from_f64(7.0)));

		let refusals = [budgets.refusal(), approver.refusal()];
		assert_eq!(
			refusals,
			[
				Some((String::from("InvalidBudgets"), String::from("options.budgets"))),
				Some((String::from("InvalidCallback"), String::from("options.approveReceipt")))
			]
		);
	}

	#[wasm_bindgen_test]
	fn a_server_dial_refuses_a_session_knob() {
		let authorization = Uint8Array::from([1u8].as_slice());
		let server = MuxWsClient::connect(
			url(),
			certificate().into(),
			options("authorization", authorization.clone().into()),
		);

		let cleartext = MuxWsClient::connect_cleartext(url(), options("authorization", authorization.into()));
		let codes = [server.code(), cleartext.code()];
		assert_eq!(
			codes,
			[
				Some(String::from("SessionOfferRequiresMutual")),
				Some(String::from("SessionOfferRequiresMutual"))
			]
		);
	}

	#[wasm_bindgen_test]
	fn a_serve_claim_other_than_shared_or_exclusive_is_refused() {
		let (mut client, _monitor, _probe) = connecting_client();
		let unary = client.serve(accepting(), Some(ServeClaim::__Invalid)).code();
		let streaming = client.serve_streaming(accepting(), Some(ServeClaim::__Invalid)).code();
		let duplex = client.serve_duplex(accepting(), Some(ServeClaim::__Invalid)).code();

		let codes = [unary.as_deref(), streaming.as_deref(), duplex.as_deref()];
		assert_eq!(codes, [Some("InvalidServeClaim"); 3]);
	}

	#[wasm_bindgen_test]
	async fn a_stream_target_other_than_a_urn_string_is_refused_at_target() {
		let (client, _monitor, _probe) = connecting_client();
		let refused = Some((String::from("InvalidStreamRoute"), String::from("target")));
		for target in [JsValue::from_f64(7.0), JsValue::from_str("not-a-urn")] {
			let stream = client.open_stream_to(target.clone()).refusal();
			let duplex = client.open_duplex_to(target.clone()).refusal();
			let submitted = client.submit_work(target, frame_der(), JsValue::UNDEFINED);
			let work = settled(JsFuture::from(submitted)).await.refusal();
			assert_eq!([stream, duplex, work], [refused.clone(), refused.clone(), refused.clone()]);
		}
	}
}
