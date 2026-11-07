//! Multiplexed browser WebSocket client. Compiled only for `wasm32`
//! targets.
//!
//! Splits the connection into exclusive halves and spawns tightbeam's
//! [`MuxTransport`] driver on the browser microtask executor. The resulting
//! client emits concurrent requests and serves peer-initiated streams over one
//! connection. Encrypted sessions negotiate HTTP/2-style stream multiplexing
//! during the HPKE handshake. Cleartext sessions have no handshake, so both
//! endpoints configure the same symmetric cap.

use core::future::Future;
use core::mem;
use std::rc::Rc;

use futures_util::future::{abortable, AbortHandle};
use js_sys::{Function, Promise, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{future_to_promise, spawn_local};

use web_sys::AbortSignal;

use tightbeam::colony::work::{ClusterWorkRequest, ClusterWorkResponse};
use tightbeam::der::Decode;
use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::handshake::HandshakeProvider;
use tightbeam::transport::multiplex::{
	MultiplexedProtocol, MuxDispatch, MuxHandle, MuxResponder, MuxRole, MuxTransport,
};
use tightbeam::transport::{EncryptedMessageIO, EnvelopeSink, EnvelopeSource, TransportResult};
use tightbeam::{Frame, TightBeamError};

use crate::fault::{JsFault, RefusalCode};
use crate::goaway::GoAwayLabel;
use crate::promise::{AbortRace, JsBytes, JsResponse, Record};
use crate::protocol::BrowserSocket;
use crate::secure::{Dial, DialOptions, MutualDialOptions, MutualIdentity};
use crate::socket::{OpeningSocket, SocketMonitor};
use crate::stream::{GlooStream, WsTransport};
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
	/// The loop holds `connection` as a WebSocket with listeners holds its
	/// socket. A serving client therefore stays open after the application
	/// frees or drops it, until `close()`, the peer's close, or a GoAway ends
	/// the connection. The loop then ends once the streams in flight settle.
	fn run(responder: MuxResponder, dispatch: impl MuxDispatch + 'static, connection: Rc<Connection>) {
		spawn_local(async move {
			// The terminal status of the loop already reached the peer
			// (GoAway), so nothing is left to report.
			let _ = responder.serve_with(dispatch).await;
			drop(connection);
		});
	}

	/// The refusal of a claim in `requested` once a loop in this mode started.
	fn conflict(self, requested: Self) -> JsFault {
		let current = self.label();
		let requested = requested.label();
		let message = format!("peer serve mode is {current}. Cannot switch to {requested} after the responder started");

		RefusalCode::ServeModeConflict.because(message)
	}
}

/// TypeScript shape of the claim a `serve*` call makes.
#[wasm_bindgen(typescript_custom_section)]
const SERVE_CLAIM_TS: &'static str = r#"
/**
 * How a `serve*` call claims the stream dispatch: `shared`, the default,
 * lets a later call in the same mode swap the handler, and `exclusive`
 * refuses every later call.
 */
export type ServeClaim = "shared" | "exclusive";
"#;

/// Whether a `serve*` claim leaves the dispatch open to later claims.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Claim {
	/// A later claim in the same mode swaps the handler.
	Shared,
	/// Every later claim refuses, because one owner dispatches the streams
	/// and composes the routes of the application under itself.
	Exclusive,
}

/// A claim as JavaScript passes it: the label `shared` or `exclusive`, or
/// `undefined` for `shared`.
impl TryFrom<&JsValue> for Claim {
	type Error = JsFault;

	/// # Errors
	///
	/// - `InvalidServeClaim` -- the value is neither `undefined` nor one of the two labels.
	fn try_from(claim: &JsValue) -> Result<Self, Self::Error> {
		let Some(label) = Record::present(claim.clone()) else {
			return Ok(Self::Shared);
		};

		match label.as_string().as_deref() {
			Some("shared") => Ok(Self::Shared),
			Some("exclusive") => Ok(Self::Exclusive),
			_ => Err(RefusalCode::InvalidServeClaim.because("a serve claim is \"shared\" or \"exclusive\"")),
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
	/// The first claim starts the serve loop of `mode`. A later shared claim
	/// in the same mode swaps the handler of a shared loop for the streams
	/// dispatched after it.
	///
	/// # Errors
	///
	/// - `ServeDispatchClaimed` -- an exclusive claim owns the dispatch.
	/// - `ServeDispatchShared` -- an exclusive claim meets a running shared handler.
	/// - `ServeModeConflict` -- an earlier claim started a loop in another mode.
	fn claim(
		&mut self,
		mode: ServeMode,
		handler: Function,
		claim: Claim,
		connection: &Rc<Connection>,
	) -> Result<(), JsFault> {
		let slot = match self {
			Self::Started { claim: Claim::Exclusive, .. } => {
				let message = "stream dispatch is exclusively claimed on this client (a SubscriptionManager?). Route \
				               application streams through the claimant instead of calling serve again";
				return Err(RefusalCode::ServeDispatchClaimed.because(message));
			}
			Self::Started { .. } if claim == Claim::Exclusive => {
				let message = "a shared handler already serves this client, so an exclusive claim would replace it";
				return Err(RefusalCode::ServeDispatchShared.because(message));
			}
			Self::Started { mode: current, handler: slot, .. } if *current == mode => {
				slot.replace(handler);
				return Ok(());
			}
			Self::Started { mode: current, .. } => return Err(current.conflict(mode)),
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
/// The split spawns the reader and writer pumps and the keepalive, and hands
/// them back as a [`MuxTasks`] set that ends them when it drops. Pump failures
/// reach callers as `ConnectionClosed` on their pending streams.
pub trait BrowserMux {
	/// Split into a stream handle, a responder, and the tasks that drive them.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidState`](tightbeam::transport::TransportError::InvalidState) --
	///   the peer did not negotiate multiplexing.
	/// - [`TransportError`](tightbeam::transport::TransportError) -- the transport fails to split
	///   into its halves.
	fn split(self) -> TransportResult<(MuxHandle, MuxResponder, MuxTasks)>;
}

impl<R, W> BrowserMux for MuxTransport<R, W>
where
	R: EnvelopeSource + 'static,
	W: EnvelopeSink + 'static,
{
	fn split(self) -> TransportResult<(MuxHandle, MuxResponder, MuxTasks)> {
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
		Ok((handle, responder, tasks))
	}
}

impl<P: HandshakeProvider> BrowserMux for WsTransport<P> {
	/// Split a handshaken transport. The handshake decides whether the peer
	/// negotiated multiplexing, and [`WsTransport::into_mux`] refuses a
	/// transport whose peer did not.
	fn split(self) -> TransportResult<(MuxHandle, MuxResponder, MuxTasks)> {
		self.into_mux(MuxRole::Client)?.split()
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
/// The client, each stream it opens, each call in flight, and a started serve
/// loop hold the connection. The socket closes and the tasks end when the last
/// holder drops, so a freed client leaves the socket to the work that still
/// uses it.
pub(crate) struct Connection {
	handle: MuxHandle,
	monitor: SocketMonitor,
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
	/// The carrier nests the caller's DER and reads its id in place, and the
	/// reply hands back the servlet's DER as it arrived. The end-to-end frame
	/// crosses the boundary untouched in both directions, and the servlet
	/// parses it.
	async fn submit_work(&self, target: &str, work_frame_der: Vec<u8>) -> Result<JsValue, JsFault> {
		let StreamTarget(servlet_type) = StreamTarget::try_from(target)?;
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
	/// Usable outbound credits for this epoch (`None` = unmetered).
	usable_send_budget: Option<u64>,
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
	///
	/// The call reads `server_cert_der` and `options` before it returns, so
	/// the caller may reuse the buffer at once.
	///
	/// # Errors
	///
	/// The call throws these:
	///
	/// - `InvalidBytes` -- `server_cert_der` is not a `Uint8Array`.
	/// - The errors of the [`DialOptions`] parse, among them `InvalidStreamCap` and
	///   `SessionOfferRequiresMutual`.
	///
	/// The promise rejects as [`connect_mutual`](Self::connect_mutual) does for a server dial.
	#[wasm_bindgen(js_name = connect, unchecked_return_type = "Promise<MuxWsClient>")]
	pub fn connect(
		url: &str,
		server_cert_der: JsBytes,
		#[wasm_bindgen(unchecked_param_type = "ConnectOptions | undefined")] options: JsValue,
	) -> Result<Promise, JsFault> {
		let options = DialOptions::try_from(&options)?;
		let dial = Dial::Server(server_cert_der.read()?);
		Ok(Self::dial(url, dial, options))
	}

	/// Open a cleartext multiplexed session to `url`. Resolves once the
	/// socket is open, so a failed dial rejects here (`ConnectionClosed`)
	/// rather than on the first emit.
	///
	/// `options.signal` aborts the dial: the socket closes and the promise
	/// rejects with the signal's abort reason.
	///
	/// # Errors
	///
	/// - The errors of the cleartext [`DialOptions`] parse, which the call throws.
	#[wasm_bindgen(js_name = connectCleartext, unchecked_return_type = "Promise<MuxWsClient>")]
	pub fn connect_cleartext(
		url: &str,
		#[wasm_bindgen(unchecked_param_type = "CleartextConnectOptions | undefined")] options: JsValue,
	) -> Result<Promise, JsFault> {
		let options = DialOptions::cleartext(&options)?;
		let url = url.to_owned();

		Ok(future_to_promise(async move {
			let signal = options.signal();
			if let Some(reason) = signal.aborted_reason() {
				return Err(reason);
			}

			let (opening, carrier) = OpeningSocket::open(&url)?;
			let opened = opening.opened();
			let ((), monitor) = opening.within(signal, opened).await?;

			let stream = GlooStream::from(carrier);
			let transport: WsTransport = BrowserSocket::cleartext(stream).map_err(JsFault::from)?;
			let (reader, writer) = transport.into_split().map_err(JsFault::from)?;
			let settings = MuxSettings::symmetric(options.streams());
			let mux = MuxTransport::new(reader, writer, MuxRole::Client, settings);
			let parts = mux.split().map_err(JsFault::from)?;

			let client = Self::assemble(parts, monitor, None);
			Ok(client.into())
		}))
	}

	/// As [`connect`](Self::connect), and present a client certificate for
	/// mutual authentication.
	///
	/// `identity` names the pinned server certificate, the client certificate,
	/// and the key that proves it. The key is one of these:
	///
	/// - The raw 32-byte secp256k1 scalar. Its wasm copy wipes as the dial drops it.
	/// - An external `TransportSigner` (WebAuthn, wallet, KMS bridge). The key stays in
	///   its JavaScript backend.
	///
	/// The call reads `identity` and `options` before it returns, so the caller
	/// may reuse their buffers at once.
	///
	/// # Errors
	///
	/// The call throws these:
	///
	/// - The errors of the [`MutualDialOptions`] parse, among them `InvalidStreamCap`.
	/// - `InvalidBytes` -- a certificate or `options.authorization` is not a `Uint8Array`.
	/// - `InvalidClientKey` -- the key is neither a `Uint8Array` nor an object.
	/// - `InvalidSigningKey` -- the scalar is not 32 octets, or names no key.
	/// - `InvalidSigner` -- the signer's `signPrehash` is not a function.
	/// - `InvalidOid` -- the signer's `algorithmOid` is no object identifier.
	/// - `InvalidBudgets` -- a budget in `options.budgets` is no whole, non-negative number.
	/// - `InvalidAuthorization` -- `options.authorization` does not fit an `OCTET STRING`.
	/// - `InvalidApproveReceipt` -- `options.approveReceipt` is not a function.
	///
	/// The promise rejects with these:
	///
	/// - `InvalidCertificate` -- the client certificate is no DER certificate.
	/// - `Signer` -- the client certificate carries another key than the signer's, or the signer
	///   names another algorithm than the profile.
	/// - `InvalidUrl` -- the browser refuses to open a socket to `url`.
	/// - `ConnectionClosed` -- the socket closes before the handshake completes.
	/// - The [`TransportError`](tightbeam::transport::TransportError) variant of a failed
	///   handshake.
	/// - `InvalidState` -- the server does not negotiate multiplexing.
	/// - The abort reason of `options.signal`.
	#[wasm_bindgen(js_name = connectMutual, unchecked_return_type = "Promise<MuxWsClient>")]
	pub fn connect_mutual(
		url: &str,
		#[wasm_bindgen(unchecked_param_type = "MutualIdentity")] identity: JsValue,
		#[wasm_bindgen(unchecked_param_type = "MutualConnectOptions | undefined")] options: JsValue,
	) -> Result<Promise, JsFault> {
		let options = MutualDialOptions::try_from(&options)?;
		let identity = MutualIdentity::try_from(&identity)?;

		let (options, offer) = options.into_parts();
		let dial = Dial::Mutual { identity, offer };
		Ok(Self::dial(url, dial, options))
	}

	/// Dial `url` as `dial` describes, and resolve with the client once the
	/// handshake completes. Every argument is already read, so the future
	/// holds no reference to the caller's values.
	fn dial(url: &str, dial: Dial, options: DialOptions) -> Promise {
		let url = url.to_owned();

		future_to_promise(async move {
			let signal = options.signal();
			if let Some(reason) = signal.aborted_reason() {
				return Err(reason);
			}

			let (transport, opening) = dial.transport(&url, options.streams())?;
			let negotiated = Self::negotiate(transport);
			let (session, monitor) = opening.within(signal, negotiated).await?;

			let (parts, usable) = session;
			let client = Self::assemble(parts, monitor, usable);
			Ok(client.into())
		})
	}

	/// Send a DER-encoded tightbeam [`Frame`] on a fresh stream and resolve
	/// with the DER-encoded response frame, or `undefined` when the server
	/// returned no payload.
	///
	/// Concurrent calls interleave on the connection. Responses correlate
	/// by stream ID.
	#[wasm_bindgen(js_name = request, unchecked_return_type = "Promise<Uint8Array | undefined>")]
	pub fn request(&self, frame_der: JsBytes) -> Promise {
		let frame_der = frame_der.read();
		let connection = Rc::clone(&self.connection);

		future_to_promise(async move { Ok(connection.emit(frame_der?).await?) })
	}

	/// As [`request`](Self::request), racing the emit against `signal`.
	///
	/// An abort cancels the stream and rejects with the signal's abort reason.
	/// Timeouts compose as `AbortSignal.timeout(ms)`.
	#[wasm_bindgen(js_name = requestWithSignal, unchecked_return_type = "Promise<Uint8Array | undefined>")]
	pub fn request_with_signal(&self, frame_der: JsBytes, signal: AbortSignal) -> Promise {
		let frame_der = frame_der.read();
		let connection = Rc::clone(&self.connection);

		// Dropping the emit future is the cancellation: tightbeam frees
		// the stream and notifies the peer from the drop guard.
		future_to_promise(async move {
			let frame_der = frame_der?;
			let emitted = async { Ok(connection.emit(frame_der).await?) };
			let raced = signal.race(emitted).await;
			raced.outcome()
		})
	}

	/// Submit a signed end-to-end work frame to the servlet type addressed
	/// by `target` (`urn:<nid>:<nss>`) through a cluster gateway, and
	/// resolve with the DER of the servlet's complete response frame.
	///
	/// The work frame's DER bytes nest in the routing envelope untouched,
	/// so its signature stays verifiable at the servlet, and the returned
	/// bytes are the servlet's envelope with the same fidelity. A served
	/// work always carries a frame, so the promise always resolves with
	/// bytes. A gateway refusal rejects with code `WorkRefused` and the
	/// refusal's transit status name on `status`.
	#[wasm_bindgen(js_name = submitWork, unchecked_return_type = "Promise<Uint8Array>")]
	pub fn submit_work(&self, target: &str, work_frame_der: JsBytes) -> Promise {
		let work_frame_der = work_frame_der.read();
		let connection = Rc::clone(&self.connection);
		let target = target.to_owned();

		future_to_promise(async move { Ok(connection.submit_work(&target, work_frame_der?).await?) })
	}

	/// As [`submitWork`](Self::submit_work), racing the submission against
	/// `signal`.
	///
	/// An abort cancels the stream and rejects with the signal's abort reason.
	/// Timeouts compose as `AbortSignal.timeout(ms)`.
	#[wasm_bindgen(js_name = submitWorkWithSignal, unchecked_return_type = "Promise<Uint8Array>")]
	pub fn submit_work_with_signal(&self, target: &str, work_frame_der: JsBytes, signal: AbortSignal) -> Promise {
		let work_frame_der = work_frame_der.read();
		let connection = Rc::clone(&self.connection);
		let target = target.to_owned();

		// Dropping the submission future is the cancellation: tightbeam
		// frees the stream and notifies the peer from the drop guard.
		future_to_promise(async move {
			let work_frame_der = work_frame_der?;
			let submitted = async { Ok(connection.submit_work(&target, work_frame_der).await?) };
			let raced = signal.race(submitted).await;
			raced.outcome()
		})
	}

	/// Serve server-initiated streams with `handler`.
	///
	/// The handler receives the request frame DER as a `Uint8Array`, and
	/// returns or resolves with one of these:
	///
	/// - The response frame DER.
	/// - `undefined` or `null`, which accepts the stream without a body.
	/// - A rejection whose `code` names a gRPC canonical status (the client's
	///   `StreamRefusal`), which answers with that status.
	/// - Any other throw or rejection, which answers `Unknown`.
	///
	/// The call is repeatable. The latest handler serves every stream that
	/// dispatches after the call, and a stream in flight finishes on its own
	/// handler. Handlers for distinct streams run concurrently.
	///
	/// # Errors
	///
	/// The first `serve*` call starts the loop and picks its mode. Each later
	/// call refuses as [`claim`](Serving::claim) states.
	///
	/// - `ServeModeConflict` -- the loop serves another mode.
	/// - `ServeDispatchClaimed` -- an `exclusive` claim owns the dispatch.
	/// - `ServeDispatchShared` -- an `exclusive` claim meets a running shared handler.
	/// - `InvalidServeClaim` -- `claim` is neither `undefined`, `shared`, nor `exclusive`.
	#[wasm_bindgen(js_name = serve)]
	pub fn serve(
		&mut self,
		handler: Function,
		#[wasm_bindgen(unchecked_param_type = "ServeClaim | undefined")] claim: JsValue,
	) -> Result<(), JsFault> {
		let claim = Claim::try_from(&claim)?;
		self.serving.claim(ServeMode::Unary, handler, claim, &self.connection)
	}

	/// Progressive request body: push chunks, then close for a Frame reply.
	#[wasm_bindgen(js_name = openStream)]
	pub fn open_stream(&self) -> Result<MuxRequestStream, JsFault> {
		MuxRequestStream::open(Rc::clone(&self.connection))
	}

	/// Progressive request routed to a servlet URN (`urn:<nid>:<nss>`).
	///
	/// The Open carries the origin hop-budget sentinel so the first
	/// gateway applies its `max_hops` clamp.
	#[wasm_bindgen(js_name = openStreamTo)]
	pub fn open_stream_to(&self, target: &str) -> Result<MuxRequestStream, JsFault> {
		MuxRequestStream::open_to(Rc::clone(&self.connection), target)
	}

	/// Full-duplex body streaming on one stream id.
	///
	/// Pushes reach the wire eagerly, so awaiting a reply chunk
	/// between pushes (a chunk-for-chunk conversation) is sound.
	#[wasm_bindgen(js_name = openDuplex)]
	pub fn open_duplex(&self) -> Result<MuxDuplexStream, JsFault> {
		MuxDuplexStream::open(Rc::clone(&self.connection))
	}

	/// Duplex stream routed to a servlet URN (`urn:<nid>:<nss>`).
	///
	/// As [`open_stream_to`](Self::open_stream_to): the Open carries the
	/// origin hop-budget sentinel for the first gateway's `max_hops` clamp.
	#[wasm_bindgen(js_name = openDuplexTo)]
	pub fn open_duplex_to(&self, target: &str) -> Result<MuxDuplexStream, JsFault> {
		MuxDuplexStream::open_to(Rc::clone(&self.connection), target)
	}

	/// Serve peer streams as progressive bodies. The handler receives a
	/// [`MuxStreamBody`](crate::streaming::MuxStreamBody) and the Open's
	/// route (`{ target?, hopsRemaining }`), and returns a Frame DER (or
	/// `undefined`).
	///
	/// # Errors
	///
	/// - The errors of [`serve`](Self::serve).
	#[wasm_bindgen(js_name = serveStreaming)]
	pub fn serve_streaming(
		&mut self,
		handler: Function,
		#[wasm_bindgen(unchecked_param_type = "ServeClaim | undefined")] claim: JsValue,
	) -> Result<(), JsFault> {
		let claim = Claim::try_from(&claim)?;
		self.serving.claim(ServeMode::Streaming, handler, claim, &self.connection)
	}

	/// Serve peer streams as duplex bodies. The handler receives a
	/// [`MuxStreamBody`](crate::streaming::MuxStreamBody),
	/// [`MuxReplySink`](crate::streaming::MuxReplySink), and the Open's
	/// route, and resolves with a gRPC status name or `undefined` (`Ok`).
	///
	/// # Errors
	///
	/// - The errors of [`serve`](Self::serve).
	#[wasm_bindgen(js_name = serveDuplex)]
	pub fn serve_duplex(
		&mut self,
		handler: Function,
		#[wasm_bindgen(unchecked_param_type = "ServeClaim | undefined")] claim: JsValue,
	) -> Result<(), JsFault> {
		let claim = Claim::try_from(&claim)?;
		self.serving.claim(ServeMode::Duplex, handler, claim, &self.connection)
	}

	/// Connection-level liveness probe
	/// ([RFC 9113 § 6.7](https://datatracker.ietf.org/doc/html/rfc9113#section-6.7)
	/// analog): resolves when the peer's ack arrives.
	///
	/// No stream is allocated and the peer's application handler never
	/// runs. A client already pings on its own to hold an idle session
	/// open, so call this to measure the link.
	///
	/// `signal` composes deadlines: an abort rejects with the signal's
	/// abort reason and a late ack is ignored.
	#[wasm_bindgen(js_name = ping, unchecked_return_type = "Promise<void>")]
	pub fn ping(&self, signal: Option<AbortSignal>) -> Promise {
		let connection = Rc::clone(&self.connection);

		future_to_promise(async move {
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
	/// Rejects with `Draining` or `ConnectionClosed` once no stream will ever
	/// be admitted again, or with the abort reason of `signal` when the caller
	/// gives up first.
	#[wasm_bindgen(js_name = waitForStreamSlot, unchecked_return_type = "Promise<void>")]
	pub fn wait_for_stream_slot(&self, signal: Option<AbortSignal>) -> Promise {
		let connection = Rc::clone(&self.connection);
		future_to_promise(async move {
			let admitted = async move {
				connection.handle.wait_for_stream_slot().await.map_err(JsFault::from)?;
				Ok(JsValue::UNDEFINED)
			};

			let raced = signal.race(admitted).await;
			raced.outcome()
		})
	}

	/// Reason carried by the peer's GoAway, or `undefined` while the
	/// connection is live or was shut down locally.
	///
	/// Reconnect policies branch on this: `shutdown` invites an immediate
	/// reconnect, `enhance-your-calm` calls for backoff, and `protocol-error`
	/// points at a bug rather than a transient fault.
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
	/// `reason` is a label or a numeric code. Codes outside the reserved
	/// range are application-defined. The label `"application"` alone
	/// carries no code and is rejected.
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
		self.usable_send_budget.map(|credits| credits as f64)
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

	/// Handshake with the mux offer the transport holds, split, and spawn the
	/// driver pumps. Resolves with the split parts and the usable send budget
	/// the handshake negotiated.
	async fn negotiate(
		mut transport: WsTransport,
	) -> Result<((MuxHandle, MuxResponder, MuxTasks), Option<u64>), JsValue> {
		transport.perform_client_handshake().await.map_err(JsFault::from)?;

		let usable = transport.negotiated_mux().and_then(|settings| settings.usable_send_budget());
		let parts = transport.split().map_err(JsFault::from)?;
		Ok((parts, usable))
	}

	/// Assemble a client over the split `parts` and the socket that `monitor`
	/// observes. Its responder waits for the first `serve*` call.
	fn assemble(
		parts: (MuxHandle, MuxResponder, MuxTasks),
		monitor: SocketMonitor,
		usable_send_budget: Option<u64>,
	) -> Self {
		let (handle, responder, tasks) = parts;
		let connection = Rc::new(Connection { handle, monitor, _tasks: tasks });
		let serving = Serving::Idle(responder);

		Self { connection, serving, usable_send_budget }
	}
}

#[cfg(test)]
mod tests {
	use futures_util::future::ready;
	use futures_util::FutureExt;
	use js_sys::{Function, Object, Promise, Reflect, Uint8Array};
	use tightbeam::transport::handshake::negotiation::MuxSettings;
	use tightbeam::transport::multiplex::{MuxHandle, MuxRole, MuxTransport};
	use tightbeam::transport::{TransportError, TransportResult};
	use wasm_bindgen::{JsCast, JsValue};
	use wasm_bindgen_futures::JsFuture;
	use wasm_bindgen_test::wasm_bindgen_test;
	use web_sys::AbortSignal;

	use super::{BrowserMux, MuxWsClient};
	use crate::fault::Refused;
	use crate::promise::JsBytes;
	use crate::protocol::BrowserSocket;
	use crate::socket::tests::UNREACHED_URL;
	use crate::socket::{OpeningSocket, SocketMonitor};
	use crate::stream::{GlooStream, WsTransport};
	use crate::streaming::MuxRequestStream;

	/// The readyState of a socket that is still connecting.
	const CONNECTING: u16 = 0;

	/// The readyState of a socket whose close has begun.
	const CLOSING: u16 = 2;

	/// The monitor that `opening` hands over for a step that settles at once
	/// under no signal.
	fn monitor_of(opening: OpeningSocket) -> SocketMonitor {
		let no_signal: Option<AbortSignal> = None;
		let step = ready(Ok::<(), JsValue>(()));
		let settled = opening.within(&no_signal, step).now_or_never();

		let ready_step = settled.expect("a race under no signal settles at once");
		let ((), monitor) = ready_step.expect("a ready step settles Ok");
		monitor
	}

	/// A cleartext client over a socket that is still connecting, the monitor
	/// of that socket, and a handle that holds no part of the connection.
	fn connecting_client() -> (MuxWsClient, SocketMonitor, MuxHandle) {
		let (opening, carrier) = OpeningSocket::open(UNREACHED_URL).expect("the socket should construct");
		let monitor = monitor_of(opening);
		let stream = GlooStream::from(carrier);
		let provisioned: TransportResult<WsTransport> = BrowserSocket::cleartext(stream);
		let transport = provisioned.expect("the cleartext transport should provision");
		let (reader, writer) = transport.into_split().expect("the transport should split");

		let mux = MuxTransport::new(reader, writer, MuxRole::Client, MuxSettings::symmetric(1));
		let (handle, responder, tasks) = mux.split().expect("the mux should split");
		let probe = handle.clone();
		let client = MuxWsClient::assemble((handle, responder, tasks), monitor.clone(), None);

		(client, monitor, probe)
	}

	/// A progressive request stream on `client`.
	fn open_stream(client: &MuxWsClient) -> MuxRequestStream {
		client.open_stream().expect("a client with headroom should open a stream")
	}

	/// A serve handler that accepts each stream without a body.
	fn accepting() -> Function {
		Function::new_no_args("return undefined")
	}

	/// The exclusive serve claim, as JavaScript passes it.
	fn exclusive() -> JsValue {
		JsValue::from_str("exclusive")
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
		let certificate = Uint8Array::from([0x30u8].as_slice());
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

	/// The code each connector throws for the options `{ [field]: value }`, in
	/// the order connect, connectMutual, connectCleartext.
	fn dial_codes(value: f64) -> [Option<String>; 3] {
		let server = MuxWsClient::connect(UNREACHED_URL, bytes(&[0x30]), options("maxPeerStreams", value.into()));
		let mutual = MuxWsClient::connect_mutual(UNREACHED_URL, identity(), options("maxPeerStreams", value.into()));
		let cleartext = MuxWsClient::connect_cleartext(UNREACHED_URL, options("streams", value.into()));

		[server.code(), mutual.code(), cleartext.code()]
	}

	/// `octets` as a JavaScript byte parameter.
	fn bytes(octets: &[u8]) -> JsBytes {
		Uint8Array::from(octets).unchecked_into()
	}

	/// Start the unary serve loop of `client` with a handler that accepts each
	/// stream without a body.
	fn serve(client: &mut MuxWsClient) {
		let handler = accepting();
		let served = client.serve(handler, JsValue::UNDEFINED);
		served.expect("an idle client should start its serve loop");
	}

	/// Let every task that a wake queued run once. The wait stays on the
	/// microtask queue, so no socket event arrives in it.
	async fn next_tick() {
		let resolved = Promise::resolve(&JsValue::UNDEFINED);
		let _ = JsFuture::from(resolved).await;
	}

	#[wasm_bindgen_test]
	fn a_freed_client_closes_its_socket() {
		let (client, monitor, _probe) = connecting_client();
		drop(client);
		assert_eq!(monitor.ready_state(), CLOSING);
	}

	#[wasm_bindgen_test]
	fn a_freed_serving_client_keeps_its_socket() {
		let (mut client, monitor, _probe) = connecting_client();
		serve(&mut client);
		drop(client);
		assert_eq!(monitor.ready_state(), CONNECTING);
		monitor.close();
	}

	#[wasm_bindgen_test]
	fn a_closed_serving_client_closes_its_socket() {
		let (mut client, monitor, _probe) = connecting_client();
		serve(&mut client);
		client.close();
		assert_eq!(monitor.ready_state(), CLOSING);
	}

	#[wasm_bindgen_test]
	async fn a_freed_client_ends_its_tasks() {
		let (client, _monitor, probe) = connecting_client();
		drop(client);

		next_tick().await;
		let opened = probe.open_stream();
		assert!(matches!(opened, Err(TransportError::ConnectionClosed)));
	}

	#[wasm_bindgen_test]
	async fn a_live_stream_keeps_the_socket_of_a_freed_client() {
		let (client, monitor, _probe) = connecting_client();
		let stream = open_stream(&client);
		drop(client);

		let chunk = Uint8Array::from([1u8].as_slice());
		let pushed = JsFuture::from(stream.push(chunk.unchecked_into())).await;
		assert!(pushed.is_ok());
		assert_eq!(monitor.ready_state(), CONNECTING);
	}

	#[wasm_bindgen_test]
	fn the_last_stream_of_a_freed_client_closes_its_socket() {
		let (client, monitor, _probe) = connecting_client();
		let stream = open_stream(&client);
		drop(client);
		drop(stream);
		assert_eq!(monitor.ready_state(), CLOSING);
	}

	#[wasm_bindgen_test]
	fn an_exclusive_claim_refuses_a_later_serve() {
		let (mut client, _monitor, _probe) = connecting_client();
		let _claimed = client.serve(accepting(), exclusive());

		let later = client.serve(accepting(), JsValue::UNDEFINED);
		assert_eq!(later.code().as_deref(), Some("ServeDispatchClaimed"));
	}

	#[wasm_bindgen_test]
	fn an_exclusive_claim_refuses_another_mode() {
		let (mut client, _monitor, _probe) = connecting_client();
		let _claimed = client.serve(accepting(), exclusive());

		let later = client.serve_streaming(accepting(), JsValue::UNDEFINED);
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

		let later = client.serve(accepting(), JsValue::UNDEFINED);
		assert!(later.is_ok());
	}

	#[wasm_bindgen_test]
	fn a_claim_in_another_mode_conflicts() {
		let (mut client, _monitor, _probe) = connecting_client();
		serve(&mut client);

		let later = client.serve_streaming(accepting(), JsValue::UNDEFINED);
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
	fn a_server_dial_refuses_a_session_knob() {
		let authorization = Uint8Array::from([1u8].as_slice());
		let server = MuxWsClient::connect(
			UNREACHED_URL,
			bytes(&[0x30]),
			options("authorization", authorization.clone().into()),
		);

		let cleartext = MuxWsClient::connect_cleartext(UNREACHED_URL, options("authorization", authorization.into()));
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
		let unary = client.serve(accepting(), JsValue::TRUE).code();
		let streaming = client.serve_streaming(accepting(), JsValue::from_str("Exclusive")).code();
		let duplex = client.serve_duplex(accepting(), JsValue::from_f64(1.0)).code();

		let codes = [unary.as_deref(), streaming.as_deref(), duplex.as_deref()];
		assert_eq!(codes, [Some("InvalidServeClaim"); 3]);
	}
}
