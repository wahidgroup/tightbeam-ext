//! Multiplexed browser WebSocket client. Compiled only for `wasm32`
//! targets.
//!
//! Splits the connection into exclusive halves and spawns tightbeam's
//! [`MuxTransport`] driver on the browser microtask executor. The resulting
//! client emits concurrent requests and serves peer-initiated streams over one
//! connection. Encrypted sessions negotiate HTTP/2-style stream multiplexing
//! during the ECIES handshake. Cleartext sessions have no handshake, so both
//! endpoints configure the same symmetric cap.

use core::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use js_sys::{Function, Promise, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{future_to_promise, spawn_local, JsFuture};

use web_sys::AbortSignal;

use tightbeam::der::asn1::OctetString;
use tightbeam::der::{Decode, Encode};
use tightbeam::policy::TransitStatus;
use tightbeam::transport::envelopes::GoAwayReason;
use tightbeam::transport::handshake::negotiation::{MuxBudgets, MuxSettings, TransportOffer};
use tightbeam::transport::handshake::receipt::ReceiptApprover;
use tightbeam::transport::multiplex::{MultiplexedProtocol, MuxHandle, MuxResponder, MuxRole, MuxTransport};
use tightbeam::transport::{EncryptedMessageIO, EnvelopeSink, EnvelopeSource, ResponsePackage, X509ClientConfig};
use tightbeam::Frame;

use crate::approver::{approver_from_js, authorization_from_js, budgets_from_js};
use crate::fault::{to_js, transport_to_js, validation};
use crate::promise::{bytes_or_undefined, race_abort, race_optional_abort};
use crate::secure::{build_signer_transport, build_transport, response_der, ClientIdentity};
use crate::signer::TransportSigner;
use crate::socket::{open_observed, SocketMonitor};
use crate::stream::{GlooStream, WsTransport};
use crate::streaming::{start_serve_duplex, start_serve_streaming, MuxDuplexStream, MuxRequestStream};

/// Peer-serve dispatch shape claimed by the first `serve*` call.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ServeMode {
	Unary,
	Streaming,
	Duplex,
}

/// Optional budget / settlement knobs for a mutual-auth dial.
struct SessionOffer {
	budgets: Option<MuxBudgets>,
	authorization: Option<OctetString>,
	approver: Option<Arc<dyn ReceiptApprover>>,
}

impl SessionOffer {
	fn from_js(value: &JsValue) -> Result<Self, JsValue> {
		if value.is_undefined() || value.is_null() {
			return Ok(Self { budgets: None, authorization: None, approver: None });
		}

		let budgets = budgets_from_js(&Reflect::get(value, &JsValue::from_str("budgets"))?)?;
		let authorization = authorization_from_js(&Reflect::get(value, &JsValue::from_str("authorization"))?)?;
		let approver = approver_from_js(&Reflect::get(value, &JsValue::from_str("approveReceipt"))?)?;

		Ok(Self { budgets, authorization, approver })
	}

	fn into_offer(self, max_peer_streams: u32) -> (TransportOffer, Option<Arc<dyn ReceiptApprover>>) {
		let mut offer = TransportOffer::mux(max_peer_streams);
		if let Some(budgets) = self.budgets {
			offer = offer.with_budgets(budgets);
		}
		if let Some(token) = self.authorization {
			offer = offer.with_authorization(token);
		}

		(offer, self.approver)
	}
}

/// TypeScript shape of the goaway reason getter.
#[wasm_bindgen(typescript_custom_section)]
const GOAWAY_REASON_TS: &'static str = r#"
/**
 * Reason carried by the peer's GoAway (RFC 9113 § 6.8 analog).
 *
 * "Application" is a code outside the protocol-reserved range. Read the
 * raw value from `goawayCode`.
 *
 * # Sources
 *
 * - RFC 9113 § 6.8, GOAWAY frame:
 *   <https://datatracker.ietf.org/doc/html/rfc9113#section-6.8>
 */
export type GoAwayReason =
	| "Shutdown"
	| "ProtocolError"
	| "EnhanceYourCalm"
	| "BudgetExhausted"
	| "SettlementFailed"
	| "Application";

/**
 * Optional budget / settlement knobs for mutual-auth dials.
 */
export interface SessionOffer {
	budgets?: { clientToServer: number; serverToClient: number };
	authorization?: Uint8Array;
	approveReceipt?: (input: {
		receiptDer: Uint8Array;
		challenge?: Uint8Array;
	}) => Uint8Array | undefined | Promise<Uint8Array | undefined>;
}
"#;

/// The JS label for a [`GoAwayReason`].
fn goaway_label(reason: GoAwayReason) -> String {
	let label = match reason {
		GoAwayReason::Shutdown => "Shutdown",
		GoAwayReason::ProtocolError => "ProtocolError",
		GoAwayReason::EnhanceYourCalm => "EnhanceYourCalm",
		GoAwayReason::BudgetExhausted => "BudgetExhausted",
		GoAwayReason::SettlementFailed => "SettlementFailed",
		GoAwayReason::Application(_) => "Application",
	};

	label.to_owned()
}

/// A multiplexed tightbeam client over a single browser WebSocket session.
///
/// Concurrent unary [`request`](Self::request) calls share the connection.
/// Progressive bodies use [`open_stream`](Self::open_stream) /
/// [`open_stream_to`](Self::open_stream_to) and duplex
/// [`open_duplex`](Self::open_duplex) / [`open_duplex_to`](Self::open_duplex_to).
/// Peer-initiated work is answered by [`serve`](Self::serve),
/// [`serve_streaming`](Self::serve_streaming), or
/// [`serve_duplex`](Self::serve_duplex) (mutually exclusive on first claim).
///
/// Async operations run on cloned handles instead of borrowing the wasm
/// object: `free()` is safe with requests in flight, which then settle
/// with `ConnectionClosed` once the socket closes.
#[wasm_bindgen]
pub struct MuxWsClient {
	handle: MuxHandle,
	responder: Option<MuxResponder>,
	handler: Rc<RefCell<Function>>,
	monitor: SocketMonitor,
	/// First-chosen peer-serve mode. Same-mode handler swaps stay allowed.
	serve_mode: Option<ServeMode>,
	/// Usable outbound credits for this epoch (`None` = unmetered).
	usable_send_budget: Option<u64>,
}

#[wasm_bindgen]
impl MuxWsClient {
	/// Open a server-authenticated multiplexed session to `url`, pinning
	/// `server_cert_der` as the sole trusted server certificate.
	///
	/// `max_peer_streams` is the concurrency cap this client grants the
	/// server for server-initiated streams. The server's own advertisement
	/// caps this client's concurrent requests. Rejects when the server does
	/// not negotiate multiplexing.
	///
	/// `signal` aborts the dial and handshake: the socket closes and the
	/// promise rejects with the signal's abort reason.
	#[wasm_bindgen(js_name = connect)]
	pub async fn connect(
		url: &str,
		server_cert_der: &[u8],
		max_peer_streams: u32,
		signal: Option<AbortSignal>,
	) -> Result<MuxWsClient, JsValue> {
		if let Some(reason) = abort_reason(&signal) {
			return Err(reason);
		}

		let (transport, monitor) = build_transport(url, server_cert_der, None)?;
		Self::establish(
			transport,
			monitor,
			max_peer_streams,
			signal,
			SessionOffer { budgets: None, authorization: None, approver: None },
		)
		.await
	}

	/// Open a cleartext multiplexed session to `url`. Resolves once the
	/// socket is open, so a failed dial rejects here (`ConnectionClosed`)
	/// rather than on the first emit.
	///
	/// Cleartext multiplexing has no handshake negotiation: `streams` is a
	/// symmetric concurrency cap and both endpoints MUST configure the
	/// same value, or their enforcement diverges. The connection carries
	/// NO confidentiality or integrity protection.
	///
	/// `signal` aborts the dial: the socket closes and the promise
	/// rejects with the signal's abort reason.
	#[wasm_bindgen(js_name = connectCleartext)]
	pub async fn connect_cleartext(
		url: &str,
		streams: u32,
		signal: Option<AbortSignal>,
	) -> Result<MuxWsClient, JsValue> {
		if let Some(reason) = abort_reason(&signal) {
			return Err(reason);
		}

		let observed = open_observed(url)?;
		Self::await_open(&observed.monitor, signal).await?;

		let transport = GlooStream::from(observed.socket).into_transport();
		let (reader, writer) = transport.into_split_cleartext().map_err(transport_to_js)?;
		let mux = MuxTransport::new(reader, writer, MuxRole::Client, MuxSettings::symmetric(streams));
		let (handle, responder) = spawn_mux(mux);

		Ok(Self::assemble(handle, responder, observed.monitor, None))
	}

	/// Wait for a dial to complete, racing `signal` when given: an abort
	/// closes the socket and yields the signal's abort reason.
	async fn await_open(monitor: &SocketMonitor, signal: Option<AbortSignal>) -> Result<(), JsValue> {
		let opening = async {
			JsFuture::from(monitor.opened()).await?;
			Ok(())
		};

		let Some(signal) = signal else {
			return opening.await;
		};

		let outcome = race_abort(&signal, opening).await;
		if signal.aborted() {
			monitor.close();
		}

		outcome
	}

	/// As [`connect`](Self::connect), additionally presenting
	/// `client_cert_der` and the raw 32-byte secp256k1 `client_signing_key`
	/// for mutual authentication.
	#[wasm_bindgen(js_name = connectMutual)]
	pub async fn connect_mutual(
		url: &str,
		server_cert_der: &[u8],
		client_cert_der: &[u8],
		client_signing_key: &[u8],
		max_peer_streams: u32,
		signal: Option<AbortSignal>,
		#[wasm_bindgen(unchecked_param_type = "SessionOffer | undefined")] session: JsValue,
	) -> Result<MuxWsClient, JsValue> {
		if let Some(reason) = abort_reason(&signal) {
			return Err(reason);
		}

		let identity = ClientIdentity { cert_der: client_cert_der, signing_key: client_signing_key };
		let (transport, monitor) = build_transport(url, server_cert_der, Some(identity))?;
		let session = SessionOffer::from_js(&session)?;

		Self::establish(transport, monitor, max_peer_streams, signal, session).await
	}

	/// As [`connectMutual`](Self::connect_mutual), but proving possession
	/// through an external `signer` (WebAuthn, wallet, KMS bridge) instead
	/// of raw key bytes: the key never crosses into wasm.
	#[wasm_bindgen(js_name = connectMutualWithSigner)]
	pub async fn connect_mutual_with_signer(
		url: &str,
		server_cert_der: &[u8],
		client_cert_der: &[u8],
		signer: TransportSigner,
		max_peer_streams: u32,
		signal: Option<AbortSignal>,
		#[wasm_bindgen(unchecked_param_type = "SessionOffer | undefined")] session: JsValue,
	) -> Result<MuxWsClient, JsValue> {
		if let Some(reason) = abort_reason(&signal) {
			return Err(reason);
		}

		let (transport, monitor) = build_signer_transport(url, server_cert_der, client_cert_der, signer)?;
		let session = SessionOffer::from_js(&session)?;
		Self::establish(transport, monitor, max_peer_streams, signal, session).await
	}

	/// Send a DER-encoded tightbeam [`Frame`] on a fresh stream and resolve
	/// with the DER-encoded response frame, or `undefined` when the server
	/// returned no payload.
	///
	/// Concurrent calls interleave on the connection. Responses correlate
	/// by stream ID.
	#[wasm_bindgen(js_name = request, unchecked_return_type = "Promise<Uint8Array | undefined>")]
	pub fn request(&self, frame_der: Vec<u8>) -> Promise {
		let handle = self.handle.clone();
		future_to_promise(async move { run_stream_emit(handle, frame_der).await })
	}

	/// As [`request`](Self::request), racing the emit against `signal`.
	///
	/// An abort cancels the stream and rejects with the signal's abort reason.
	/// Timeouts compose as `AbortSignal.timeout(ms)`.
	#[wasm_bindgen(js_name = requestWithSignal, unchecked_return_type = "Promise<Uint8Array | undefined>")]
	pub fn request_with_signal(&self, frame_der: Vec<u8>, signal: AbortSignal) -> Promise {
		let handle = self.handle.clone();

		// Dropping the emit future is the cancellation: tightbeam frees
		// the stream and notifies the peer from the drop guard.
		future_to_promise(async move { race_abort(&signal, run_stream_emit(handle, frame_der)).await })
	}

	/// Serve server-initiated streams with `handler`.
	///
	/// The handler receives the request frame DER as a `Uint8Array` and
	/// returns (or resolves with) the response frame DER, or `undefined`/`null`
	/// for a bodiless acceptance. A rejection whose `code` names a gRPC
	/// canonical status (the client's `StreamRefusal`) answers the stream with
	/// that status. Any other throwing or rejecting handler answers `Unknown`.
	///
	/// Callable repeatedly. The latest handler serves every stream dispatched
	/// after the call, and streams already in flight finish on the handler they
	/// started with. Handlers for distinct streams run concurrently.
	///
	/// Mutually exclusive with [`serveStreaming`](Self::serve_streaming) and
	/// [`serveDuplex`](Self::serve_duplex): the first call consumes the
	/// responder. A later call in a different mode rejects with
	/// `ServeModeConflict`.
	#[wasm_bindgen(js_name = serve)]
	pub fn serve(&mut self, handler: Function) -> Result<(), JsValue> {
		self.claim_serve(ServeMode::Unary)?;
		self.handler.replace(handler);

		// The first call starts the serve loop
		if let Some(responder) = self.responder.take() {
			let slot = Rc::clone(&self.handler);
			spawn_local(async move {
				// The serve loop ends with the connection. Its terminal
				// status already reached the peer (GoAway), so nothing is
				// left to report.
				let _ = responder.serve(move |frame| respond_via_js(slot.borrow().clone(), frame)).await;
			});
		}

		Ok(())
	}

	/// Progressive request body: push chunks, then close for a Frame reply.
	#[wasm_bindgen(js_name = openStream)]
	pub fn open_stream(&self) -> Result<MuxRequestStream, JsValue> {
		MuxRequestStream::open(&self.handle)
	}

	/// Progressive request routed to a servlet URN (`urn:<nid>:<nss>`).
	///
	/// The Open carries the origin hop-budget sentinel so the first
	/// gateway applies its `max_hops` clamp.
	#[wasm_bindgen(js_name = openStreamTo)]
	pub fn open_stream_to(&self, target: &str) -> Result<MuxRequestStream, JsValue> {
		MuxRequestStream::open_to(&self.handle, target)
	}

	/// Full-duplex body streaming on one stream id.
	///
	/// Pushes reach the wire eagerly, so awaiting a reply chunk
	/// between pushes (a chunk-for-chunk conversation) is sound.
	#[wasm_bindgen(js_name = openDuplex)]
	pub fn open_duplex(&self) -> Result<MuxDuplexStream, JsValue> {
		MuxDuplexStream::open(&self.handle)
	}

	/// Duplex stream routed to a servlet URN (`urn:<nid>:<nss>`).
	///
	/// As [`open_stream_to`](Self::open_stream_to): the Open carries the
	/// origin hop-budget sentinel for the first gateway's `max_hops` clamp.
	#[wasm_bindgen(js_name = openDuplexTo)]
	pub fn open_duplex_to(&self, target: &str) -> Result<MuxDuplexStream, JsValue> {
		MuxDuplexStream::open_to(&self.handle, target)
	}

	/// Serve peer streams as progressive bodies. The handler receives a
	/// [`MuxStreamBody`](crate::streaming::MuxStreamBody) and the Open's
	/// route (`{ target?, hopsRemaining }`), and returns a Frame DER
	/// (or `undefined`). Consumes the responder on first call. A later
	/// call in a different mode rejects with `ServeModeConflict`.
	#[wasm_bindgen(js_name = serveStreaming)]
	pub fn serve_streaming(&mut self, handler: Function) -> Result<(), JsValue> {
		self.claim_serve(ServeMode::Streaming)?;
		self.handler.replace(handler);

		if let Some(responder) = self.responder.take() {
			start_serve_streaming(responder, Rc::clone(&self.handler));
		}

		Ok(())
	}

	/// Serve peer streams as duplex bodies. The handler receives a
	/// [`MuxStreamBody`](crate::streaming::MuxStreamBody),
	/// [`MuxReplySink`](crate::streaming::MuxReplySink), and the Open's
	/// route, and resolves with a gRPC status name or `undefined` (`Ok`).
	/// Consumes the responder. A later call in a different mode rejects
	/// with `ServeModeConflict`.
	#[wasm_bindgen(js_name = serveDuplex)]
	pub fn serve_duplex(&mut self, handler: Function) -> Result<(), JsValue> {
		self.claim_serve(ServeMode::Duplex)?;
		self.handler.replace(handler);

		if let Some(responder) = self.responder.take() {
			start_serve_duplex(responder, Rc::clone(&self.handler));
		}

		Ok(())
	}

	/// Connection-level liveness probe
	/// ([RFC 9113 § 6.7](https://datatracker.ietf.org/doc/html/rfc9113#section-6.7)
	/// analog): resolves when the peer's ack arrives.
	///
	/// No stream is allocated and the peer's application handler never
	/// runs, so this doubles as an idle keepalive for links whose carrier
	/// cannot ping itself (a browser WebSocket).
	///
	/// `signal` composes deadlines: an abort rejects with the signal's
	/// abort reason and a late ack is ignored.
	#[wasm_bindgen(js_name = ping, unchecked_return_type = "Promise<void>")]
	pub fn ping(&self, signal: Option<AbortSignal>) -> Promise {
		let handle = self.handle.clone();

		future_to_promise(async move {
			let ping = async move {
				handle.ping().await.map_err(transport_to_js)?;
				Ok(JsValue::UNDEFINED)
			};

			race_optional_abort(signal, ping).await
		})
	}

	/// Whether a new locally-initiated stream would be admitted now.
	///
	/// Advisory: a concurrent emit can take the last slot after this
	/// returns, so callers still handle the `StreamsExhausted` rejection.
	#[wasm_bindgen(getter, js_name = hasStreamHeadroom)]
	pub fn has_stream_headroom(&self) -> bool {
		self.handle.has_stream_headroom()
	}

	/// Whether any locally-initiated stream still awaits its response.
	///
	/// Advisory like [`hasStreamHeadroom`](Self::has_stream_headroom): a
	/// pre-close check, not a synchronization primitive.
	#[wasm_bindgen(getter, js_name = hasPendingStreams)]
	pub fn has_pending_streams(&self) -> bool {
		self.handle.has_pending_streams()
	}

	/// Resolves once a new locally-initiated stream would be admitted.
	/// Replaces polling `hasStreamHeadroom` in a loop, with the same
	/// advisory caveat.
	///
	/// Rejects with `Draining` once no stream will ever be admitted again,
	/// or with the abort reason of `signal` when the caller gives up first.
	#[wasm_bindgen(js_name = waitForStreamSlot, unchecked_return_type = "Promise<void>")]
	pub fn wait_for_stream_slot(&self, signal: Option<AbortSignal>) -> Promise {
		let handle = self.handle.clone();
		future_to_promise(async move {
			let admitted = async move {
				handle.wait_for_stream_slot().await.map_err(transport_to_js)?;
				Ok(JsValue::UNDEFINED)
			};

			race_optional_abort(signal, admitted).await
		})
	}

	/// Reason carried by the peer's GoAway, or `undefined` while the
	/// connection is live or was shut down locally.
	///
	/// Reconnect policies branch on this: `Shutdown` invites an immediate
	/// reconnect, `EnhanceYourCalm` calls for backoff, and `ProtocolError`
	/// points at a bug rather than a transient fault.
	#[wasm_bindgen(getter, js_name = goawayReason, unchecked_return_type = "GoAwayReason | undefined")]
	pub fn goaway_reason(&self) -> Option<String> {
		self.handle.goaway_reason().map(goaway_label)
	}

	/// Numeric code behind [`goawayReason`](Self::goaway_reason), or
	/// `undefined` when that getter is `undefined`. Distinguishes
	/// application-defined codes that all label as `"Application"`.
	#[wasm_bindgen(getter, js_name = goawayCode)]
	pub fn goaway_code(&self) -> Option<u32> {
		self.handle.goaway_reason().map(u32::from)
	}

	/// Gracefully shut the connection down: sends GoAway, lets in-flight
	/// streams drain, then stops the writer.
	#[wasm_bindgen(js_name = shutdown, unchecked_return_type = "Promise<void>")]
	pub fn shutdown(&self) -> Promise {
		let handle = self.handle.clone();

		future_to_promise(async move {
			handle.shutdown().await.map_err(transport_to_js)?;
			Ok(JsValue::UNDEFINED)
		})
	}

	/// As [`shutdown`](Self::shutdown), advertising `reason` in the GoAway
	/// so the peer's reconnect policy can branch on it.
	///
	/// `reason` is a label or a numeric code. Codes outside the reserved
	/// range are application-defined. The label `"Application"` alone
	/// carries no code and is rejected.
	#[wasm_bindgen(js_name = shutdownWith, unchecked_return_type = "Promise<void>")]
	pub fn shutdown_with(
		&self,
		#[wasm_bindgen(unchecked_param_type = "GoAwayReason | number")] reason: JsValue,
	) -> Promise {
		let handle = self.handle.clone();

		future_to_promise(async move {
			let reason = reason_from_js(&reason)?;
			handle.shutdown_with(reason).await.map_err(transport_to_js)?;
			Ok(JsValue::UNDEFINED)
		})
	}

	/// The negotiated cap on concurrent locally-initiated streams.
	#[wasm_bindgen(getter, js_name = maxConcurrentStreams)]
	pub fn max_concurrent_streams(&self) -> u32 {
		self.handle.max_concurrent_streams()
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
		let stored = self.handle.session_receipt()?;
		let der = stored.to_der().ok()?;
		Some(Uint8Array::from(der.as_slice()))
	}

	/// A promise resolving with a `SocketCloseInfo` when the socket closes.
	#[wasm_bindgen(getter, js_name = closed, unchecked_return_type = "Promise<SocketCloseInfo>")]
	pub fn closed(&self) -> Promise {
		self.monitor.closed()
	}

	/// The socket's readyState (0 CONNECTING, 1 OPEN, 2 CLOSING, 3 CLOSED).
	#[wasm_bindgen(getter, js_name = readyState)]
	pub fn ready_state(&self) -> u16 {
		self.monitor.ready_state()
	}

	/// Close the underlying socket without a graceful drain (see
	/// [`shutdown`](Self::shutdown)). The `closed` promise resolves once
	/// the close completes.
	#[wasm_bindgen(js_name = close)]
	pub fn close(&self) {
		self.monitor.close();
	}

	/// Handshake with the mux offer, split, and spawn the driver pumps,
	/// racing the whole establishment against `signal` when one is given.
	async fn establish(
		transport: WsTransport,
		monitor: SocketMonitor,
		max_peer_streams: u32,
		signal: Option<AbortSignal>,
		session: SessionOffer,
	) -> Result<MuxWsClient, JsValue> {
		let Some(signal) = signal else {
			return Self::negotiate(transport, monitor, max_peer_streams, session).await;
		};

		let negotiated = Self::negotiate(transport, monitor.clone(), max_peer_streams, session);
		let outcome = race_abort(&signal, negotiated).await;
		if signal.aborted() {
			monitor.close();
		}

		outcome
	}

	/// Handshake with the mux offer, split, and spawn the driver pumps.
	async fn negotiate(
		mut transport: WsTransport,
		monitor: SocketMonitor,
		max_peer_streams: u32,
		session: SessionOffer,
	) -> Result<MuxWsClient, JsValue> {
		let (offer, approver) = session.into_offer(max_peer_streams);
		transport = transport.with_mux_offer(Some(offer));
		if let Some(approver) = approver {
			transport = transport.with_receipt_approver(approver);
		}
		transport.perform_client_handshake().await.map_err(transport_to_js)?;

		let settings = transport
			.negotiated_mux()
			.ok_or_else(|| JsValue::from_str("the server did not negotiate multiplexing"))?;
		let usable = settings.usable_send_budget();
		let (handle, responder) = split_mux(transport)?;
		Ok(Self::assemble(handle, responder, monitor, usable))
	}

	/// Assemble a client with an inert handler slot. The slot is only
	/// read by the serve loop, which [`serve`](Self::serve) fills before
	/// spawning.
	fn assemble(
		handle: MuxHandle,
		responder: MuxResponder,
		monitor: SocketMonitor,
		usable_send_budget: Option<u64>,
	) -> Self {
		let inert = Function::new_no_args("");
		Self {
			handle,
			responder: Some(responder),
			handler: Rc::new(RefCell::new(inert)),
			monitor,
			serve_mode: None,
			usable_send_budget,
		}
	}

	/// Record `mode` as the peer-serve mode, or reject a cross-mode swap.
	fn claim_serve(&mut self, mode: ServeMode) -> Result<(), JsValue> {
		match self.serve_mode {
			None => {
				self.serve_mode = Some(mode);
				Ok(())
			}
			Some(current) if current == mode => Ok(()),
			Some(current) => Err(validation(
				"ServeModeConflict",
				&format!(
					"peer serve mode is {}. Cannot switch to {} after the responder started",
					serve_mode_label(current),
					serve_mode_label(mode),
				),
			)),
		}
	}
}

/// Stable label for [`ServeMode`] in error messages.
fn serve_mode_label(mode: ServeMode) -> &'static str {
	match mode {
		ServeMode::Unary => "unary",
		ServeMode::Streaming => "streaming",
		ServeMode::Duplex => "duplex",
	}
}

/// Parse a JavaScript GoAway reason: a label for the reserved variants,
/// or a numeric code (application-defined outside the reserved range).
fn reason_from_js(value: &JsValue) -> Result<GoAwayReason, JsValue> {
	if let Some(code) = value.as_f64() {
		if code.fract() != 0.0 || !(0.0..=f64::from(u32::MAX)).contains(&code) {
			return Err(JsValue::from_str("a numeric GoAway reason must be a u32 code"));
		}

		return Ok(GoAwayReason::from(code as u32));
	}

	match value.as_string().as_deref() {
		Some("Shutdown") => Ok(GoAwayReason::Shutdown),
		Some("ProtocolError") => Ok(GoAwayReason::ProtocolError),
		Some("EnhanceYourCalm") => Ok(GoAwayReason::EnhanceYourCalm),
		Some("BudgetExhausted") => Ok(GoAwayReason::BudgetExhausted),
		Some("SettlementFailed") => Ok(GoAwayReason::SettlementFailed),
		_ => Err(JsValue::from_str(
			"a GoAway reason is \"Shutdown\", \"ProtocolError\", \"EnhanceYourCalm\", \"BudgetExhausted\", \"SettlementFailed\", or a numeric code",
		)),
	}
}

/// The abort reason of an already-aborted optional signal.
fn abort_reason(signal: &Option<AbortSignal>) -> Option<JsValue> {
	let signal = signal.as_ref()?;
	if signal.aborted() {
		return Some(signal.reason());
	}

	None
}

/// Emit `frame_der` on a fresh stream and encode the optional response
/// for JavaScript.
async fn run_stream_emit(handle: MuxHandle, frame_der: Vec<u8>) -> Result<JsValue, JsValue> {
	let frame = Frame::from_der(&frame_der).map_err(to_js)?;
	let response = handle.emit_on_stream(&frame).await.map_err(transport_to_js)?;
	let der = response_der(response)?;

	Ok(bytes_or_undefined(der))
}

/// Split a handshaken, mux-negotiated transport into a stream handle and
/// responder, spawning the driver pumps on the browser executor.
///
/// Generic over the compile-time crypto provider: custom-profile builds
/// call this after driving their own handshake on a transport that carried
/// a mux offer (`with_mux_config`). Rejects when the peer did not
/// negotiate multiplexing.
pub fn split_mux(transport: WsTransport) -> Result<(MuxHandle, MuxResponder), JsValue> {
	if transport.negotiated_mux().is_none() {
		return Err(JsValue::from_str("the server did not negotiate multiplexing"));
	}
	let mux = transport.into_mux(MuxRole::Client).map_err(transport_to_js)?;

	Ok(spawn_mux(mux))
}

/// Spawn the driver pumps of an assembled mux (encrypting or
/// cleartext) on the browser executor.
fn spawn_mux<R, W>(mux: MuxTransport<R, W>) -> (MuxHandle, MuxResponder)
where
	R: EnvelopeSource + 'static,
	W: EnvelopeSink + 'static,
{
	let (handle, reader_driver, writer_driver, responder) = mux.into_parts();

	// Pump failures reach callers as ConnectionClosed on their pending
	// streams. The drivers themselves have nowhere to report.
	spawn_local(async move {
		let _ = reader_driver.drive().await;
	});
	spawn_local(async move {
		let _ = writer_driver.drive().await;
	});

	(handle, responder)
}

/// Drive one server-initiated stream through the JavaScript handler.
async fn respond_via_js(handler: Function, frame: Arc<Frame>) -> ResponsePackage {
	match call_handler(&handler, &frame).await {
		Ok(response) => response,
		Err(rejection) => ResponsePackage::new(refusal_for(&rejection), None),
	}
}

/// Map a handler rejection to its wire status.
///
/// A rejection carrying a `code` string that names a gRPC canonical
/// status  answers with that status. Every other throw is an unclassified
/// handler failure and answers `Unknown`.
fn refusal_for(rejection: &JsValue) -> TransitStatus {
	let code = Reflect::get(rejection, &JsValue::from_str("code"))
		.ok()
		.and_then(|value| value.as_string());

	match code {
		Some(name) => status_from_code(&name),
		None => TransitStatus::Unknown,
	}
}

/// Parse a gRPC canonical status name into its refusal status.
///
/// `Ok` is absent on purpose: a rejection cannot claim success. Names
/// outside the registry fall back to `Unknown`.
pub(crate) fn status_from_code(name: &str) -> TransitStatus {
	match name {
		"Cancelled" => TransitStatus::Cancelled,
		"InvalidArgument" => TransitStatus::InvalidArgument,
		"DeadlineExceeded" => TransitStatus::DeadlineExceeded,
		"NotFound" => TransitStatus::NotFound,
		"AlreadyExists" => TransitStatus::AlreadyExists,
		"PermissionDenied" => TransitStatus::PermissionDenied,
		"ResourceExhausted" => TransitStatus::ResourceExhausted,
		"FailedPrecondition" => TransitStatus::FailedPrecondition,
		"Aborted" => TransitStatus::Aborted,
		"OutOfRange" => TransitStatus::OutOfRange,
		"Unimplemented" => TransitStatus::Unimplemented,
		"Internal" => TransitStatus::Internal,
		"Unavailable" => TransitStatus::Unavailable,
		"DataLoss" => TransitStatus::DataLoss,
		"Unauthenticated" => TransitStatus::Unauthenticated,
		_ => TransitStatus::Unknown,
	}
}

/// Call the JS handler with the request DER and decode its resolution:
/// `undefined`/`null` accepts without a body, bytes decode as the
/// response frame.
async fn call_handler(handler: &Function, frame: &Frame) -> Result<ResponsePackage, JsValue> {
	let request_der = frame.to_der().map_err(to_js)?;
	let argument = Uint8Array::from(request_der.as_slice());

	let returned = handler.call1(&JsValue::UNDEFINED, &argument)?;
	let settled = match returned.dyn_into::<Promise>() {
		Ok(promise) => JsFuture::from(promise).await?,
		Err(value) => value,
	};

	if settled.is_undefined() || settled.is_null() {
		return Ok(ResponsePackage::new(TransitStatus::Ok, None));
	}

	let response_der = Uint8Array::from(settled).to_vec();
	let response = Frame::from_der(&response_der).map_err(to_js)?;
	Ok(ResponsePackage::new(TransitStatus::Ok, Some(response)))
}
