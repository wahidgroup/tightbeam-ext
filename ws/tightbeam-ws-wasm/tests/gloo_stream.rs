//! The envelope rules of `tightbeam_ws::wire`, run against the browser kind,
//! [`GlooStream`], under a JavaScript host.
//!
//! Each case opens a real `gloo` WebSocket to a peer served by `ws`, the
//! RFC 6455 server of the ws workspace, over a loopback socket, so the host
//! WebSocket, `gloo`, the stream, and the peer all run as they do in a page.
//!
//! # Sources
//!
//! - RFC 6455, The WebSocket Protocol, December 2011, section 5.2 (the frame
//!   opcodes): <https://datatracker.ietf.org/doc/html/rfc6455>
//! - `ws` 8.18.3, the WebSocket server of the ws workspace:
//!   <https://github.com/websockets/ws>
#![cfg(target_arch = "wasm32")]

use core::ops::Deref;

use gloo_net::websocket::futures::WebSocket;
use js_sys::Promise;
use tightbeam::transport::{AsyncProtocolStream, TransportError, TransportFailure};
use tightbeam_ws_wasm::GlooStream;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen(inline_js = r#"
const { createRequire } = process.getBuiltinModule('node:module');

// The `ws` server of the ws workspace, a complete RFC 6455 implementation,
// resolved from the directory the test runs in.
const { WebSocketServer } = createRequire(`${process.cwd()}/`)('ws');

class Frame {
	constructor(opcode, payload) {
		this.opcode = opcode;
		this.payload = payload;
	}
}

class Peer {
	constructor(server, url) {
		this.server = server;
		this.url = url;
		this.socket = null;
		this.frames = [];
		this.waiters = [];
		this.arrived = new Promise((resolve) => {
			server.on('connection', (socket) => {
				this.socket = socket;
				socket.on('message', (data, isBinary) => this.receive(data, isBinary));
				resolve();
			});
		});
	}

	accepted() {
		return this.arrived;
	}

	// RFC 6455 section 5.2: opcode 0x1 is a text frame, 0x2 a binary frame.
	send(opcode, payload) {
		const binary = opcode === 0x2;
		this.socket.send(Buffer.from(payload), { binary });
	}

	// Close with status 1000, as a server does.
	close() {
		this.socket.close(1000);
	}

	nextFrame() {
		const frame = this.frames.shift();
		if (frame !== undefined) {
			return Promise.resolve(frame);
		}

		return new Promise((resolve) => this.waiters.push(resolve));
	}

	receive(data, isBinary) {
		const opcode = isBinary ? 0x2 : 0x1;
		const frame = new Frame(opcode, Uint8Array.from(data));

		const waiter = this.waiters.shift();
		if (waiter !== undefined) {
			waiter(frame);
		} else {
			this.frames.push(frame);
		}
	}

	shutdown() {
		if (this.socket !== null) {
			this.socket.terminate();
		}

		this.server.close();
	}
}

export function listen() {
	return new Promise((resolve) => {
		const server = new WebSocketServer({ host: '127.0.0.1', port: 0 }, () => {
			const { port } = server.address();
			resolve(new Peer(server, `ws://127.0.0.1:${port}/`));
		});
	});
}
"#)]
extern "C" {
	/// A WebSocket server for one client, on an ephemeral loopback port.
	type Peer;

	/// One frame the client sent.
	type Frame;

	/// A peer that listens, as a promise of the [`Peer`].
	fn listen() -> Promise;

	#[wasm_bindgen(method, getter)]
	fn url(this: &Peer) -> String;

	/// Settles once the client finished its upgrade.
	#[wasm_bindgen(method)]
	fn accepted(this: &Peer) -> Promise;

	#[wasm_bindgen(method)]
	fn send(this: &Peer, opcode: u8, payload: &[u8]);

	#[wasm_bindgen(method)]
	fn close(this: &Peer);

	/// The next frame the client sends, as a promise of the [`Frame`].
	#[wasm_bindgen(method, js_name = nextFrame)]
	fn next_frame(this: &Peer) -> Promise;

	#[wasm_bindgen(method)]
	fn shutdown(this: &Peer);

	#[wasm_bindgen(method, getter)]
	fn opcode(this: &Frame) -> u8;

	#[wasm_bindgen(method, getter)]
	fn payload(this: &Frame) -> Vec<u8>;
}

/// The opcode of a text frame, RFC 6455 section 5.2.
const TEXT: u8 = 0x1;

/// The opcode of a binary frame, RFC 6455 section 5.2.
const BINARY: u8 = 0x2;

/// The cap of every read in these cases.
const CAP: usize = 8;

/// A listening peer that shuts down when the case ends.
struct Served(Peer);

impl Deref for Served {
	type Target = Peer;

	fn deref(&self) -> &Peer {
		&self.0
	}
}

impl Drop for Served {
	fn drop(&mut self) {
		self.0.shutdown();
	}
}

/// A stream under test, and the peer that accepted its socket.
async fn connected() -> (GlooStream, Served) {
	let listening = JsFuture::from(listen());
	let listened = listening.await.expect("the peer should listen");
	let peer = Served(listened.unchecked_into());

	let url = peer.url();
	let socket = WebSocket::open(&url).expect("the host should open the socket");
	let accepting = JsFuture::from(peer.accepted());
	accepting.await.expect("the peer should accept the socket");

	(GlooStream::from(socket), peer)
}

/// The next frame the client sent, as its opcode and payload.
async fn next_frame(peer: &Served) -> (u8, Vec<u8>) {
	let arriving = JsFuture::from(peer.next_frame());
	let arrived = arriving.await.expect("the client should send a frame");
	let frame: Frame = arrived.unchecked_into();

	(frame.opcode(), frame.payload())
}

#[wasm_bindgen_test]
async fn a_text_message_is_skipped() -> Result<(), JsValue> {
	let (mut stream, peer) = connected().await;
	peer.send(TEXT, b"noise");
	peer.send(BINARY, &[1, 2, 3]);

	let envelope = stream.read_frame(CAP).await;
	assert!(matches!(envelope, Ok(bytes) if bytes == [1, 2, 3]));
	Ok(())
}

#[wasm_bindgen_test]
async fn an_envelope_past_the_cap_is_size_exceeded() -> Result<(), JsValue> {
	let (mut stream, peer) = connected().await;
	peer.send(BINARY, &[0; CAP + 1]);

	let refused = stream.read_frame(CAP).await;

	let size_exceeded = matches!(refused, Err(TransportError::OperationFailed(TransportFailure::SizeExceeded)));
	assert!(size_exceeded);
	Ok(())
}

#[wasm_bindgen_test]
async fn a_close_ends_the_read_as_connection_closed() -> Result<(), JsValue> {
	let (mut stream, peer) = connected().await;
	peer.close();

	let closed = stream.read_frame(CAP).await;
	assert!(matches!(closed, Err(TransportError::ConnectionClosed)));
	Ok(())
}

#[wasm_bindgen_test]
async fn an_envelope_leaves_as_one_binary_message() -> Result<(), JsValue> {
	let (mut stream, peer) = connected().await;

	let sent = stream.write_frame(&[1, 2, 3]).await;
	let received = next_frame(&peer).await;
	assert!(sent.is_ok());
	assert_eq!(received, (BINARY, vec![1, 2, 3]));
	Ok(())
}
