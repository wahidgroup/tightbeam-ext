//! The live `ws` peer of the wasm unit tests, as the module table of
//! `docs/ws-wasm.md` lists.

use gloo_net::websocket::futures::WebSocket;
use js_sys::{Function, Promise};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use tightbeam::transport::multiplex::MuxRole;

use crate::clock::BrowserClock;
use crate::mux::SessionParts;
use crate::protocol::BrowserSocket;

#[path = "../tests/support/patience.rs"]
mod patience;

pub(crate) use patience::settled;

#[wasm_bindgen(inline_js = r#"
const { createRequire } = process.getBuiltinModule('node:module');

// The `ws` server of the ws workspace, resolved from the directory the test
// runs in. Its sockets carry the browser WebSocket API that `gloo` drives,
// and the listener gives the server end the `dispatchEvent` of that API.
const { WebSocketServer } = createRequire(`${process.cwd()}/`)('ws');

class Listener {
	constructor(server, url) {
		this.server = server;
		this.url = url;
		this.arrived = new Promise((resolve) => {
			server.once('connection', (socket) => {
				// A `gloo` socket frees its close listener at its drop
				// through a synthetic close event, which this method hands
				// to that listener.
				socket.dispatchEvent = (event) => socket.emit(event.type, event.code, event.reason);
				resolve(socket);
			});
		});
	}

	accepted() {
		return this.arrived;
	}

	held() {
		return this.arrived.then((socket) => {
			socket.pause();
			return () => socket.resume();
		});
	}

	shutdown() {
		for (const socket of this.server.clients) {
			socket.terminate();
		}

		this.server.close();
	}
}

export function listen() {
	return new Promise((resolve) => {
		const server = new WebSocketServer({ host: '127.0.0.1', port: 0 }, () => {
			const { port } = server.address();
			resolve(new Listener(server, `ws://127.0.0.1:${port}/`));
		});
	});
}
"#)]
extern "C" {
	/// A WebSocket server for one client, on an ephemeral loopback port.
	type Listener;

	/// A listener that listens, as a promise of the [`Listener`].
	fn listen() -> Promise;

	#[wasm_bindgen(method, getter)]
	fn url(this: &Listener) -> String;

	/// Settles with the server end of the socket once the client upgraded.
	#[wasm_bindgen(method)]
	fn accepted(this: &Listener) -> Promise;

	/// Settles with the release of a pause on the server end of the socket,
	/// which reads no frame until the release runs.
	#[wasm_bindgen(method)]
	fn held(this: &Listener) -> Promise;

	#[wasm_bindgen(method)]
	fn shutdown(this: &Listener);
}

/// A client session, the server session that accepted it, and the server
/// that shuts down as the loopback drops.
pub(crate) struct Loopback {
	pub(crate) client: SessionParts,
	pub(crate) server: SessionParts,
	_listener: Served,
}

/// A listening server that shuts down as it drops.
pub(crate) struct Served(Listener);

impl Drop for Served {
	fn drop(&mut self) {
		self.0.shutdown();
	}
}

impl Served {
	/// A server for one client, once it listens.
	pub(crate) async fn listening() -> Self {
		let listened = settled(JsFuture::from(listen())).await;
		let listener: Listener = listened.expect("the server should listen").unchecked_into();
		Self(listener)
	}

	/// The URL that a client dials.
	pub(crate) fn url(&self) -> String {
		self.0.url()
	}

	/// Pause the server end of the socket this server accepted, so it reads no
	/// frame and answers no close until the hold drops.
	pub(crate) async fn hold(&self) -> Hold {
		let held = settled(JsFuture::from(self.0.held())).await;
		let release = held.expect("the server should accept the socket");
		Hold(release.unchecked_into())
	}
}

/// A pause on the server end of a socket, which resumes it as it drops.
pub(crate) struct Hold(Function);

impl Drop for Hold {
	fn drop(&mut self) {
		let _ = self.0.call0(&JsValue::UNDEFINED);
	}
}

impl Loopback {
	/// Connect a client session to a server session under the symmetric cap
	/// `streams`.
	pub(crate) async fn open(streams: u32) -> Self {
		let listener = Served::listening().await;

		let socket = WebSocket::open(&listener.url()).expect("the host should open the socket");
		let accepted = settled(JsFuture::from(listener.0.accepted())).await;
		let accepted = accepted.expect("the server should accept the socket");
		let served = WebSocket::try_from(accepted.unchecked_into::<web_sys::WebSocket>());
		let served = served.expect("the server end should adapt");

		let client = BrowserSocket::cleartext_session(socket, MuxRole::Client, streams);
		let client = client.expect("the client session should split");
		let server = BrowserSocket::cleartext_session(served, MuxRole::Server, streams);
		let server = server.expect("the server session should split");
		Self { client, server, _listener: listener }
	}
}
