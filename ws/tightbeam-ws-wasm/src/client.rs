//! Browser WebSocket client driving the tightbeam cleartext request/response
//! exchange. Compiled only for `wasm32` targets.

use futures_util::{SinkExt, StreamExt};
use gloo_net::websocket::futures::WebSocket;
use gloo_net::websocket::Message;
use wasm_bindgen::prelude::*;

use crate::envelope::{decode_response, encode_cleartext_request};
use crate::error::Error;

impl From<Error> for JsValue {
	fn from(error: Error) -> Self {
		JsValue::from_str(&error.to_string())
	}
}

/// A tightbeam client over a single browser WebSocket connection.
#[wasm_bindgen]
pub struct WsClient {
	socket: WebSocket,
}

#[wasm_bindgen]
impl WsClient {
	/// Open a WebSocket to `url` (for example `ws://127.0.0.1:9000/`).
	#[wasm_bindgen(js_name = connect)]
	pub fn connect(url: &str) -> Result<WsClient, JsValue> {
		let socket = WebSocket::open(url).map_err(|error| JsValue::from_str(&error.to_string()))?;
		Ok(Self { socket })
	}

	/// Send a DER-encoded [`tightbeam::Frame`] as a cleartext request and
	/// resolve with the DER-encoded response frame, or `undefined` when the
	/// server returned no payload.
	#[wasm_bindgen(js_name = request)]
	pub async fn request(&mut self, frame_der: Vec<u8>) -> Result<Option<Vec<u8>>, JsValue> {
		let envelope = encode_cleartext_request(&frame_der)?;
		self.socket.send(Message::Bytes(envelope)).await.map_err(Error::from)?;

		let reply = self.next_binary().await?;
		Ok(decode_response(&reply)?)
	}
}

impl WsClient {
	/// Await the next binary frame, skipping any interleaved text frames.
	async fn next_binary(&mut self) -> Result<Vec<u8>, Error> {
		loop {
			match self.socket.next().await {
				Some(Ok(Message::Bytes(bytes))) => return Ok(bytes),
				Some(Ok(Message::Text(_))) => continue,
				Some(Err(error)) => return Err(Error::from(error)),
				None => return Err(Error::ConnectionClosed),
			}
		}
	}
}
