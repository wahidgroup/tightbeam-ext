//! Pre-agreed HoneyBadger round lifecycle over a tightbeam mesh.
//!
//! Parties and consumers call the same phase sequence; there is no
//! separate control-plane coordinator. Round order is enforced locally:
//!
//! ```text
//! Idle -> Preprocessing -> Ready -> Input -> Computing -> Output -> Finished
//! ```
//!
//! Enable with the `session` feature (pulls in `stoffelcrypto`).

use core::fmt;
use core::future::Future;
use core::time::Duration;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::sync::Arc;

use ark_ff::{FftField, PrimeField};
use ark_std::rand::Rng;
use stoffelcrypto::common::{MPCProtocol, PreprocessingMPCProtocol, RBC};
use stoffelcrypto::honeybadger::input::InputError;
use stoffelcrypto::honeybadger::output::OutputError;
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelcrypto::honeybadger::{HoneyBadgerError, HoneyBadgerMPCClient, HoneyBadgerMPCNode, SessionId};
use stoffelnet::network_utils::ClientId;
use tokio::task::JoinHandle;

use crate::client::TightbeamClient;
use crate::error::Error as AdapterError;
use crate::network::TightbeamNetwork;
use crate::trace::{events, TraceEvent, TraceHandle};

/// Protocol round a [`PartySession`] is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Round {
	/// Session opened; message loop running; no preprocessing yet.
	Idle,
	/// Offline preprocessing in flight.
	Preprocessing,
	/// Preprocessing complete; ready for client input.
	Ready,
	/// Mask shares sent; waiting on / holding client input shares.
	Input,
	/// Online computation in flight or complete with result shares.
	Computing,
	/// Result shares sent to a consumer.
	Output,
	/// Session finished; no further phases.
	Finished,
}

impl fmt::Display for Round {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Idle => f.write_str("idle"),
			Self::Preprocessing => f.write_str("preprocessing"),
			Self::Ready => f.write_str("ready"),
			Self::Input => f.write_str("input"),
			Self::Computing => f.write_str("computing"),
			Self::Output => f.write_str("output"),
			Self::Finished => f.write_str("finished"),
		}
	}
}

/// Why a session operation failed.
#[derive(Debug)]
pub enum SessionError {
	/// The caller invoked a phase out of order.
	WrongRound {
		/// Round the session is in.
		current: Round,
		/// Round the phase requires.
		required: Round,
	},
	/// The network inbox was already taken.
	InboxTaken,
	/// The tightbeam adapter failed.
	Adapter(AdapterError),
	/// The HoneyBadger engine failed.
	Protocol(HoneyBadgerError),
	/// The input subprotocol failed.
	Input(InputError),
	/// The output subprotocol failed.
	Output(OutputError),
	/// The consumer's shares never appeared in the input store.
	ClientSharesMissing {
		/// The client that should have provided inputs.
		client: ClientId,
	},
}

impl fmt::Display for SessionError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::WrongRound { current, required } => {
				write!(f, "session is in round {current}, required {required}")
			}
			Self::InboxTaken => f.write_str("the network inbox was already taken"),
			Self::Adapter(cause) => write!(f, "the tightbeam adapter failed: {cause}"),
			Self::Protocol(cause) => write!(f, "the honeybadger protocol failed: {cause}"),
			Self::Input(cause) => write!(f, "the input protocol failed: {cause}"),
			Self::Output(cause) => write!(f, "the output protocol failed: {cause}"),
			Self::ClientSharesMissing { client } => {
				write!(f, "no input shares for client {client}")
			}
		}
	}
}

impl StdError for SessionError {
	fn source(&self) -> Option<&(dyn StdError + 'static)> {
		match self {
			Self::Adapter(cause) => Some(cause),
			Self::Protocol(cause) => Some(cause),
			Self::Input(cause) => Some(cause),
			Self::Output(cause) => Some(cause),
			_ => None,
		}
	}
}

impl From<AdapterError> for SessionError {
	fn from(cause: AdapterError) -> Self {
		Self::Adapter(cause)
	}
}

impl From<HoneyBadgerError> for SessionError {
	fn from(cause: HoneyBadgerError) -> Self {
		Self::Protocol(cause)
	}
}

impl From<InputError> for SessionError {
	fn from(cause: InputError) -> Self {
		Self::Input(cause)
	}
}

impl From<OutputError> for SessionError {
	fn from(cause: OutputError) -> Self {
		Self::Output(cause)
	}
}

/// Party-side session: engine node, mesh network, and round state.
pub struct PartySession<F, R>
where
	F: PrimeField,
	R: RBC<Id = SessionId>,
{
	node: HoneyBadgerMPCNode<F, R>,
	network: Arc<TightbeamNetwork>,
	round: Round,
	trace: TraceHandle,
	message_loop: JoinHandle<()>,
}

impl<F, R> PartySession<F, R>
where
	F: PrimeField + FftField + 'static,
	R: RBC<Id = SessionId> + Clone + 'static,
{
	/// Take the inbox, spawn the message loop, start in [`Round::Idle`].
	pub fn open(node: HoneyBadgerMPCNode<F, R>, network: Arc<TightbeamNetwork>) -> Result<Self, SessionError> {
		let mut inbox = network.take_inbox().ok_or(SessionError::InboxTaken)?;
		let mut loop_node = node.clone();
		let loop_network = Arc::clone(&network);
		let handle = tokio::spawn(async move {
			while let Some((sender, raw)) = inbox.recv().await {
				let _ = loop_node.process(sender, raw, Arc::clone(&loop_network)).await;
			}
		});

		Ok(Self {
			node,
			network,
			round: Round::Idle,
			trace: TraceHandle::default(),
			message_loop: handle,
		})
	}

	/// Record round transitions on `trace` instead of the default
	/// isolated collector, so verification runs can check the live
	/// phase sequence against the round-lifecycle process model.
	#[must_use]
	pub fn with_trace(mut self, trace: TraceHandle) -> Self {
		self.trace = trace;
		self
	}

	/// Current round.
	pub fn round(&self) -> Round {
		self.round
	}

	/// The underlying engine node.
	pub fn node(&self) -> &HoneyBadgerMPCNode<F, R> {
		&self.node
	}

	/// The mesh network.
	pub fn network(&self) -> &Arc<TightbeamNetwork> {
		&self.network
	}

	/// Wait until every listed consumer is linked.
	pub async fn await_clients(&self, clients: &[ClientId], deadline: Duration) -> Result<(), SessionError> {
		self.network.await_clients(clients, deadline).await?;
		Ok(())
	}

	/// Run offline preprocessing. Requires [`Round::Idle`].
	#[allow(clippy::let_and_return)]
	pub async fn preprocess<G>(&mut self, rng: &mut G) -> Result<(), SessionError>
	where
		G: Rng + Send,
	{
		self.require(Round::Idle)?;
		self.enter(&events::PREPROCESS, Round::Preprocessing)?;
		let network = Arc::clone(&self.network);
		let outcome = self.node.run_preprocessing(network, rng).await;
		let settled = match outcome {
			Ok(()) => self.settle(&events::PREPROCESS_OK, Round::Ready, Round::Idle),
			Err(cause) => {
				self.back_edge(&events::PREPROCESS_FAIL, Round::Idle);
				Err(SessionError::from(cause))
			}
		};
		settled
	}

	/// Send mask shares to `client` and wait until every authorized
	/// client's inputs are derived. Requires [`Round::Ready`].
	pub async fn collect_input(
		&mut self,
		client: ClientId,
		input_len: usize,
		wait: Duration,
	) -> Result<Vec<RobustShare<F>>, SessionError> {
		let mut collected = self.collect_inputs(&[(client, input_len)], wait).await?;
		let shares = collected.remove(&client).ok_or(SessionError::ClientSharesMissing { client })?;
		Ok(shares)
	}

	/// Send mask shares to every declared client and wait until all
	/// inputs are derived. Requires [`Round::Ready`].
	///
	/// Mask init runs for every client before the single wait, which is
	/// what the engine's input store expects for multi-client rounds.
	pub async fn collect_inputs(
		&mut self,
		declarations: &[(ClientId, usize)],
		wait: Duration,
	) -> Result<HashMap<ClientId, Vec<RobustShare<F>>>, SessionError> {
		self.require(Round::Ready)?;
		self.enter(&events::COLLECT, Round::Input)?;

		let collected = async {
			for (client, input_len) in declarations {
				let masks = {
					let mut material = self.node.preprocessing_material.lock().await;
					material.take_random_shares(*input_len)?
				};

				let network = Arc::clone(&self.network);
				self.node.preprocess.input.init(*client, masks, *input_len, network).await?;
			}

			let store = self.node.preprocess.input.wait_for_all_inputs(wait).await?;
			let mut shares = HashMap::new();
			for (client, _) in declarations {
				let derived = store
					.get(client)
					.cloned()
					.ok_or(SessionError::ClientSharesMissing { client: *client })?;
				shares.insert(*client, derived);
			}
			Ok(shares)
		}
		.await;

		match collected {
			Ok(shares) => Ok(shares),
			Err(cause) => {
				self.back_edge(&events::COLLECT_FAIL, Round::Ready);
				Err(cause)
			}
		}
	}

	/// Run Beaver multiplication on two share vectors. Requires
	/// [`Round::Input`] (set by a successful [`Self::collect_input`]).
	pub async fn multiply(
		&mut self,
		x: Vec<RobustShare<F>>,
		y: Vec<RobustShare<F>>,
	) -> Result<Vec<RobustShare<F>>, SessionError> {
		self.require(Round::Input)?;
		self.enter(&events::COMPUTE, Round::Computing)?;
		let network = Arc::clone(&self.network);
		let outcome = self.node.mul(x, y, network).await;
		match outcome {
			Ok(products) => Ok(products),
			Err(cause) => {
				self.back_edge(&events::COMPUTE_FAIL, Round::Input);
				Err(SessionError::from(cause))
			}
		}
	}

	/// Run an online computation with exclusive access to the engine.
	/// Requires [`Round::Input`].
	///
	/// The closure's error type is caller-chosen so layered protocols
	/// (like the bytecode VM) surface their own failures; it only has
	/// to absorb [`SessionError`] for the round-machine check.
	pub async fn compute<'a, T, E, Fut>(
		&'a mut self,
		work: impl FnOnce(&'a mut HoneyBadgerMPCNode<F, R>, Arc<TightbeamNetwork>) -> Fut,
	) -> Result<T, E>
	where
		Fut: Future<Output = Result<T, E>> + 'a,
		E: From<SessionError>,
	{
		if let Err(cause) = self.require(Round::Input) {
			return Err(E::from(cause));
		}
		if let Err(cause) = self.enter(&events::COMPUTE, Round::Computing) {
			return Err(E::from(cause));
		}

		let outcome = work(&mut self.node, Arc::clone(&self.network)).await;
		match outcome {
			Ok(result) => Ok(result),
			Err(cause) => {
				// Field-level accesses keep the closure's exclusive
				// node borrow legal where a method call would not be.
				let _ = self.trace.event(&events::COMPUTE_FAIL);
				self.round = Round::Input;
				Err(cause)
			}
		}
	}

	/// Send result shares to `client`. Requires [`Round::Computing`].
	#[allow(clippy::let_and_return)]
	pub async fn send_output(&mut self, client: ClientId, shares: Vec<RobustShare<F>>) -> Result<(), SessionError> {
		self.require(Round::Computing)?;
		self.enter(&events::OUTPUT, Round::Output)?;
		let input_len = shares.len();
		let network = Arc::clone(&self.network);
		let outcome = self.node.output.init(client, shares, input_len, network).await;
		let settled = match outcome {
			Ok(()) => self.settle(&events::OUTPUT_OK, Round::Finished, Round::Computing),
			Err(cause) => {
				self.back_edge(&events::OUTPUT_FAIL, Round::Computing);
				Err(SessionError::from(cause))
			}
		};
		settled
	}

	fn require(&self, required: Round) -> Result<(), SessionError> {
		if self.round == required {
			return Ok(());
		}
		Err(SessionError::WrongRound { current: self.round, required })
	}

	/// Trace a forward transition, then enter its phase. An injected
	/// fault at the label leaves the round untouched.
	fn enter(&mut self, event: &TraceEvent, phase: Round) -> Result<(), SessionError> {
		self.trace.event(event).map_err(SessionError::from)?;
		self.round = phase;
		Ok(())
	}

	/// Trace a success edge and settle on `landing`. An injected fault
	/// at the label takes the same back-edge a genuine failure would,
	/// so injection exercises real recovery code.
	fn settle(&mut self, event: &TraceEvent, landing: Round, fallback: Round) -> Result<(), SessionError> {
		match self.trace.event(event) {
			Ok(()) => {
				self.round = landing;
				Ok(())
			}
			Err(fault) => {
				self.round = fallback;
				Err(SessionError::from(fault))
			}
		}
	}

	/// Trace a failure back-edge and rewind the round. The edge event
	/// is advisory: the path is already failing for its own reason.
	fn back_edge(&mut self, event: &TraceEvent, fallback: Round) {
		let _ = self.trace.event(event);
		self.round = fallback;
	}
}

impl<F, R> Drop for PartySession<F, R>
where
	F: PrimeField,
	R: RBC<Id = SessionId>,
{
	fn drop(&mut self) {
		self.message_loop.abort();
	}
}

/// Consumer-side session: client engine, dialed party links, message loop.
pub struct ClientSession<F, R>
where
	F: FftField,
	R: RBC<Id = SessionId>,
{
	client: HoneyBadgerMPCClient<F, R>,
	network: Arc<TightbeamClient>,
	finished: bool,
	trace: TraceHandle,
	message_loop: JoinHandle<()>,
}

impl<F, R> ClientSession<F, R>
where
	F: FftField + 'static,
	R: RBC<Id = SessionId> + 'static,
{
	/// Take the inbox, spawn the message loop.
	pub fn open(client: HoneyBadgerMPCClient<F, R>, network: Arc<TightbeamClient>) -> Result<Self, SessionError> {
		let mut inbox = network.take_inbox().ok_or(SessionError::InboxTaken)?;
		let mut loop_client = client.clone();
		let loop_network = Arc::clone(&network);
		let handle = tokio::spawn(async move {
			while let Some((sender, raw)) = inbox.recv().await {
				let _ = loop_client.process(sender, raw, Arc::clone(&loop_network)).await;
			}
		});

		Ok(Self {
			client,
			network,
			finished: false,
			trace: TraceHandle::default(),
			message_loop: handle,
		})
	}

	/// Record output-phase events on `trace` instead of the default
	/// isolated collector.
	#[must_use]
	pub fn with_trace(mut self, trace: TraceHandle) -> Self {
		self.trace = trace;
		self
	}

	/// The consumer network.
	pub fn network(&self) -> &Arc<TightbeamClient> {
		&self.network
	}

	/// Wait until parties deliver enough output shares to reconstruct.
	pub async fn wait_output(&mut self, deadline: Duration) -> Result<Vec<F>, SessionError> {
		if self.finished {
			return Err(SessionError::WrongRound { current: Round::Finished, required: Round::Output });
		}

		self.trace.event(&events::WAIT_OUTPUT).map_err(SessionError::from)?;
		let recovered = self.client.output.wait_for_output(deadline).await?;
		// An injected fault here leaves `finished` unset, so the
		// consumer can re-wait: the output store retains the shares.
		self.trace.event(&events::OUTPUT_RECOVERED).map_err(SessionError::from)?;
		self.finished = true;
		Ok(recovered)
	}
}

impl<F, R> Drop for ClientSession<F, R>
where
	F: FftField,
	R: RBC<Id = SessionId>,
{
	fn drop(&mut self) {
		self.message_loop.abort();
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn wrong_round_displays_both_states() {
		let error = SessionError::WrongRound { current: Round::Idle, required: Round::Ready };
		let text = error.to_string();
		assert!(text.contains("idle"));
		assert!(text.contains("ready"));
	}

	#[test]
	fn client_shares_missing_names_the_client() {
		let error = SessionError::ClientSharesMissing { client: 100 };
		assert!(error.to_string().contains("100"));
	}
}
