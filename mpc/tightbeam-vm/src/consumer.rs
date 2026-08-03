//! The consumer-side host: submit a program, verify digest agreement,
//! then run the input/output session.
//!
//! Submission is all-or-nothing: every party must echo the exact
//! digest of the submitted bytes with `accept = true` before the
//! consumer opens its engine session. A single disagreement or
//! rejection aborts before any secret leaves the consumer.

use core::time::Duration;
use std::sync::Arc;

use ark_ff::FftField;
use stoffelcrypto::common::RBC;
use stoffelcrypto::honeybadger::{HoneyBadgerMPCClient, SessionId};
use stoffelnet::network_utils::Network;
use tightbeam_mpc::{ClientSession, Delivery, SessionError, TightbeamClient, TraceHandle};
use tokio::sync::mpsc::Receiver;
use tokio::time::Instant;

use crate::control::ControlMessage;
use crate::error::{Result, VmError};
use crate::events;
use crate::validate::ValidProgram;

/// A consumer connected to every party, ready to submit programs.
pub struct VmConsumer {
	network: Arc<TightbeamClient>,
	control: Receiver<Delivery>,
	trace: TraceHandle,
}

impl VmConsumer {
	/// Wrap an established consumer network, taking its control inbox.
	pub fn new(network: Arc<TightbeamClient>) -> Result<Self> {
		let control = network.take_control_inbox().ok_or(VmError::Session(SessionError::InboxTaken))?;
		Ok(Self { network, control, trace: TraceHandle::default() })
	}

	/// Record submission-flow events (`submit`, `echo_ok`, `echo_lost`,
	/// `digest_mismatch`) on `trace` instead of the default isolated
	/// collector.
	#[must_use]
	pub fn with_trace(mut self, trace: TraceHandle) -> Self {
		self.trace = trace;
		self
	}

	/// Submit the program to every party and wait until each echoes
	/// the exact digest with acceptance.
	pub async fn submit(&mut self, program: &ValidProgram, deadline: Duration) -> Result<()> {
		self.trace.event(&events::SUBMIT)?;
		let message = ControlMessage::Submit { program: program.bytes().to_vec() }.encode()?;
		let parties = self.network.party_count();
		for party in 0..parties {
			self.network.send_control(party, &message).await?;
		}

		let mut confirmed = vec![false; parties];
		let deadline_at = Instant::now() + deadline;

		while confirmed.iter().any(|accepted| !accepted) {
			let now = Instant::now();
			if now >= deadline_at {
				let _ = self.trace.event(&events::ECHO_LOST);
				return Err(VmError::SubmissionTimeout);
			}

			let arrival = tokio::time::timeout(deadline_at - now, self.control.recv()).await;
			let Ok(delivery) = arrival else {
				let _ = self.trace.event(&events::ECHO_LOST);
				return Err(VmError::SubmissionTimeout);
			};
			let Some((sender, raw)) = delivery else {
				return Err(VmError::ControlClosed);
			};

			if sender >= parties {
				continue;
			}
			let Ok(ControlMessage::Echo { digest, accept }) = ControlMessage::decode(&raw) else {
				continue;
			};

			if !accept {
				return Err(VmError::Rejected { party: sender });
			}
			if digest != program.digest() {
				let _ = self.trace.event(&events::DIGEST_MISMATCH);
				return Err(VmError::DigestMismatch { party: sender });
			}
			confirmed[sender] = true;
		}

		self.trace.event(&events::ECHO_OK)?;
		Ok(())
	}

	/// Open the engine session for a digest-agreed program.
	///
	/// `inputs` are this consumer's secrets, in declaration order; the
	/// count must match the program's declaration for this client.
	pub fn open_session<F, R>(
		&self,
		program: &ValidProgram,
		threshold: usize,
		inputs: Vec<F>,
	) -> Result<ClientSession<F, R>>
	where
		F: FftField + 'static,
		R: RBC<Id = SessionId> + 'static,
	{
		let client_id = self.network.client_id();
		let declaration = program
			.program()
			.inputs
			.iter()
			.find(|decl| decl.client == client_id)
			.ok_or(VmError::MissingInput { client: client_id })?;

		let declared = declaration.dest.len as usize;
		if inputs.len() != declared {
			return Err(VmError::InputArity { client: client_id, expected: declared, got: inputs.len() });
		}

		let parties = self.network.party_count();
		let engine =
			HoneyBadgerMPCClient::new(client_id, parties, threshold, program.digest().instance_id(), inputs, declared)
				.map_err(SessionError::from)?;

		let opened = ClientSession::open(engine, Arc::clone(&self.network))?;
		let session = opened.with_trace(self.trace.clone());
		Ok(session)
	}
}
