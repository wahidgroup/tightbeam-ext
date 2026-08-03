//! The party-side host: receive a program, agree on its digest, run it.
//!
//! One [`VmParty`] wraps one program execution end to end. The
//! submission arrives on the control lane, is validated into a
//! [`ValidProgram`], and its digest is echoed back to the submitter -
//! accept or reject - before any protocol round runs. The engine node
//! is then sized from the program's [`Budget`](crate::validate::Budget)
//! and keyed by the digest-derived instance id, so every party (and the
//! consumer) joins the same protocol sessions without further
//! coordination.

use core::time::Duration;
use std::sync::Arc;

use ark_ff::{FftField, PrimeField};
use ark_std::rand::Rng;
use stoffelcrypto::common::{MPCProtocol, RBC};
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelcrypto::honeybadger::{HoneyBadgerMPCNode, HoneyBadgerMPCNodeOpts, SessionId};
use stoffelnet::network_utils::{ClientId, Network};
use tightbeam_mpc::{Delivery, PartySession, SessionError, TightbeamNetwork, TraceHandle};
use tokio::sync::mpsc::Receiver;
use tokio::time::Instant;

use crate::backend::HoneyBadgerBackend;
use crate::codec::digest;
use crate::control::ControlMessage;
use crate::error::{Result, VmError};
use crate::events;
use crate::executor::execute;
use crate::isa::Instruction;
use crate::validate::ValidProgram;

/// Tunables for one party-side program execution.
#[derive(Clone, Debug)]
pub struct VmPartyConfig {
	/// Upper bound of corrupt parties the deployment tolerates.
	pub threshold: usize,
	/// How long to wait for a program submission.
	pub submission_deadline: Duration,
	/// How long to wait for the program's clients to link.
	pub client_ready_deadline: Duration,
	/// How long the input store waits for every client's inputs.
	pub input_wait: Duration,
	/// How long each reveal waits for peer shares.
	pub reveal_deadline: Duration,
	/// The engine's internal protocol timeout.
	pub engine_timeout: Duration,
	/// Where this host's lifecycle events land: the submission verdict
	/// (`admit` / `refuse` / `submit_timeout`), the session's round
	/// transitions, and the interpreter's execution events. The default
	/// is an isolated collector nobody observes.
	pub trace: TraceHandle,
}

/// A party ready to run one received, digest-agreed program.
pub struct VmParty<F, R>
where
	F: PrimeField,
	R: RBC<Id = SessionId>,
{
	session: PartySession<F, R>,
	control: Receiver<Delivery>,
	program: ValidProgram,
	config: VmPartyConfig,
	parties: usize,
}

/// Wait for a `Submit` on the control lane from a consumer.
async fn await_submission(
	control: &mut Receiver<Delivery>,
	parties: usize,
	deadline: Duration,
	trace: &TraceHandle,
) -> Result<(ClientId, Vec<u8>)> {
	let deadline_at = Instant::now() + deadline;
	loop {
		let now = Instant::now();
		if now >= deadline_at {
			let _ = trace.event(&events::SUBMIT_TIMEOUT);
			return Err(VmError::SubmissionTimeout);
		}

		let arrival = tokio::time::timeout(deadline_at - now, control.recv()).await;
		let Ok(delivery) = arrival else {
			let _ = trace.event(&events::SUBMIT_TIMEOUT);
			return Err(VmError::SubmissionTimeout);
		};
		let Some((sender, raw)) = delivery else {
			return Err(VmError::ControlClosed);
		};

		// Only consumers submit; mesh parties never carry a Submit.
		if sender < parties {
			continue;
		}
		if let Ok(ControlMessage::Submit { program }) = ControlMessage::decode(&raw) {
			return Ok((sender, program));
		}
	}
}

impl<F, R> VmParty<F, R>
where
	F: PrimeField + FftField + 'static,
	R: RBC<Id = SessionId> + Clone + Send + Sync + 'static,
{
	/// Wait for a program submission, validate it, and echo the
	/// verdict to the submitter.
	///
	/// On acceptance the engine node is built from the program's
	/// budget and digest and the session opens.
	pub async fn receive(network: Arc<TightbeamNetwork>, config: VmPartyConfig) -> Result<Self> {
		let mut control = network.take_control_inbox().ok_or(VmError::Session(SessionError::InboxTaken))?;
		let parties = network.party_count();

		let (submitter, bytes) =
			await_submission(&mut control, parties, config.submission_deadline, &config.trace).await?;

		let validated = ValidProgram::from_der(&bytes);
		let program = match validated {
			Ok(program) => {
				config.trace.event(&events::ADMIT)?;
				let echo = ControlMessage::Echo { digest: program.digest(), accept: true }.encode()?;
				network.send_control_to_client(submitter, &echo).await?;
				program
			}
			Err(cause) => {
				// Best-effort verdict: the rejection stands even if the
				// submitter already hung up.
				let _ = config.trace.event(&events::REFUSE);
				if let Ok(echo) = (ControlMessage::Echo { digest: digest(&bytes), accept: false }).encode() {
					let _ = network.send_control_to_client(submitter, &echo).await;
				}
				return Err(cause);
			}
		};

		let budget = program.budget();
		// The RISS random-integer bound is 2^(l + k); the engine only
		// consumes the sum, sized to the integer part of the format.
		let riss_bits = match program.precision() {
			Some(precision) => usize::from(precision.k - precision.f),
			None => 0,
		};
		let opts = HoneyBadgerMPCNodeOpts::new(
			parties,
			config.threshold,
			budget.triples.max(1),
			budget.random_shares,
			program.digest().instance_id(),
			budget.prandbits,
			budget.prandints,
			riss_bits,
			0,
			config.engine_timeout,
		)
		.map_err(SessionError::from)?;

		let clients = participating_clients(&program);
		let local = network.local_party_id();
		let node =
			<HoneyBadgerMPCNode<F, R> as MPCProtocol<F, RobustShare<F>, TightbeamNetwork>>::setup(local, opts, clients)
				.map_err(SessionError::from)?;

		let opened = PartySession::open(node, network)?;
		let session = opened.with_trace(config.trace.clone());
		Ok(Self { session, control, program, config, parties })
	}

	/// The digest-agreed program this party will run.
	pub fn program(&self) -> &ValidProgram {
		&self.program
	}

	/// Drive the full lifecycle: client readiness, preprocessing,
	/// input collection, execution, output delivery.
	///
	/// Borrows rather than consumes the host: dropping a [`VmParty`]
	/// tears down its mesh (links and listener), so a party that
	/// finishes early must stay alive until every peer has finished
	/// too.
	pub async fn run<G>(&mut self, rng: &mut G) -> Result<()>
	where
		G: Rng + Send,
	{
		let clients = participating_clients(&self.program);
		self.session.await_clients(&clients, self.config.client_ready_deadline).await?;

		self.session.preprocess(rng).await?;

		let declarations: Vec<(ClientId, usize)> = self
			.program
			.program()
			.inputs
			.iter()
			.map(|decl| (decl.client, decl.dest.len as usize))
			.collect();

		let inputs = self.session.collect_inputs(&declarations, self.config.input_wait).await?;
		let control = &mut self.control;
		let valid = &self.program;
		let parties = self.parties;
		let threshold = self.config.threshold;
		let reveal_deadline = self.config.reveal_deadline;
		let trace = &self.config.trace;

		let output = self
			.session
			.compute(move |node, network| async move {
				let mut backend = HoneyBadgerBackend::new(node, network, control, parties, threshold, reveal_deadline);
				execute(valid, inputs, &mut backend, trace).await
			})
			.await?;

		self.session.send_output(output.client, output.shares).await?;
		Ok(())
	}
}

/// Every client the program touches: input providers and the output
/// receiver, deduplicated in first-appearance order.
fn participating_clients(program: &ValidProgram) -> Vec<ClientId> {
	let providers = program.program().inputs.iter().map(|decl| decl.client);
	let receivers = program.program().instructions.iter().filter_map(|instruction| {
		if let Instruction::Out { client, .. } = instruction {
			return Some(*client);
		}

		None
	});

	let mut clients: Vec<ClientId> = Vec::new();
	for client in providers.chain(receivers) {
		if !clients.contains(&client) {
			clients.push(client);
		}
	}

	clients
}
