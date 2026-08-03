//! The VM event catalog, on the same dual-plane scheme as
//! [`tightbeam_mpc::events`]: each [`TraceEvent`] pairs the assertion
//! label the verification framework counts with a URN naming the event
//! kind on the instrumentation plane
//! (`urn:tightbeam:vm:event/<kind>`).

use tightbeam_mpc::TraceEvent;

/// A program submission left the consumer.
pub const SUBMIT: TraceEvent = TraceEvent::new("submit", "vm:event/submit");
/// A party's submission deadline elapsed without a program.
pub const SUBMIT_TIMEOUT: TraceEvent = TraceEvent::new("submit_timeout", "vm:event/submit-timeout");
/// A party validated and admitted the submitted program.
pub const ADMIT: TraceEvent = TraceEvent::new("admit", "vm:event/admit");
/// A party refused the submitted program.
pub const REFUSE: TraceEvent = TraceEvent::new("refuse", "vm:event/refuse");
/// Every party echoed the digest with acceptance.
pub const ECHO_OK: TraceEvent = TraceEvent::new("echo_ok", "vm:event/echo-ok");
/// An expected echo never arrived.
pub const ECHO_LOST: TraceEvent = TraceEvent::new("echo_lost", "vm:event/echo-lost");
/// An echo carried a digest that disagrees with the submission.
pub const DIGEST_MISMATCH: TraceEvent = TraceEvent::new("digest_mismatch", "vm:event/digest-mismatch");

/// The interpreter started a validated program.
pub const PROGRAM_START: TraceEvent = TraceEvent::new("program_start", "vm:event/program-start");
/// The interpreter ran an interactive reveal.
pub const REVEAL: TraceEvent = TraceEvent::new("reveal", "vm:event/reveal");
/// The interpreter finished the program.
pub const PROGRAM_END: TraceEvent = TraceEvent::new("program_end", "vm:event/program-end");

/// The catalog's URNs as bare constants, because `tb_assert_spec!`
/// `events:` ordering blocks take identifiers that must resolve to
/// [`Urn`](tightbeam::utils::urn::Urn) values.
pub mod kind {
	use tightbeam::utils::urn::Urn;

	pub const SUBMIT: Urn<'static> = super::SUBMIT.urn();
	pub const SUBMIT_TIMEOUT: Urn<'static> = super::SUBMIT_TIMEOUT.urn();
	pub const ADMIT: Urn<'static> = super::ADMIT.urn();
	pub const REFUSE: Urn<'static> = super::REFUSE.urn();
	pub const ECHO_OK: Urn<'static> = super::ECHO_OK.urn();
	pub const ECHO_LOST: Urn<'static> = super::ECHO_LOST.urn();
	pub const DIGEST_MISMATCH: Urn<'static> = super::DIGEST_MISMATCH.urn();
	pub const PROGRAM_START: Urn<'static> = super::PROGRAM_START.urn();
	pub const REVEAL: Urn<'static> = super::REVEAL.urn();
	pub const PROGRAM_END: Urn<'static> = super::PROGRAM_END.urn();
}
