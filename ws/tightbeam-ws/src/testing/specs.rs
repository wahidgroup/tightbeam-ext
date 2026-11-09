//! The specs of the shared suites, which the scenarios of every transport of
//! the repository grade their traces with.
//!
//! Each spec states what one shared suite records when it runs over a
//! transport that carries it unchanged, so a transport whose scenarios meet
//! the spec behaves as the other transports do. The suite that each spec
//! grades lives beside it in this module's parent: [`EchoService`],
//! [`ReadOutcome`], and, under `colony`, [`WorkPlane`].
//!
//! [`EchoService`]: super::EchoService
//! [`ReadOutcome`]: super::ReadOutcome
//! [`WorkPlane`]: super::WorkPlane

use tightbeam::instrumentation::events;
use tightbeam::{exactly, tb_assert_spec};

use super::ReadOutcome;

tb_assert_spec! {
	/// One cleartext exchange with the shared echo through `client!`, which
	/// takes no trace: the server accepts the one connection, and its gate
	/// admits the one request.
	pub CleartextRoundTripSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CONNECTION_ACCEPTED, exactly!(1)),
			(events::GATE_ACCEPT, exactly!(1)),
			(events::GATE_REJECT, exactly!(0))
		]
	}
}

tb_assert_spec! {
	/// One encrypted exchange with the shared echo over a dialed transport
	/// that records on the trace: each end completes one handshake, the
	/// server accepts the one connection, and its gate admits the one request.
	pub EncryptedRoundTripSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(2)),
			(events::CONNECTION_ACCEPTED, exactly!(1)),
			(events::GATE_ACCEPT, exactly!(1)),
			(events::GATE_REJECT, exactly!(0))
		]
	}
}

tb_assert_spec! {
	/// The stream kinds of [`EchoService::through_pool`] over one pooled,
	/// multiplexed connection to the shared echo: the pool dials once, each
	/// end completes one handshake, the server accepts the one connection,
	/// and its gate admits each of the three streams.
	///
	/// [`EchoService::through_pool`]: super::EchoService::through_pool
	pub PooledMuxSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::POOL_MUX_DECLINED, exactly!(0)),
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(2)),
			(events::CONNECTION_ACCEPTED, exactly!(1)),
			(events::GATE_ACCEPT, exactly!(3)),
			(events::MUX_STREAM_REFUSED, exactly!(0))
		]
	}
}

tb_assert_spec! {
	/// The read of a dial that a hostile peer answers with a frame past the
	/// ceiling of the endpoint: the read refuses the frame by its declared
	/// size, before any byte of its payload arrives.
	pub DialCeilingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(ReadOutcome::EVENT, exactly!(1), equals!("size-exceeded"))
		]
	}
}

#[cfg(feature = "colony")]
tb_assert_spec! {
	/// One signed work frame from the edge of a [`WorkPlane`] gateway to its
	/// work probe: the hive registers once through the colony plane, the
	/// gateway routes the work once, and the edge refuses nothing.
	///
	/// [`WorkPlane`]: super::WorkPlane
	pub EdgeWorkSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1)),
			(events::CLUSTER_EDGE_REFUSED, exactly!(0))
		]
	}
}

#[cfg(feature = "colony")]
tb_assert_spec! {
	/// One work frame from the edge of a [`WorkPlane`] gateway to a servlet
	/// type that no hive serves: the type has no live trail, so the gateway
	/// routes nothing.
	///
	/// [`WorkPlane`]: super::WorkPlane
	pub UnservedWorkSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, exactly!(0)),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(1))
		]
	}
}
