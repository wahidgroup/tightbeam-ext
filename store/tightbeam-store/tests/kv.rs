//! The KV contract on the backend that ships with the store.

use std::io;

use tightbeam::testing::SetupEnv;
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn};
use tightbeam_store::testing::KvConformance;
use tightbeam_store::MemoryKv;

/// Whether `MemoryKv` met every clause of the KV contract.
const CONFORMS: Urn<'static> = urn!("test", "event:store-kv/conforms");

tb_assert_spec! {
	pub MemoryKvSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(CONFORMS, exactly!(1), equals!(true))
		]
	}
}

// `MemoryKv` meets each clause of the KV contract, each on a fresh backend.
tb_scenario! {
	name: memory_kv_meets_the_kv_contract,
	spec: MemoryKvSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let checked = KvConformance::new(|| async { Ok(MemoryKv::default()) }).check().await;
			checked.map_err(io::Error::other)?;
			trace.event_with(CONFORMS, &[], true)?;
			Ok(())
		}
	}
}
