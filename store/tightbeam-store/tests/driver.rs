//! The native contract on the backend that ships with the store.

use std::io;

use tightbeam::testing::SetupEnv;
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn};
use tightbeam_store::testing::DriverConformance;
use tightbeam_store::MemoryDriver;

/// Whether `MemoryDriver` met every clause of the native contract.
const CONFORMS: Urn<'static> = urn!("test", "event:store-driver/conforms");

tb_assert_spec! {
	pub MemoryDriverSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(CONFORMS, exactly!(1), equals!(true))
		]
	}
}

// `MemoryDriver` meets each clause of the native contract, each on a fresh
// backend.
tb_scenario! {
	name: memory_driver_meets_the_native_contract,
	spec: MemoryDriverSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let checked = DriverConformance::new(|| async { Ok(MemoryDriver::default()) }).check().await;
			checked.map_err(io::Error::other)?;
			trace.event_with(CONFORMS, &[], true)?;
			Ok(())
		}
	}
}
