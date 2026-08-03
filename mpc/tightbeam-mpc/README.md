# tightbeam-mpc

HoneyBadgerMPC network adapter for the [tightbeam](https://crates.io/crates/tightbeam-rs) messaging protocol.

The [stoffelcrypto](https://crates.io/crates/stoffelcrypto) HoneyBadgerMPC engine drives any implementation of the [stoffelnet](https://crates.io/crates/stoffelnet) `Network` abstraction. This crate implements it on a full mesh of pairwise tightbeam links: mutually-authenticated ECIES sessions with HTTP/2-style stream multiplexing, one TCP connection per party pair.

## Topology

Party `i` binds the listener named by its roster entry and dials every party `j > i`, so exactly one link exists per pair and multiplexing carries both directions concurrently. Certificates are the identity anchor:

- Dialers pin the target's roster certificate as their only trust anchor.
- Acceptors require mutual authentication and validate the presented client certificate against the roster (direct trust plus expiry).
- Every inbound frame is attributed to the party whose certificate authenticated the link it arrived on. No identity claim travels inside frames, so there is nothing to spoof.

When flow-control budgets or AEAD record limits drain a session (GoAway), the dialing side re-establishes the link on its next send; the acceptor side accepts the replacement connection.

### Consumers

MPC clients (input providers and output receivers) are not mesh members. The roster authorizes them by certificate (`Roster::with_clients`), with ids outside the party id space. A consumer never listens: `TightbeamClient` dials every party, and the party-side `send_to_client` rides the same mux links back. Because party and client ids never overlap, one party inbox carries both kinds of traffic, attributed by the certificate that authenticated each link.

## Surface

- `Roster` - the party directory: dense `0..n` ids (they double as share-evaluation indices), listen addresses, certificates. `with_clients` authorizes consumers.
- `LocalIdentity` - the local endpoint's id, certificate, and signing key provider (parties and consumers alike).
- `TightbeamNetwork` - the party-side stoffelnet `Network` implementation. `establish` resolves once every pairwise link exists.
- `TightbeamClient` - the consumer-side `Network` implementation. `establish` resolves once every party link exists.
- `take_inbox` / `await_clients` - delivery stream and client-link readiness gate before `send_to_client`.
- Lanes - every frame carries a lane discriminant. `Engine` traffic feeds the MPC engine inbox; `Control` traffic (`take_control_inbox`, `send_control`, `send_control_to_client`) carries application protocols such as [tightbeam-vm](../tightbeam-vm) program submission and reveals, without ever entering the engine.
- `MeshConfig` - stream concurrency cap, establishment deadline, dial retry pacing, inbox depth, saturated-send deadline, and the mesh's trace handle.
- `TraceHandle` - a shareable wrapper over tightbeam's trace collector, injected the way upstream feeds its colony components: inject one handle and the component records lifecycle events from inside its real code paths. The mesh traces link lifecycle (`link_up`, `link_dead`, `redial`, `send_saturated`, and `client_` twins) through `MeshConfig::trace`; sessions trace their round transitions through `with_trace`. The default handle is an isolated collector nobody observes.
- `PartySession` / `ClientSession` (`session` feature) - pre-agreed HoneyBadger round lifecycle (`Idle -> Preprocessing -> Ready -> Input -> Computing -> Output -> Finished`) over the mesh. No separate coordinator process. Each forward transition and failure back-edge is traced under the round-lifecycle event names, so verification runs can refine the live phase sequence against the CSP model.

## Usage

```rust
let roster = Roster::new(entries)?; // every party: id, address, certificate
let network = Arc::new(TightbeamNetwork::establish(roster, identity, MeshConfig::default()).await?);

// One message loop per party: mesh deliveries into the engine.
let mut inbox = network.take_inbox().expect("first take");
let mut engine = node.clone();
let net = Arc::clone(&network);
tokio::spawn(async move {
	while let Some((sender, raw)) = inbox.recv().await {
		let _ = engine.process(sender, raw, Arc::clone(&net)).await;
	}
});

// The engine drives the network for every protocol phase.
node.run_preprocessing(Arc::clone(&network), &mut rng).await?;
let products = node.mul(x_shares, y_shares, Arc::clone(&network)).await?;
```

Broadcast is send-to-everyone including self; self-sends loop straight into the local inbox, matching the reference network semantics the engine's all-to-all rounds assume.

## Features

- `testing` - `PartyMaterials`: mint self-signed party and consumer identities so a whole test roster exists in one call.
- `session` - `PartySession` / `ClientSession` HoneyBadger round helpers (depends on `stoffelcrypto`).

## Related

The integration tests run real multi-party HoneyBadgerMPC sessions over localhost TCP: [tests/honeybadger_e2e.rs](tests/honeybadger_e2e.rs) covers the party mesh (preprocessing, Beaver multiplication, output reconstruction), [tests/consumer_e2e.rs](tests/consumer_e2e.rs) covers the full consumer flow through `PartySession` / `ClientSession`, and [tests/session_rounds.rs](tests/session_rounds.rs) covers wrong-round rejection and client-readiness timeouts.

[tests/round_fdr.rs](tests/round_fdr.rs) model-checks the session round lifecycle with tightbeam's verification framework: the `Round` machine is modeled as a CSP process spec and explored with seeded FDR under fault injection on every forward transition. The happy-path scenario then runs a real three-party round over localhost TCP with the scenario collector injected into one party's session, so the trace that must refine the spec is the phase sequence `PartySession` actually performed on the wire. The `testing-*` features forward to tightbeam's own (the framework macros expand their feature gates into the calling crate) and are dev-enabled through the self dev-dependency.

See the [repository README](../../README.md) for development and release workflows.

## License

Licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.
