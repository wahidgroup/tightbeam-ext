//! Work through the h2c Envoy hop of the docker stack, in the grpc e2e lane
//! under the `e2e` feature.

mod support;

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;
use tightbeam::colony::SubmitWork;
use tightbeam::instrumentation::events;
use tightbeam::testing::SetupEnv;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::PooledClient;
use tightbeam::urn::Urn;
use tightbeam::{at_least, exactly, tb_assert_spec, tb_scenario, urn, Frame, TightBeamError};
use tightbeam_grpc::protocol::{GrpcAddr, GrpcListener};
use tightbeam_ws::testing::{EnvVar, IdentityFiles, WorkClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use support::bounded;

/// The host port of Envoy, which the stack allocates.
const ENVOY_PORT: EnvVar = EnvVar::new("GRPC_ENVOY_HOST_PORT");

/// The loopback port of the admin endpoint of Envoy, which the stack
/// allocates.
const ENVOY_ADMIN_PORT: EnvVar = EnvVar::new("GRPC_ENVOY_ADMIN_HOST_PORT");

/// The directory of the stack identities.
const CERT_DIR: EnvVar = EnvVar::new("CERT_DIR");

/// The cluster of the gateway, which the route of each tunnel names.
const GATEWAY_CLUSTER: &str = "grpc_gateway";

/// The timeout of a route to the gateway, as the admin endpoint of Envoy
/// reports it.
const ROUTE_TIMEOUT: Urn<'static> = urn!("test", "event:envoy/route-timeout");

/// The stack: the address of Envoy by host name, the port of its admin
/// endpoint, and the client side of its work probe.
struct Stack {
	envoy: GrpcAddr,
	admin: u16,
	probe: WorkClient,
}

impl Stack {
	/// The stack that the e2e lane exports.
	fn from_env() -> Result<Self, TightBeamError> {
		let port: u16 = ENVOY_PORT.parsed().map_err(|_| TightBeamError::MissingConfiguration)?;
		let envoy = format!("localhost:{port}").parse()?;
		let admin = ENVOY_ADMIN_PORT.parsed().map_err(|_| TightBeamError::MissingConfiguration)?;

		let certs: PathBuf = CERT_DIR.parsed().map_err(|_| TightBeamError::MissingConfiguration)?;
		let gateway = IdentityFiles::new(&certs, "server")?.load()?;
		let work = Arc::new(IdentityFiles::new(&certs, "client")?.load()?);
		let probe = WorkClient::new(&gateway, work)?;
		Ok(Self { envoy, admin, probe })
	}

	/// The stack of the e2e lane, which every case of this file needs.
	fn exported() -> Self {
		let exported = Self::from_env();
		exported.expect("the grpc e2e lane exports the Envoy port and the stack identities")
	}

	/// A lease on a fresh pool to Envoy that pins the gateway identity and
	/// records on `trace`, so its first use dials a fresh tunnel.
	async fn lease(&self, trace: &TraceCollector) -> Result<PooledClient<GrpcListener>, TightBeamError> {
		let pool = self.probe.pool::<GrpcListener>(trace);
		pool.connect(self.envoy.clone()).await.map_err(TightBeamError::from)
	}

	/// Submit a probe work frame under `id` to the servlet type `servlet`.
	async fn submit(
		&self,
		lease: &mut PooledClient<GrpcListener>,
		servlet: tightbeam::urn::Urn<'static>,
		id: &[u8],
	) -> Result<Result<Frame, TightBeamError>, TightBeamError> {
		let work = self.probe.work(id).await?;
		Ok(lease.submit_work_to(servlet, &work).await)
	}

	/// Submit a probe work frame under `id` to the work probe, and require
	/// its verified answer.
	async fn round_trip(&self, lease: &mut PooledClient<GrpcListener>, id: &[u8]) -> Result<(), TightBeamError> {
		let served = self.submit(lease, WorkClient::probe()?, id).await??;
		let answer = self.probe.answer(&served)?;
		assert_eq!(
			answer.as_deref(),
			Some(&b"pong:3231:true"[..]),
			"the probe MUST verify the work end to end, both ways"
		);
		assert_eq!(served.metadata().id(), id, "the probe response MUST correlate with the work id");
		Ok(())
	}

	/// The configuration that the admin endpoint of Envoy reports, from
	/// `/config_dump`, which it answers over HTTP/1.1 alone.
	async fn config_dump(&self) -> Result<Value, TightBeamError> {
		let exchanged = async {
			let mut admin = TcpStream::connect(("127.0.0.1", self.admin)).await?;
			let request = b"GET /config_dump HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
			admin.write_all(request).await?;

			let mut answer = Vec::new();
			admin.read_to_end(&mut answer).await?;
			Ok::<_, io::Error>(answer)
		};

		let answer = bounded(exchanged).await??;
		Ok(serde_json::from_slice(&Self::body_of(&answer)?).map_err(io::Error::other)?)
	}

	/// The body of `answer`, an answer of the admin endpoint, which it sends
	/// in chunks (RFC 9112 section 7.1).
	fn body_of(answer: &[u8]) -> io::Result<Vec<u8>> {
		let truncated = || io::Error::other("the admin answer ends inside its body");
		let head = answer
			.windows(4)
			.position(|window| window == b"\r\n\r\n")
			.ok_or_else(truncated)?;
		let (mut rest, mut body) = (&answer[head + 4..], Vec::new());
		loop {
			let line = rest.windows(2).position(|window| window == b"\r\n").ok_or_else(truncated)?;
			let size = core::str::from_utf8(&rest[..line]).map_err(io::Error::other)?;
			let size = usize::from_str_radix(size.trim(), 16).map_err(io::Error::other)?;
			if size == 0 {
				return Ok(body);
			}

			let (chunk, after) = rest[line + 2..].split_at_checked(size).ok_or_else(truncated)?;
			body.extend_from_slice(chunk);
			rest = after.get(2..).ok_or_else(truncated)?;
		}
	}

	/// The timeout of each route in `config` to the cluster of the gateway.
	fn gateway_timeouts(config: &Value, timeouts: &mut Vec<String>) {
		match config {
			Value::Object(fields) => {
				let route = fields.get("route").and_then(Value::as_object);
				let to_gateway =
					route.filter(|route| route.get("cluster").and_then(Value::as_str) == Some(GATEWAY_CLUSTER));
				if let Some(route) = to_gateway {
					let timeout = route.get("timeout").and_then(Value::as_str).unwrap_or("absent");
					timeouts.push(timeout.to_owned());
				}

				fields.values().for_each(|field| Self::gateway_timeouts(field, timeouts));
			}
			Value::Array(items) => items.iter().for_each(|item| Self::gateway_timeouts(item, timeouts)),
			_ => {}
		}
	}
}

tb_assert_spec! {
	pub OneTunnelSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(1))
		]
	}
}

// One tunnel crosses the hop: the pool dials Envoy once, the handshake with
// the gateway completes through it, and the work round-trips.
tb_scenario! {
	name: submit_work_round_trips_through_envoy,
	spec: OneTunnelSpec,
	environment Bare {
		context: Stack::exported(),
		exec: |SetupEnv { trace, context }| async move {
			let mut lease = context.lease(&trace).await?;
			context.round_trip(&mut lease, b"grpc-hop-1").await
		}
	}
}

// An unserved type resolves to a typed refusal through the hop, on the one
// tunnel that the pool dialed.
tb_scenario! {
	name: an_unserved_type_resolves_to_a_work_refusal_through_envoy,
	spec: OneTunnelSpec,
	environment Bare {
		context: Stack::exported(),
		exec: |SetupEnv { trace, context }| async move {
			let mut lease = context.lease(&trace).await?;
			let refused = context.submit(&mut lease, WorkClient::servlet("unserved")?, b"grpc-hop-refused").await?;
			assert!(
				matches!(refused, Err(TightBeamError::WorkRefused(_))),
				"an unserved servlet type MUST resolve to a typed WorkRefused through the hop, got {refused:?}"
			);
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub TunnelsInARowSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(3)),
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(3))
		]
	}
}

// Three fresh tunnels in a row cross the pooled upstream of Envoy, and each
// completes its own handshake with the gateway.
tb_scenario! {
	name: tunnels_in_a_row_cross_the_pooled_upstream_of_envoy,
	spec: TunnelsInARowSpec,
	environment Bare {
		context: Stack::exported(),
		exec: |SetupEnv { trace, context }| async move {
			for id in [&b"grpc-hop-row-1"[..], b"grpc-hop-row-2", b"grpc-hop-row-3"] {
				let mut lease = context.lease(&trace).await?;
				context.round_trip(&mut lease, id).await?;
			}
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub RouteTimeoutSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(ROUTE_TIMEOUT, at_least!(1), equals!("0s"))
		]
	}
}

// The running hop routes each tunnel to the gateway with no route timeout,
// which Envoy reports as `0s` in each section of its configuration.
tb_scenario! {
	name: the_hop_routes_each_tunnel_with_no_route_timeout,
	spec: RouteTimeoutSpec,
	environment Bare {
		context: Stack::exported(),
		exec: |SetupEnv { trace, context }| async move {
			let mut timeouts = Vec::new();
			Stack::gateway_timeouts(&context.config_dump().await?, &mut timeouts);
			for timeout in timeouts {
				trace.event_with(ROUTE_TIMEOUT, &[], timeout)?;
			}
			Ok(())
		}
	}
}
