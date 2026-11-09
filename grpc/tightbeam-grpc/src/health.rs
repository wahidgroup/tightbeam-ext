//! The `grpc.health.v1.Health/Check` call of an edge.
//!
//! A load balancer or an orchestrator probes an edge with the standard health
//! check. The check names the whole server with an empty service, which is
//! the one service an edge answers for: a tunnel edge serves while it
//! listens, and a coupled edge serves while its loopback session is open.
//! Each message has one field, so the edge encodes both by hand.
//!
//! # Sources
//!
//! - gRPC health checking, `grpc/grpc` `doc/health-checking.md`: <https://github.com/grpc/grpc/blob/master/doc/health-checking.md>
//! - Protocol Buffers encoding, `protobuf.dev/programming-guides/encoding`: <https://protobuf.dev/programming-guides/encoding/>

use tonic::{Response, Status};

/// The path of the health check, which a probe calls on every edge.
pub const HEALTH_CHECK_PATH: &str = "/grpc.health.v1.Health/Check";

/// The tag of field 1 as a length-delimited value: the `service` of a
/// `HealthCheckRequest`.
const SERVICE_TAG: u8 = 0x0a;

/// The tag of field 1 as a varint: the `status` of a `HealthCheckResponse`.
const STATUS_TAG: u8 = 0x08;

/// The `ServingStatus` of a health check answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HealthStatus {
	Serving = 1,
	/// A coupled edge whose loopback session is not open.
	#[cfg(feature = "couple")]
	NotServing = 2,
}

impl HealthStatus {
	/// The status of an edge whose service carries calls when `serving`.
	#[cfg(feature = "couple")]
	pub(crate) fn of(serving: bool) -> Self {
		if serving {
			Self::Serving
		} else {
			Self::NotServing
		}
	}

	/// The answer to `request`, the encoded `HealthCheckRequest` of a probe.
	///
	/// # Errors
	///
	/// - `NOT_FOUND` -- the request names a service, because the edge answers for the server alone.
	/// - `INVALID_ARGUMENT` -- the request does not decode.
	pub(crate) fn answer(self, request: &[u8]) -> Result<Response<Vec<u8>>, Status> {
		let service = Self::service_of(request)?;
		if !service.is_empty() {
			return Err(Status::not_found("the edge answers for the whole server alone"));
		}

		Ok(Response::new(vec![STATUS_TAG, self as u8]))
	}

	/// The `service` of an encoded `HealthCheckRequest`, empty when the
	/// request omits it. Field 1 is the one field of the message.
	fn service_of(request: &[u8]) -> Result<&[u8], Status> {
		let malformed = || Status::invalid_argument("the health check request does not decode");
		let Some((&tag, rest)) = request.split_first() else {
			return Ok(&[]);
		};
		if tag != SERVICE_TAG {
			return Err(malformed());
		}

		let (length, rest) = Self::varint(rest).ok_or_else(malformed)?;
		let length = usize::try_from(length).map_err(|_| malformed())?;
		if rest.len() != length {
			return Err(malformed());
		}

		Ok(rest)
	}

	/// The varint at the head of `bytes`, and the bytes after it.
	fn varint(bytes: &[u8]) -> Option<(u64, &[u8])> {
		let mut value = 0_u64;
		for (index, byte) in bytes.iter().enumerate().take(10) {
			value |= u64::from(byte & 0x7f) << (7 * index);
			if byte & 0x80 == 0 {
				return Some((value, &bytes[index + 1..]));
			}
		}

		None
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn an_empty_request_reads_the_status_of_the_server() -> Result<(), Status> {
		let serving = HealthStatus::Serving.answer(&[])?;
		assert_eq!(serving.into_inner(), [0x08, 0x01]);

		let named = [0x0a, 0x00];
		let empty_named = HealthStatus::Serving.answer(&named)?;
		assert_eq!(empty_named.into_inner(), [0x08, 0x01]);

		#[cfg(feature = "couple")]
		{
			let not_serving = HealthStatus::NotServing.answer(&[])?;
			assert_eq!(not_serving.into_inner(), [0x08, 0x02]);
		}
		Ok(())
	}

	#[test]
	fn a_named_service_or_a_malformed_request_is_refused() {
		let named = HealthStatus::Serving.answer(b"\x0a\x03abc");
		assert_eq!(named.map(|_| ()).map_err(|status| status.code()), Err(tonic::Code::NotFound));

		for malformed in [&b"\x12\x00"[..], b"\x0a\x05abc", b"\x0a\xff"] {
			let refused = HealthStatus::Serving.answer(malformed);
			assert_eq!(
				refused.map(|_| ()).map_err(|status| status.code()),
				Err(tonic::Code::InvalidArgument)
			);
		}
	}
}
