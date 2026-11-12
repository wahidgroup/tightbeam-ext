//! gRPC-Web on a coupled edge: the browser origins it serves, and the CORS
//! answers that let a page of each one call.
//!
//! # Sources
//!
//! - gRPC-Web, `grpc/grpc` `doc/PROTOCOL-WEB.md`:
//!   <https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md>
//! - Fetch Standard, CORS protocol: <https://fetch.spec.whatwg.org/#http-cors-protocol>
//! - RFC 6454, The Web Origin Concept, December 2011, section 6.1:
//!   <https://www.rfc-editor.org/rfc/rfc6454#section-6.1>

use core::convert::Infallible;
use core::str::FromStr;
use std::sync::Arc;

use http::header::{
	ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
	ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_REQUEST_HEADERS,
	ACCESS_CONTROL_REQUEST_METHOD, CONTENT_TYPE, ORIGIN, VARY,
};
use http::uri::Authority;
use http::{HeaderMap, HeaderValue, Method, Request as HttpRequest, Response as HttpResponse, StatusCode};
use tonic::body::Body;
use tonic_web::GrpcWebLayer;
use tower_layer::Layer;
use tower_service::Service;

use super::error::CoupleError;
use crate::tunnel::BoxFuture;

/// The response metadata that a page may read: the status of each call.
const EXPOSED: HeaderValue = HeaderValue::from_static("grpc-status, grpc-message, grpc-status-details-bin");

/// How long a browser keeps a preflight answer, in seconds.
const PREFLIGHT_AGE: HeaderValue = HeaderValue::from_static("600");

/// The one method of a gRPC-Web call.
const POST: HeaderValue = HeaderValue::from_static("POST");

/// The content types of a gRPC-Web call, as tonic-web `call.rs` matches them.
const GRPC_WEB_TYPES: [&[u8]; 4] = [
	b"application/grpc-web",
	b"application/grpc-web+proto",
	b"application/grpc-web-text",
	b"application/grpc-web-text+proto",
];

/// The browser origins that a coupled edge serves gRPC-Web to.
#[derive(Clone, Debug)]
pub(crate) struct WebOrigins {
	origins: Arc<[HeaderValue]>,
}

/// What one call of a gRPC-Web edge is.
pub(crate) enum WebCall {
	/// The preflight of a page of an allowed origin.
	Preflight(HeaderValue),
	/// A gRPC-Web call, from a page of an allowed origin, or from no page.
	Web(Option<HeaderValue>),
	/// A preflight or a gRPC-Web call from a page of another origin.
	Foreign,
	/// A gRPC call, which the edge serves as it serves any other.
	Native,
}

impl WebOrigins {
	/// The origins of `origins`, each a scheme, a host, and a port when it is
	/// not the default, such as `https://shop.example`.
	///
	/// # Errors
	///
	/// - [`CoupleError::Origin`] -- an origin of `origins` that the variant
	///   describes.
	pub(crate) fn new<O: AsRef<str>>(origins: impl IntoIterator<Item = O>) -> Result<Self, CoupleError> {
		let parsed: Result<Vec<HeaderValue>, CoupleError> =
			origins.into_iter().map(|origin| Self::origin(origin.as_ref())).collect();
		Ok(Self { origins: Arc::from(parsed?) })
	}

	/// The header value of `origin` in the serialization of RFC 6454 section
	/// 6.2, as a browser sends it: the scheme and the host in lowercase, and
	/// the port only when it is not the default of the scheme.
	fn origin(origin: &str) -> Result<HeaderValue, CoupleError> {
		let refused = || CoupleError::Origin(origin.to_owned());
		let (scheme, authority) = origin.split_once("://").ok_or_else(refused)?;
		let scheme = scheme.to_ascii_lowercase();
		let default_port = match scheme.as_str() {
			"https" => 443,
			"http" => 80,
			_ => return Err(refused()),
		};

		let bare = !authority.contains(['/', '?', '#', '*', '@']);
		let authority = Authority::from_str(authority).ok();
		let authority = authority
			.filter(|parsed| bare && !parsed.host().is_empty())
			.ok_or_else(refused)?;
		let (host, port) = authority.as_str().split_at(authority.host().len());
		let port = match port.strip_prefix(':') {
			Some(digits) if digits.bytes().all(|byte| byte.is_ascii_digit()) => {
				Some(digits.parse::<u16>().map_err(|_| refused())?)
			}
			Some(_) => return Err(refused()),
			None => None,
		};

		let host = host.to_ascii_lowercase();
		let serialized = match port.filter(|port| *port != default_port) {
			Some(port) => format!("{scheme}://{host}:{port}"),
			None => format!("{scheme}://{host}"),
		};

		HeaderValue::from_str(&serialized).map_err(|_| refused())
	}

	/// What a call of `method` with `headers` is.
	pub(crate) fn call_of(&self, method: &Method, headers: &HeaderMap) -> WebCall {
		let origin = headers.get(ORIGIN);
		let allowed = origin.filter(|origin| self.origins.contains(origin)).cloned();
		let preflight = method == Method::OPTIONS && headers.contains_key(ACCESS_CONTROL_REQUEST_METHOD);
		let web = headers.get(CONTENT_TYPE).is_some_and(Self::is_grpc_web);

		match (preflight, web, origin, allowed) {
			(true, _, _, Some(allowed)) => WebCall::Preflight(allowed),
			(true, _, _, None) => WebCall::Foreign,
			(false, true, None, _) => WebCall::Web(None),
			(false, true, Some(_), Some(allowed)) => WebCall::Web(Some(allowed)),
			(false, true, Some(_), None) => WebCall::Foreign,
			(false, false, _, _) => WebCall::Native,
		}
	}

	/// Whether `content_type` is one of the four gRPC-Web types that tonic-web
	/// translates, byte for byte, so the edge and tonic-web agree on every
	/// call.
	fn is_grpc_web(content_type: &HeaderValue) -> bool {
		GRPC_WEB_TYPES.contains(&content_type.as_bytes())
	}
}

impl WebCall {
	/// Serve `request` as this kind of call: answer the preflight of an
	/// allowed origin, refuse another origin, translate a gRPC-Web call for
	/// `native`, the native arm of the edge, and hand a native call to it.
	///
	/// `native` is always ready, so the call reaches it with no wait.
	pub(crate) fn serve<S>(
		self,
		request: HttpRequest<Body>,
		mut native: S,
	) -> BoxFuture<Result<HttpResponse<Body>, Infallible>>
	where
		S: Service<HttpRequest<Body>, Response = HttpResponse<Body>, Error = Infallible> + Send + 'static,
		S::Future: Send + 'static,
	{
		match self {
			Self::Preflight(origin) => {
				let answer = Self::preflight(origin, request.headers());
				Box::pin(core::future::ready(Ok(answer)))
			}
			Self::Foreign => Box::pin(core::future::ready(Ok(Self::forbidden()))),
			Self::Web(origin) => {
				let mut translated = GrpcWebLayer::new().layer(native);
				Box::pin(async move {
					let mut answer = translated.call(request).await?;
					if let Some(origin) = origin {
						Self::allow(&mut answer, origin);
					}
					Ok(answer)
				})
			}
			Self::Native => Box::pin(native.call(request)),
		}
	}

	/// The answer to the preflight of a page of `origin` that asks for the
	/// request headers of `requested`.
	fn preflight(origin: HeaderValue, requested: &HeaderMap) -> HttpResponse<Body> {
		let mut response = HttpResponse::new(Body::empty());
		*response.status_mut() = StatusCode::NO_CONTENT;
		let headers = response.headers_mut();
		headers.insert(ACCESS_CONTROL_ALLOW_METHODS, POST);
		headers.insert(ACCESS_CONTROL_MAX_AGE, PREFLIGHT_AGE);
		if let Some(asked) = requested.get(ACCESS_CONTROL_REQUEST_HEADERS) {
			headers.insert(ACCESS_CONTROL_ALLOW_HEADERS, asked.clone());
		}

		Self::allow(&mut response, origin);
		response
	}

	/// Let a page of `origin` read `response`, and the status it carries.
	fn allow(response: &mut HttpResponse<Body>, origin: HeaderValue) {
		let headers = response.headers_mut();
		headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
		headers.insert(ACCESS_CONTROL_EXPOSE_HEADERS, EXPOSED);
		headers.append(VARY, HeaderValue::from_static("origin"));
	}

	/// The refusal of a page of another origin.
	fn forbidden() -> HttpResponse<Body> {
		let mut response = HttpResponse::new(Body::empty());
		*response.status_mut() = StatusCode::FORBIDDEN;
		response.headers_mut().insert(VARY, HeaderValue::from_static("origin"));
		response
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use http::Request;

	/// What an edge that serves `configured` takes a call of `method` with
	/// `headers` for.
	fn classify(configured: &str, method: Method, headers: &[(&'static str, &'static str)]) -> WebCall {
		let web = WebOrigins::new([configured]).expect("the configured origin is admitted");
		let mut request = Request::builder().method(method).uri("/orders.v1.Orders/Browse");
		for (key, value) in headers {
			request = request.header(*key, *value);
		}

		let head = request.body(()).expect("a test head builds").into_parts().0;
		web.call_of(&head.method, &head.headers)
	}

	/// The name of the arm of `call`.
	fn arm(call: &WebCall) -> &'static str {
		match call {
			WebCall::Preflight(_) => "preflight",
			WebCall::Web(Some(_)) => "web from a page",
			WebCall::Web(None) => "web from no page",
			WebCall::Foreign => "foreign",
			WebCall::Native => "native",
		}
	}

	const SHOP: (&str, &str) = ("origin", "https://shop.example");
	const EVIL: (&str, &str) = ("origin", "https://evil.example");
	const ASKS: (&str, &str) = ("access-control-request-method", "POST");
	const TEXT: (&str, &str) = ("content-type", "application/grpc-web-text+proto");

	tightbeam::tb_cases! {
		fn each_call_takes_the_arm_of_its_origin_and_its_media((method, headers, expected): (Method, Vec<(&'static str, &'static str)>, &str)) {
			assert_eq!(arm(&classify("https://shop.example", method, &headers)), expected);
		}

		cases {
			a_preflight_of_the_shop => (Method::OPTIONS, vec![SHOP, ASKS], "preflight"),
			a_preflight_of_another_origin => (Method::OPTIONS, vec![EVIL, ASKS], "foreign"),
			a_call_of_the_shop => (Method::POST, vec![SHOP, TEXT], "web from a page"),
			a_call_from_no_page => (Method::POST, vec![TEXT], "web from no page"),
			a_call_of_another_origin => (Method::POST, vec![EVIL, TEXT], "foreign"),
			a_grpc_call => (Method::POST, vec![SHOP, ("content-type", "application/grpc")], "native"),
			a_media_type_that_tonic_web_does_not_translate => (
				Method::POST,
				vec![("content-type", "application/grpc-web+json")],
				"native"
			),
		}
	}

	tightbeam::tb_cases! {
		fn an_origin_off_the_grammar_is_refused(origin: &str) {
			assert!(WebOrigins::new([origin]).is_err());
		}

		cases {
			a_wildcard => "*",
			no_scheme => "shop.example",
			no_host => "https://",
			a_path => "https://shop.example/",
			another_scheme => "ftp://shop.example",
			a_wildcard_host => "https://*.example",
			a_user => "https://user@shop.example",
			a_port_off_its_range => "https://shop.example:65536",
			a_signed_port => "https://shop.example:+443",
			an_empty_port => "https://shop.example:",
			no_host_before_a_port => "https://:8080",
			a_query => "https://shop.example?page=1",
			a_fragment => "https://shop.example#top",
			a_space_in_the_host => "https://shop example",
			a_host_outside_ascii => "https://café.example",
			a_percent_in_the_host => "https://shop%41.example",
			an_unmatched_bracket => "https://[::1",
		}
	}

	tightbeam::tb_cases! {
		fn a_configured_origin_serves_the_page_of_its_serialization(configured: &str) {
			assert_eq!(arm(&classify(configured, Method::OPTIONS, &[SHOP, ASKS])), "preflight");
		}

		cases {
			an_uppercase_host => "https://Shop.example",
			an_uppercase_scheme => "HTTPS://shop.example",
			the_default_port => "https://shop.example:443",
			a_leading_zero_port => "https://shop.example:0443",
		}
	}

	tightbeam::tb_cases! {
		fn an_address_origin_serves_the_page_of_its_serialization((configured, page): (&str, &'static str)) {
			assert_eq!(arm(&classify(configured, Method::OPTIONS, &[("origin", page), ASKS])), "preflight");
		}

		cases {
			an_ipv6_host => ("https://[::1]:443", "https://[::1]"),
			an_ipv4_host_and_its_port => ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
		}
	}

	#[test]
	fn an_origin_with_a_port_is_admitted() {
		assert!(WebOrigins::new(["http://localhost:8080"]).is_ok());
	}
}
