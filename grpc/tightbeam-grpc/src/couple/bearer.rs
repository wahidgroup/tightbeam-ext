//! Bearer callers: a JWT-SVID in the `authorization` metadata, under ES256
//! keys that the edge pins from its profile.
//!
//! # Sources
//!
//! - JWT-SVID, `spiffe/spiffe` `standards/JWT-SVID.md`:
//!   <https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md>
//! - RFC 7519, JSON Web Token, May 2015: <https://www.rfc-editor.org/rfc/rfc7519>
//! - RFC 7518, JSON Web Algorithms, May 2015, section 3.4:
//!   <https://www.rfc-editor.org/rfc/rfc7518#section-3.4>
//! - RFC 7517, JSON Web Key, May 2015: <https://www.rfc-editor.org/rfc/rfc7517>
//! - RFC 6750, Bearer Token Usage, October 2012, section 2.1:
//!   <https://www.rfc-editor.org/rfc/rfc6750#section-2.1>

use core::fmt;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http::HeaderMap;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::EncodedPoint;
use serde_json::{Map, Value};

use super::error::CoupleError;
use super::principal::{Principal, SpiffeId, TrustDomain};

/// The longest token that the edge reads.
const MAX_TOKEN: usize = 8 * 1024;

/// The scheme of a bearer `authorization` value.
const BEARER: &str = "Bearer ";

/// The trust of a coupled edge in the bearer callers of one SPIFFE trust
/// domain: the audience that each token must name, and the ES256 keys of the
/// bundle of the domain, by key ID.
///
/// # Examples
///
/// ```
/// use tightbeam_grpc::couple::BearerTrust;
///
/// let jwks = r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"k1",
/// 	"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
/// 	"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}"#;
/// let trust = BearerTrust::from_jwks("acme", "spiffe://acme/orders-edge", jwks)?;
/// # Ok::<(), tightbeam_grpc::couple::CoupleError>(())
/// ```
#[derive(Clone)]
pub struct BearerTrust {
	/// The trust domain whose workloads the keys may sign for.
	domain: TrustDomain,
	audience: String,
	keys: Arc<HashMap<String, VerifyingKey>>,
	leeway: Duration,
}

impl BearerTrust {
	/// How far the clock of the issuer may run from the clock of the edge,
	/// unless [`BearerTrust::with_leeway`] sets it.
	pub const DEFAULT_LEEWAY: Duration = Duration::from_secs(30);

	/// The metadata key of a bearer token.
	pub(crate) const HEADER: &'static str = "authorization";

	/// Trust in the tokens for `audience` of the subjects of `trust_domain`,
	/// such as `acme`, that the keys of `jwks`, the JSON Web Key Set of the
	/// bundle of the domain, sign. A key counts when it has each of these, and
	/// every other key is passed over:
	///
	/// - `kty` `EC` on `P-256`, and an `x` and a `y` that name a point on the curve.
	/// - A `use` of `sig`, or none.
	/// - A `kid` that no later key of the set repeats.
	///
	/// # Errors
	///
	/// - [`CoupleError::Principal`] -- `trust_domain` is no trust domain:
	///   empty, or holding a byte off its grammar.
	/// - [`CoupleError::BearerKeys`] -- `jwks` is no key set, or holds no usable key.
	pub fn from_jwks(trust_domain: &str, audience: impl Into<String>, jwks: &str) -> Result<Self, CoupleError> {
		let domain = TrustDomain::parse(trust_domain).ok_or_else(|| CoupleError::Principal(trust_domain.to_owned()))?;

		let set: Value = serde_json::from_str(jwks).map_err(|error| CoupleError::BearerKeys(Some(error)))?;
		let entries = set.get("keys").and_then(Value::as_array).ok_or(CoupleError::BearerKeys(None))?;
		let keys: HashMap<String, VerifyingKey> = entries.iter().filter_map(Self::key_of).collect();
		if keys.is_empty() {
			return Err(CoupleError::BearerKeys(None));
		}

		Ok(Self {
			domain,
			audience: audience.into(),
			keys: Arc::new(keys),
			leeway: Self::DEFAULT_LEEWAY,
		})
	}

	/// Admit a token whose `exp` or `nbf` is off by up to `leeway`, in place
	/// of [`BearerTrust::DEFAULT_LEEWAY`].
	#[must_use]
	pub fn with_leeway(mut self, leeway: Duration) -> Self {
		self.leeway = leeway;
		self
	}

	/// The key ID and the key of one JSON Web Key, when it is an ES256 key.
	fn key_of(key: &Value) -> Option<(String, VerifyingKey)> {
		let field = |name: &str| key.get(name).and_then(Value::as_str);
		let usable = field("kty") == Some("EC") && field("crv") == Some("P-256");
		let signs = field("use").is_none_or(|purpose| purpose == "sig");
		if !usable || !signs {
			return None;
		}

		let coordinate = |name: &str| field(name).and_then(|text| URL_SAFE_NO_PAD.decode(text).ok());
		let x: [u8; 32] = coordinate("x")?.try_into().ok()?;
		let y: [u8; 32] = coordinate("y")?.try_into().ok()?;
		let point = EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);

		let verifying = VerifyingKey::from_encoded_point(&point).ok()?;
		Some((field("kid")?.to_owned(), verifying))
	}

	/// The principal of the bearer token in `headers` at `now`, `None` when
	/// they carry no `authorization` metadata.
	///
	/// # Errors
	///
	/// - The [`BearerRefusal`] of a token that is no ES256 JWT-SVID that a
	///   pinned key signed for the audience, at `now`.
	pub(crate) fn principal_of(
		&self,
		headers: &HeaderMap,
		now: SystemTime,
	) -> Option<Result<Principal, BearerRefusal>> {
		let value = headers.get(Self::HEADER)?;
		let token = value.to_str().ok().and_then(Self::token_of);
		Some(token.ok_or(BearerRefusal).and_then(|token| self.verify(token, now)))
	}

	/// The token of a bearer `authorization` value, whose scheme matches in
	/// any case.
	fn token_of(value: &str) -> Option<&str> {
		let (scheme, token) = value.split_at_checked(BEARER.len())?;
		let bearer = scheme.eq_ignore_ascii_case(BEARER);
		bearer
			.then_some(token.trim())
			.filter(|token| !token.is_empty() && token.len() <= MAX_TOKEN)
	}

	/// The principal of `token` at `now`: its `sub`, once its signature
	/// verifies under the key of its `kid`, its `aud` names the audience,
	/// `now` falls within its `nbf` and its `exp`, and the `sub` is the SPIFFE
	/// ID of a workload of the trust domain.
	///
	/// # Errors
	///
	/// - The [`BearerRefusal`] of a step that fails.
	fn verify(&self, token: &str, now: SystemTime) -> Result<Principal, BearerRefusal> {
		let (signed, signature) = token.rsplit_once('.').ok_or(BearerRefusal)?;
		let (header, payload) = signed.split_once('.').ok_or(BearerRefusal)?;
		if payload.contains('.') {
			return Err(BearerRefusal);
		}

		let header = Self::json(header)?;
		let algorithm = header.get("alg").and_then(Value::as_str);
		let typed = header
			.get("typ")
			.and_then(Value::as_str)
			.is_none_or(|typ| typ == "JWT" || typ == "JOSE");
		if algorithm != Some("ES256") || !typed {
			return Err(BearerRefusal);
		}

		let kid = header.get("kid").and_then(Value::as_str).ok_or(BearerRefusal)?;
		let key = self.keys.get(kid).ok_or(BearerRefusal)?;
		let signature = URL_SAFE_NO_PAD.decode(signature).map_err(|_| BearerRefusal)?;
		let signature = Signature::from_slice(&signature).map_err(|_| BearerRefusal)?;
		key.verify(signed.as_bytes(), &signature).map_err(|_| BearerRefusal)?;

		let claims = Self::json(payload)?;
		self.admits(&claims, now)?;

		let subject = claims.get("sub").and_then(Value::as_str).ok_or(BearerRefusal)?;
		let subject = SpiffeId::parse(subject).filter(|subject| self.domain.holds(subject));
		subject.map(Principal::of_spiffe).ok_or(BearerRefusal)
	}

	/// Refuse `claims` unless they name the audience and `now` falls within
	/// their `nbf` and their required `exp`, each widened by the leeway.
	/// An `nbf` or an `exp` that is no NumericDate refuses them.
	fn admits(&self, claims: &Map<String, Value>, now: SystemTime) -> Result<(), BearerRefusal> {
		let audience = match claims.get("aud") {
			Some(Value::String(audience)) => *audience == self.audience,
			Some(Value::Array(audiences)) => audiences.iter().any(|audience| audience.as_str() == Some(&self.audience)),
			_ => false,
		};
		if !audience {
			return Err(BearerRefusal);
		}

		let now = now.duration_since(UNIX_EPOCH).map_err(|_| BearerRefusal)?;
		let expires = Self::date(claims, "exp")?.ok_or(BearerRefusal)?;
		let not_before = Self::date(claims, "nbf")?;

		let current = now < expires.saturating_add(self.leeway);
		let started = not_before.is_none_or(|not_before| not_before <= now.saturating_add(self.leeway));
		if !current || !started {
			return Err(BearerRefusal);
		}

		Ok(())
	}

	/// The NumericDate of the claim `name` of `claims`, `None` when they
	/// carry no such claim.
	///
	/// - A NumericDate is a JSON number of seconds since the epoch, which may
	///   hold a fraction.
	///
	/// # Errors
	///
	/// - [`BearerRefusal`] -- the claim is no number of seconds that a
	///   `Duration` holds.
	fn date(claims: &Map<String, Value>, name: &str) -> Result<Option<Duration>, BearerRefusal> {
		let Some(value) = claims.get(name) else {
			return Ok(None);
		};

		let whole = value.as_u64().map(Duration::from_secs);
		let fractional = || value.as_f64().and_then(|seconds| Duration::try_from_secs_f64(seconds).ok());
		whole.or_else(fractional).map(Some).ok_or(BearerRefusal)
	}

	/// The JSON object of one base64url part of a token.
	fn json(part: &str) -> Result<Map<String, Value>, BearerRefusal> {
		let decoded = URL_SAFE_NO_PAD.decode(part).map_err(|_| BearerRefusal)?;
		match serde_json::from_slice(&decoded) {
			Ok(Value::Object(object)) => Ok(object),
			_ => Err(BearerRefusal),
		}
	}
}

impl fmt::Debug for BearerTrust {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let mut kids: Vec<&String> = self.keys.keys().collect();
		kids.sort();
		f.debug_struct("BearerTrust")
			.field("domain", &self.domain.as_str())
			.field("audience", &self.audience)
			.field("keys", &kids)
			.field("leeway", &self.leeway)
			.finish()
	}
}

/// A bearer token that the edge refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BearerRefusal;

#[cfg(test)]
mod tests {
	use super::*;

	use p256::ecdsa::signature::Signer;
	use p256::ecdsa::SigningKey;
	use rand_core::OsRng;

	const AUDIENCE: &str = "spiffe://acme/orders-edge";

	/// The header of a token of the pinned key.
	const HEADER: &str = r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#;

	/// The claims of a token that admits at [`now`].
	const CLAIMS: &str = r#"{"sub":"spiffe://acme/web","aud":"spiffe://acme/orders-edge","exp":1800000060}"#;

	/// The one key of a test, and a second key that no set pins.
	struct Keys {
		pinned: SigningKey,
		other: SigningKey,
	}

	impl Keys {
		fn create() -> Self {
			Self { pinned: SigningKey::random(&mut OsRng), other: SigningKey::random(&mut OsRng) }
		}

		/// A key set of the pinned key under `k1`, beside a key of another
		/// type.
		fn jwks(&self) -> String {
			let point = self.pinned.verifying_key().to_encoded_point(false);
			let x = URL_SAFE_NO_PAD.encode(point.x().expect("an uncompressed point"));
			let y = URL_SAFE_NO_PAD.encode(point.y().expect("an uncompressed point"));
			format!(
				r#"{{"keys":[{{"kty":"RSA","kid":"rsa"}},{{"kty":"EC","crv":"P-256","kid":"k1","x":"{x}","y":"{y}"}}]}}"#
			)
		}

		/// The trust of the domain `acme` in the pinned key, with `leeway`.
		fn trust(&self, leeway: Duration) -> BearerTrust {
			let trust = BearerTrust::from_jwks("acme", AUDIENCE, &self.jwks()).expect("the test key set admits");
			trust.with_leeway(leeway)
		}
	}

	/// The two JSON parts of a token: its header and its claims.
	#[derive(Clone, Copy)]
	struct TokenParts<'a> {
		header: &'a str,
		claims: &'a str,
	}

	/// A token of `parts`, signed under `signing`.
	fn token(signing: &SigningKey, parts: TokenParts<'_>) -> String {
		let signed = format!(
			"{}.{}",
			URL_SAFE_NO_PAD.encode(parts.header),
			URL_SAFE_NO_PAD.encode(parts.claims)
		);
		let signature: Signature = signing.sign(signed.as_bytes());
		format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
	}

	fn now() -> SystemTime {
		UNIX_EPOCH + Duration::from_secs(1_800_000_000)
	}

	/// What the trust of the pinned key reads of a token of `parts`, signed
	/// under the pinned key, with no leeway.
	fn verified(parts: TokenParts<'_>) -> Result<Principal, BearerRefusal> {
		let keys = Keys::create();
		keys.trust(Duration::ZERO).verify(&token(&keys.pinned, parts), now())
	}

	#[test]
	fn a_pinned_svid_for_the_audience_names_its_subject() -> Result<(), CoupleError> {
		let principal = verified(TokenParts { header: HEADER, claims: CLAIMS });
		assert_eq!(principal, Ok(Principal::spiffe("spiffe://acme/web")?));
		Ok(())
	}

	#[test]
	fn a_jose_typ_admits() {
		let header = r#"{"alg":"ES256","kid":"k1","typ":"JOSE"}"#;
		assert!(verified(TokenParts { header, claims: CLAIMS }).is_ok());
	}

	#[test]
	fn an_audience_in_a_list_admits() {
		let claims = r#"{"sub":"spiffe://acme/web","aud":["other","spiffe://acme/orders-edge"],"exp":1800000060}"#;
		assert!(verified(TokenParts { header: HEADER, claims }).is_ok());
	}

	#[test]
	fn a_token_of_another_key_is_refused() {
		let keys = Keys::create();
		let forged = token(&keys.other, TokenParts { header: HEADER, claims: CLAIMS });
		assert_eq!(keys.trust(Duration::ZERO).verify(&forged, now()), Err(BearerRefusal));
	}

	#[test]
	fn a_leeway_admits_a_token_that_expired_within_it() {
		let keys = Keys::create();
		let expired = r#"{"sub":"spiffe://acme/web","aud":"spiffe://acme/orders-edge","exp":1799999990}"#;
		let late = token(&keys.pinned, TokenParts { header: HEADER, claims: expired });
		assert!(keys.trust(Duration::from_secs(30)).verify(&late, now()).is_ok());
	}

	#[test]
	fn a_fractional_current_expiry_admits() {
		let claims = r#"{"sub":"spiffe://acme/web","aud":"spiffe://acme/orders-edge","exp":1800000060.5}"#;
		assert!(verified(TokenParts { header: HEADER, claims }).is_ok());
	}

	#[test]
	fn an_expiry_at_the_end_of_time_never_overflows() {
		let claims = r#"{"sub":"spiffe://acme/web","aud":"spiffe://acme/orders-edge","exp":18446744073709551615}"#;
		let keys = Keys::create();
		let token = token(&keys.pinned, TokenParts { header: HEADER, claims });
		assert!(keys.trust(Duration::MAX).verify(&token, now()).is_ok());
	}

	tightbeam::tb_cases! {
		fn a_token_off_any_rule_is_refused((header, claims): (&str, &str)) {
			assert_eq!(verified(TokenParts { header, claims }), Err(BearerRefusal));
		}

		cases {
			an_unknown_kid => (r#"{"alg":"ES256","kid":"k2"}"#, CLAIMS),
			no_kid => (r#"{"alg":"ES256"}"#, CLAIMS),
			alg_none => (r#"{"alg":"none","kid":"k1"}"#, CLAIMS),
			alg_hs256 => (r#"{"alg":"HS256","kid":"k1"}"#, CLAIMS),
			a_foreign_typ => (r#"{"alg":"ES256","kid":"k1","typ":"at+jwt"}"#, CLAIMS),
			expired => (HEADER, r#"{"sub":"spiffe://acme/web","aud":"spiffe://acme/orders-edge","exp":1799999900}"#),
			no_exp => (HEADER, r#"{"sub":"spiffe://acme/web","aud":"spiffe://acme/orders-edge","iat":1800000000}"#),
			not_yet_valid => (
				HEADER,
				r#"{"sub":"spiffe://acme/web","aud":"spiffe://acme/orders-edge","exp":1800000600,"nbf":1800000300}"#
			),
			a_fractional_future_nbf => (
				HEADER,
				r#"{"sub":"spiffe://acme/web","aud":"spiffe://acme/orders-edge","exp":1800000600,"nbf":1800000300.5}"#
			),
			a_string_nbf => (
				HEADER,
				r#"{"sub":"spiffe://acme/web","aud":"spiffe://acme/orders-edge","exp":1800000600,"nbf":"1799999000"}"#
			),
			another_audience => (HEADER, r#"{"sub":"spiffe://acme/web","aud":"other","exp":1800000060}"#),
			a_subject_of_another_trust_domain => (
				HEADER,
				r#"{"sub":"spiffe://evil/web","aud":"spiffe://acme/orders-edge","exp":1800000060}"#
			),
			the_trust_domain_itself => (
				HEADER,
				r#"{"sub":"spiffe://acme/","aud":"spiffe://acme/orders-edge","exp":1800000060}"#
			),
			the_trust_domain_with_no_slash => (
				HEADER,
				r#"{"sub":"spiffe://acme","aud":"spiffe://acme/orders-edge","exp":1800000060}"#
			),
			a_subject_that_is_no_spiffe_id => (HEADER, r#"{"sub":"web","aud":"spiffe://acme/orders-edge","exp":1800000060}"#),
		}
	}

	tightbeam::tb_cases! {
		fn a_value_off_the_token_grammar_is_refused(token: &str) {
			let keys = Keys::create();
			assert_eq!(keys.trust(Duration::ZERO).verify(token, now()), Err(BearerRefusal));
		}

		cases {
			two_parts => "a.b",
			four_parts => "a.b.c.d",
			no_base64 => "!.!.!",
		}
	}

	tightbeam::tb_cases! {
		fn the_scheme_matches_in_any_case((value, token): (&str, Option<&str>)) {
			assert_eq!(BearerTrust::token_of(value), token);
		}

		cases {
			lowercase => ("bearer abc", Some("abc")),
			uppercase => ("BEARER abc", Some("abc")),
			another_scheme => ("Basic abc", None),
			no_token => ("Bearer ", None),
		}
	}

	tightbeam::tb_cases! {
		fn a_trust_domain_off_its_grammar_is_refused(domain: &str) {
			let keys = Keys::create();
			assert!(BearerTrust::from_jwks(domain, AUDIENCE, &keys.jwks()).is_err());
		}

		cases {
			empty => "",
			a_path => "acme/orders",
			uppercase => "Acme",
		}
	}

	tightbeam::tb_cases! {
		fn a_key_set_with_no_usable_key_is_refused(jwks: &str) {
			assert!(BearerTrust::from_jwks("acme", AUDIENCE, jwks).is_err());
		}

		cases {
			only_another_type => r#"{"keys":[{"kty":"RSA","kid":"rsa"}]}"#,
			an_encryption_key => r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","use":"enc","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}"#,
			no_key_set => "[]",
		}
	}
}
