# Connect gRPC Systems to a Colony

For engineers who run a tightbeam colony and need stock gRPC clients or servers to talk to it. [The gRPC Transport](grpc.md) specifies the listener, the coupler and the backend adapter that these steps use.

## Contents

- [Serve stock gRPC callers](#serve-stock-grpc-callers)
- [Serve a streaming method](#serve-a-streaming-method)
- [Admit callers behind a proxy or with tokens](#admit-callers-behind-a-proxy-or-with-tokens)
- [Revoke a caller certificate](#revoke-a-caller-certificate)
- [Serve browser pages](#serve-browser-pages)
- [Read the client address behind a load balancer](#read-the-client-address-behind-a-load-balancer)
- [Run replicas of a coupled edge](#run-replicas-of-a-coupled-edge)
- [Call a stock gRPC server](#call-a-stock-grpc-server)
- [Fix a refused call](#fix-a-refused-call)

## Serve stock gRPC callers

1. Enable the `couple` feature of `tightbeam-grpc`, and add `tightbeam-ws` with its `colony` feature for the `WsListener` of the colony.
2. Write the edge profile, and declare the gateway with it:

    ```rust
    # mod profile {
    # #![allow(unexpected_cfgs)]
    use tightbeam::crypto::profiles::DefaultCryptoProvider;
    use tightbeam::{cluster, urn};
    use tightbeam_grpc::couple::{Assurance, CallerTrust, CallerTrustFiles, Coupler, Grants, Principal, Routes, Servlet};
    use tightbeam_grpc::edge::{Dial, DialTls, Edge, EdgeError, EdgeProfile, EdgeTls, EdgeTlsFiles};
    use tightbeam_grpc::protocol::GrpcListener;
    use tightbeam_ws::protocol::WsListener;
    # use tightbeam::crypto::x509::Certificate;
    # use tightbeam_grpc::couple::Voucher;
    # fn voucher() -> Result<Voucher, EdgeError> { unimplemented!() }
    # fn orders_signer() -> Certificate { unimplemented!() }

    struct Orders;

    impl EdgeProfile for Orders {
    	fn edge() -> Result<Edge, EdgeError> {
    		let tls = EdgeTls::from_pem(EdgeTlsFiles { chain: "/run/edge/tls.crt", key: "/run/edge/tls.key" })?;
    		let tls_roots = "/run/edge/callers-ca.pem";
    		let callers = CallerTrust::from_pem(CallerTrustFiles { tls_roots, claim_roots: "/run/edge/claims-ca.pem" })?;

    		let orders = Servlet::new(urn!("orders", "servlet:orders"), orders_signer())?;
    		let routes = Routes::new().unary("/orders.v1.Orders/Get", orders, Assurance::Vouched)?;
    		let billing = Principal::spiffe("spiffe://acme/billing")?;
    		let grants = Grants::deny_all().grant(billing, "/orders.v1.Orders/Get")?;

    		let coupler = Coupler::new(callers, voucher()?, routes, grants)?;
    		let coupler = coupler.with_forwarded_metadata(["traceparent"])?;
    		Ok(Edge::coupled(tls, coupler))
    	}

    	fn dial() -> Result<Dial, EdgeError> {
    		Ok(Dial::Tls(DialTls::from_pem("/run/edge/ca.crt")?))
    	}
    }

    type OrdersEdge = GrpcListener<DefaultCryptoProvider, Orders>;

    cluster! {
    	pub OrdersGateway,
    	protocol: WsListener,
    	edge: OrdersEdge
    }
    # }
    ```

    - `Voucher::new(Identities { handshake, signer })` takes the two tightbeam identities of the coupler.
    - `orders_signer()` is the certificate of the identity that the servlet answers under.
    - Set `ClusterConfig::edge` to `EdgePlane::new` on the edge port, with `with_streams` for stream routes.
    - `with_forwarded_metadata` names the request headers that `Origin::metadata` reads.
    - A refused configuration is a `CoupleError`, which `?` turns into the `EdgeError` of the profile.

3. Serve the call in a servlet whose input is `CoupledCall`:

    ```rust
    # mod serve {
    # use tightbeam::crypto::sign::SigningIdentity;
    # use tightbeam::{Frame, TightBeamError};
    # use tightbeam_grpc::couple::{AdmissionTrust, AdmittedCall};
    # async fn serve(frame: &Frame, trust: &AdmissionTrust, signer: &SigningIdentity) -> Result<Option<Frame>, TightBeamError> {
    let admitted = AdmittedCall::admit(frame, trust)?;
    let order = admitted.body().to_vec();
    admitted.reply(order, signer).await
    # }
    # }
    ```

    Build its trust as `AdmissionTrust::new().with_vouchers(couplers).with_claim_signers(callers.claim_store())`, so the servlet checks claims under the same store as the edge.

4. Call the method from any gRPC client that has a certificate under `callers-ca.pem`:

    ```sh
    grpcurl -cacert ca.crt -cert billing.crt -key billing.key -proto orders.proto \
      -d '{"id":"order-7"}' gateway:9122 orders.v1.Orders/Get
    ```

For a method routed as `Assurance::Signed`, a Rust caller adds a claim under a tightbeam identity of the same principal:

```rust
# mod claim {
# use rustls_pki_types::CertificateDer;
# use tightbeam::crypto::sign::SigningIdentity;
# use tightbeam_grpc::couple::ClaimSigner;
# async fn sign(identity: SigningIdentity, tls_cert: CertificateDer<'static>, order: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
let signer = ClaimSigner::new(identity, [], &tls_cert);
let claim = signer.sign(&"/orders.v1.Orders/Place".parse()?, &order).await?;
let mut request = tonic::Request::new(order);
claim.attach(request.metadata_mut());
# Ok(())
# }
# }
```

## Serve a streaming method

1. Route it with `Routes::server_stream`, `client_stream`, or `bidi_stream`.
2. Offer mux on the gateway, `pool_config.mux_offer`, and on the servlet, `ServletConfigBuilder::with_mux_offer`.
3. Serve it in the `duplex:` arm of `servlet!`:

    ```rust
    # mod stream {
    # use tightbeam::crypto::sign::SigningIdentity;
    # use tightbeam::transport::multiplex::{ReplySink, StreamBody};
    # use tightbeam::TightBeamError;
    # use tightbeam_grpc::couple::{AdmissionTrust, AdmittedStream, AdmittedStreamParts};
    # async fn chat(body: StreamBody, reply: ReplySink, trust: &AdmissionTrust, signer: SigningIdentity) -> Result<(), TightBeamError> {
    let stream = AdmittedStream::admit(body, reply, trust, signer).await?;
    let AdmittedStreamParts { mut requests, mut answers, .. } = stream.split();
    while let Some(message) = requests.next().await? {
    	answers.send(message).await?;
    }
    answers.finish(requests).await
    # }
    # }
    ```

4. For a `Signed` route, the caller signs its claim over an empty body: `signer.sign(&method, b"")`.
5. Set `ClusterConfig::edge` to `EdgePlane::new(addr).with_streams()`.
6. Keep `CallLimits::with_streams` at 2 streams or more. `Coupler::with_call_limits` refuses fewer with `CoupleError::Streams`, because an open stream would hold the one stream that unary calls need.
7. `split()` gives an `AdmittedStreamParts` of the `Origin`, the `StreamRequests`, and the `StreamAnswers`, so each direction can run on a task of its own. `StreamAnswers::finish` and `end` take the `StreamRequests` back.

## Admit callers behind a proxy or with tokens

```rust
# mod callers {
use tightbeam_grpc::couple::{Assurance, BearerTrust, CallerTrust, CallerTrustFiles, Principal, Routes, Servlet};
# fn callers(jwks: &str, browse: Servlet) -> Result<(CallerTrust, Routes<Servlet>), tightbeam_grpc::edge::EdgeError> {
let bearer = BearerTrust::from_jwks("acme", "spiffe://acme/orders-edge", jwks)?;
let roots = CallerTrustFiles { tls_roots: "/run/edge/callers-ca.pem", claim_roots: "/run/edge/claims-ca.pem" };
let callers = CallerTrust::from_pem(roots)?
	.with_forwarding_proxy(Principal::spiffe("spiffe://acme/envoy")?)
	.with_bearer(bearer);

let routes = Routes::new().unary("/orders.v1.Orders/Browse", browse, Assurance::Bearer)?;
# Ok((callers, routes))
# }
# }
```

- Give the proxy a client certificate that names `spiffe://acme/envoy`, under `callers-ca.pem`.
- Set Envoy `forward_client_cert_details: SANITIZE_SET`, with `set_current_client_cert_details` of `cert: true` and `chain: true`.
- Route a method as `Assurance::Bearer` for token callers. A `Vouched` route refuses them.

## Revoke a caller certificate

1. Revoke the certificate in a CRL of its issuer.
2. Load a fresh CRL of each authority that issues caller chains, the root and each intermediate:

    ```rust
    # mod revoked {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::CertificateRevocationListDer;
    use tightbeam_grpc::couple::{CallerTrust, CallerTrustFiles};
    # fn callers() -> Result<CallerTrust, tightbeam_grpc::edge::EdgeError> {
    let crls = CertificateRevocationListDer::pem_file_iter("/run/edge/callers-crls.pem")?;
    let roots = CallerTrustFiles { tls_roots: "/run/edge/callers-ca.pem", claim_roots: "/run/edge/claims-ca.pem" };
    let callers = CallerTrust::from_pem(roots)?
    	.with_crls(crls.collect::<Result<Vec<_>, _>>()?);
    # Ok(callers)
    # }
    # }
    ```

3. Restart the replicas one at a time, before the `nextUpdate` of any CRL. A stale CRL refuses every chain that it covers.

## Serve browser pages

1. Admit bearer callers, as in the section above.
2. Add the origins of the pages: `coupler.with_grpc_web(["https://shop.example"])?`.
3. Call from the page with a gRPC-Web client over HTTPS, and send `authorization: Bearer <JWT-SVID>`.

## Read the client address behind a load balancer

1. Turn on PROXY protocol v2 at the load balancer.
2. Read it at the edge:

    ```rust
    # mod proxied {
    use tightbeam_grpc::edge::{Edge, EdgeError, EdgeTls, EdgeTlsFiles, ProxyHops};
    # fn edge() -> Result<Edge, EdgeError> {
    let tls = EdgeTls::from_pem(EdgeTlsFiles { chain: "/run/edge/tls.crt", key: "/run/edge/tls.key" })?;
    let edge = Edge::tls(tls).with_proxy_protocol(ProxyHops::new(["10.0.0.0/8"])?);
    # Ok(edge)
    # }
    # }
    ```

3. `accept` yields the client address of each tunnel.

## Run replicas of a coupled edge

1. Write a driver of `ClaimLedger` over a store that the replicas share: an insert of `ClaimSpend::key` that fails when the key exists or the spend is past its expiry at the `now` of `spend`, with that expiry, and a delete that holds only for `ClaimSpend::holder`.
2. Check it in its own tests:

    ```rust
    # mod conformance {
    # use std::sync::Arc;
    # use tightbeam_grpc::couple::ClaimLedger;
    use tightbeam_grpc::testing::{LedgerBreach, LedgerConformance};
    # async fn check(driver: Arc<dyn ClaimLedger>) -> Result<(), LedgerBreach> {
    LedgerConformance::new(driver).check().await
    # }
    # }
    ```

3. Give every replica the same ledger:

    ```rust
    # mod replicas {
    use std::sync::Arc;
    use tightbeam_grpc::couple::{ClaimLedger, Coupler};
    # fn replica(coupler: Coupler, driver: Arc<dyn ClaimLedger>) -> Coupler {
    let coupler = coupler.with_claim_ledger(driver);
    # coupler
    # }
    # }
    ```

## Call a stock gRPC server

1. Build a `Backend` for the server:

    ```rust
    # mod backend {
    use tightbeam_grpc::couple::{AdmissionTrust, Assurance, Backend, BackendChannel, Grants, Principal, Routes};
    use tightbeam_grpc::edge::DialTls;
    use tightbeam_grpc::protocol::GrpcAddr;
    # use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    # use tightbeam::crypto::sign::SigningIdentity;
    # fn ledger(admission: AdmissionTrust, signer: SigningIdentity, chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Result<Backend, Box<dyn std::error::Error>> {
    let tls = DialTls::from_pem("/run/adapter/ledger-ca.pem")?.with_identity(chain, key)?;
    let addr: GrpcAddr = "ledger.internal:443".parse()?;
    let channel = BackendChannel::new(&addr, &tls)?;

    let routes = Routes::new().unary("/ledger.v1.Ledger/Post", (), Assurance::Signed)?;
    let web = Principal::subject("CN=web,O=acme")?;
    let grants = Grants::deny_all().grant(web, "/ledger.v1.Ledger/Post")?;
    let backend = Backend::new(channel, routes, grants, admission, signer)?;
    # Ok(backend)
    # }
    # }
    ```

2. Host it in a servlet whose input is `CoupledCall`. Answer each frame with `ctx.env_config().relay(&frame).await`, and each stream in the `duplex:` arm with `ctx.env_config().relay_stream(body, reply).await`.
3. Reach it from either side of the colony:
    - A tightbeam client sends `CoupledCall::direct(method, body)` in a frame it signs.
    - A coupled edge routes a method to the servlet type of the adapter.
4. The server reads the principal in `tightbeam-principal-bin`, and a signed call's claim in `tightbeam-claim-bin`. A servlet of your own writes both with `Origin::stamp`.

A tightbeam client reads the answer as a `CoupledReply`:

```rust
# mod direct {
# use tightbeam::builder::TypeBuilder;
# use tightbeam::colony::SubmitWork;
# use tightbeam::crypto::sign::SigningIdentity;
# use tightbeam::urn::Urn;
# use tightbeam::{TightBeamError, Version};
# use tightbeam_grpc::couple::{CoupledCall, CoupledReply};
# async fn post(client: &mut impl SubmitWork, adapter: Urn<'static>, identity: &SigningIdentity, entry: Vec<u8>) -> Result<CoupledReply, Box<dyn std::error::Error>> {
let call = CoupledCall::direct("/ledger.v1.Ledger/Post", entry)?;
let mut frame = Version::V1.compose().with_id(b"post-1").with_order(1).with_message(call).build()?;
frame.sign_with_provider(identity).await?;

let reply = client.submit_work_to(adapter, &frame).await?;
let answer: CoupledReply = reply.decode_message()?;
# Ok(answer)
# }
# }
```

## Fix a refused call

| Status                 | Cause                                                                          | Fix                                                                               |
| ---------------------- | ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| 16 `UNAUTHENTICATED`   | No client certificate, or one outside `callers-ca.pem`                         | Issue the caller a certificate under the caller CA                                |
| 16 `UNAUTHENTICATED`   | The SPIFFE ID of the caller names no workload, such as `spiffe://acme`         | Issue the caller a SPIFFE ID with a path, such as `spiffe://acme/billing`         |
| 16 `UNAUTHENTICATED`   | The bearer token fails its key, its audience, or its time                      | Issue a fresh ES256 JWT-SVID for the audience of `BearerTrust`                    |
| 16 `UNAUTHENTICATED`   | A call of the forwarding proxy with no chain, or one outside the caller CA     | Set `forward_client_cert_details` on the proxy                                    |
| 16 `UNAUTHENTICATED`   | A CRL refuses the chain that the proxy forwards                                | Issue the caller a new certificate, or load a fresh CRL of each issuer            |
| 14 `UNAVAILABLE`       | The handshake failed with `certificate_revoked` or `unknown_ca` under the CRLs | Issue the caller a new certificate, or load a fresh CRL of each issuer            |
| 7 `PERMISSION_DENIED`  | A stream, and the `EdgePlane` of the gateway refuses streams                   | Set `EdgePlane::with_streams`                                                     |
| 14 `UNAVAILABLE`       | A signed call, and the claim ledger failed                                     | Restore the store of the ledger driver                                            |
| 403                    | A gRPC-Web call or preflight from an origin that the edge does not serve       | Add the origin to `Coupler::with_grpc_web`                                        |
| 16 `UNAUTHENTICATED`   | The claim failed, or was spent already                                         | Sign a fresh claim over this method and body, bound to this certificate           |
| 7 `PERMISSION_DENIED`  | No grant names the principal, or the call proves less than the route requires  | Add the grant, or sign a claim for a `Signed` route                               |
| 12 `UNIMPLEMENTED`     | The method is not routed                                                       | Route it with `Routes::unary`, `server_stream`, `client_stream`, or `bidi_stream` |
| 14 `UNAVAILABLE`       | Health reads `NOT_SERVING`: the gateway refuses the voucher handshake          | Trust the handshake identity of the voucher on a mutual edge                      |
| 14 `UNAVAILABLE`       | The connection already carries a tunnel                                        | Use a separate connection for tunnel and coupled calls                            |
| 14 `UNAVAILABLE`       | A stream, and the loopback session runs one call at a time                     | Set `pool_config.mux_offer` on the gateway                                        |
| 12 `UNIMPLEMENTED`     | A second request to a server-streaming method, or none to it                   | Send exactly one request message                                                  |
| 12 `UNIMPLEMENTED`     | The servlet answers a count of messages that the route does not take           | Send exactly one response message on a unary or client-streaming route            |
| 8 `RESOURCE_EXHAUSTED` | The edge carries its most streams at once                                      | Retry later, or raise `CallLimits::with_streams`                                  |
| 3 `INVALID_ARGUMENT`   | A forwarded metadata value does not decode                                     | Send a valid value, or drop the header                                            |
| 4 `DEADLINE_EXCEEDED`  | The call outlived its `grpc-timeout` or `CallLimits::with_timeout`             | Raise the deadline. An unspent claim can be retried                               |
| 13 `INTERNAL`          | The answer is signed by a key that the route does not pin                      | Pass the certificate the servlet signs under to `Servlet::new`                    |
| 8 `RESOURCE_EXHAUSTED` | The call, or a part of its stream, passes the envelope ceiling of the edge     | Send a smaller body, or raise `TransportLimits` on the edge                       |
