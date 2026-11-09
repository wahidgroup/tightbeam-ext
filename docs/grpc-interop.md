# Connect gRPC Systems to a Colony

For engineers who run a tightbeam colony and need stock gRPC clients or servers to talk to it. Every type below is specified in [The gRPC Transport](grpc.md).

## Contents

- [Serve stock gRPC callers](#serve-stock-grpc-callers)
- [Call a stock gRPC server](#call-a-stock-grpc-server)
- [Fix a refused call](#fix-a-refused-call)

## Serve stock gRPC callers

1. Enable the `couple` feature of `tightbeam-grpc`.
2. Write the edge profile, and declare the gateway with it:

   ```rust
   # mod profile {
   # #![allow(unexpected_cfgs)]
   use tightbeam::crypto::profiles::DefaultCryptoProvider;
   use tightbeam::transport::tcp::r#async::TokioListener;
   use tightbeam::{cluster, urn};
   use tightbeam_grpc::couple::{Assurance, CallerTrust, Coupler, Grants, Principal, Routes, Servlet};
   use tightbeam_grpc::edge::{Dial, DialTls, Edge, EdgeError, EdgeProfile, EdgeTls};
   use tightbeam_grpc::protocol::GrpcListener;
   # use tightbeam::crypto::x509::Certificate;
   # use tightbeam_grpc::couple::Voucher;
   # fn voucher() -> Result<Voucher, EdgeError> { unimplemented!() }
   # fn orders_signer() -> Certificate { unimplemented!() }

   struct Orders;

   impl EdgeProfile for Orders {
       fn edge() -> Result<Edge, EdgeError> {
           let tls = EdgeTls::from_pem("/run/edge/tls.crt", "/run/edge/tls.key")?;
           let callers = CallerTrust::from_pem("/run/edge/callers-ca.pem", "/run/edge/claims-ca.pem")?;

           let orders = Servlet::new(urn!("orders", "servlet:orders"), orders_signer())?;
           let routes = Routes::new().unary("/orders.v1.Orders/Get", orders, Assurance::Vouched)?;
           let billing = Principal::spiffe("spiffe://acme/billing")?;
           let grants = Grants::deny_all().grant(billing, "/orders.v1.Orders/Get");

           Ok(Edge::Coupled(tls, Coupler::new(callers, voucher()?, routes, grants)?))
       }

       fn dial() -> Result<Dial, EdgeError> {
           Ok(Dial::Tls(DialTls::from_pem("/run/edge/ca.crt")?))
       }
   }

   type OrdersEdge = GrpcListener<DefaultCryptoProvider, Orders>;

   cluster! {
       pub OrdersGateway,
       protocol: TokioListener,
       edge: OrdersEdge
   }
   # }
   ```

   - `Voucher::new(handshake, signer)` takes the two tightbeam identities of the coupler.
   - `orders_signer()` is the certificate of the identity that the servlet answers under.
   - Set `ClusterConfig::edge_bind_addr` to the edge port.

3. Serve the call in a servlet whose input is `CoupledCall`:

   ```rust
   # mod serve {
   # use tightbeam::crypto::sign::SigningIdentity;
   # use tightbeam::{Frame, TightBeamError};
   # use tightbeam_grpc::couple::{AdmissionTrust, AdmittedCall, Code};
   # async fn serve(frame: &Frame, trust: &AdmissionTrust, signer: &SigningIdentity) -> Result<Option<Frame>, TightBeamError> {
   let admitted = AdmittedCall::admit(frame, trust)?;
   let order = admitted.body().to_vec();
   admitted.reply(Code::Ok, order, signer).await
   # }
   # }
   ```

   Build its `AdmissionTrust` with `CallerTrust::claim_store()`, so the servlet checks claims under the same store as the edge.

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
# async fn sign(identity: SigningIdentity, tls_cert: CertificateDer<'static>, order: Vec<u8>) -> Result<(), tightbeam::TightBeamError> {
let signer = ClaimSigner::new(identity, [], &tls_cert);
let claim = signer.sign("/orders.v1.Orders/Place", &order).await?;
let mut request = tonic::Request::new(order);
claim.attach(request.metadata_mut())?;
# Ok(())
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
   let grants = Grants::deny_all().grant(web, "/ledger.v1.Ledger/Post");
   let backend = Backend::new(channel, routes, grants, admission, signer)?;
   # Ok(backend)
   # }
   # }
   ```

2. Host it in a servlet whose input is `CoupledCall`, and answer each frame with `ctx.env_config().relay(&frame).await`.
3. Reach it from either side of the colony:
   - A tightbeam client sends `CoupledCall::direct(method, body)` in a frame it signs.
   - A coupled edge routes a method to the servlet type of the adapter.
4. The server reads the principal in `tightbeam-principal-bin`, and a signed call's claim in `tightbeam-claim-bin`.

A tightbeam client reads the answer as a `CoupledReply`:

```rust
# mod direct {
# use tightbeam::builder::TypeBuilder;
# use tightbeam::colony::SubmitWork;
# use tightbeam::crypto::sign::SigningIdentity;
# use tightbeam::urn::Urn;
# use tightbeam::{TightBeamError, Version};
# use tightbeam_grpc::couple::{CoupledCall, CoupledReply};
# async fn post(client: &mut impl SubmitWork, adapter: Urn<'static>, identity: &SigningIdentity, entry: Vec<u8>) -> Result<CoupledReply, TightBeamError> {
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

| Status                 | Cause                                                                         | Fix                                                                     |
| ---------------------- | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| 16 `UNAUTHENTICATED`   | No client certificate, or one outside `callers-ca.pem`                        | Issue the caller a certificate under the caller CA                      |
| 16 `UNAUTHENTICATED`   | The claim failed, or was spent already                                        | Sign a fresh claim over this method and body, bound to this certificate |
| 7 `PERMISSION_DENIED`  | No grant names the principal, or the call proves less than the route requires | Add the grant, or sign a claim for a `Signed` route                     |
| 12 `UNIMPLEMENTED`     | The method is not routed                                                      | Add it with `Routes::unary`                                             |
| 14 `UNAVAILABLE`       | Health reads `NOT_SERVING`: the gateway refuses the voucher handshake         | Trust the handshake identity of the voucher on a mutual edge            |
| 14 `UNAVAILABLE`       | The connection already carries a tunnel                                       | Use a separate connection for tunnel and coupled calls                  |
| 4 `DEADLINE_EXCEEDED`  | The call outlived its `grpc-timeout` or `Coupler::with_call_limits`           | Raise the deadline. An unspent claim can be retried                     |
| 13 `INTERNAL`          | The answer is signed by a key that the route does not pin                     | Pass the certificate the servlet signs under to `Servlet::new`          |
| 8 `RESOURCE_EXHAUSTED` | The call passes the envelope ceiling of the edge                              | Send a smaller body, or raise `TransportLimits` on the edge             |
