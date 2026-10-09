# brz-http-cors

Shared CORS policy for `brz-http-server` and `brz-http-gateway`. The crate depends
only on `http`; it owns no sockets, async runtime, routing, authentication,
recording admission, or response body buffering.

Applications explicitly enable CORS on their public HTTP boundary. A preflight
is an OPTIONS request with both Origin and Access-Control-Request-Method. Its
decision depends on the configured policy, not on business route registration.
Ordinary OPTIONS requests remain the application's responsibility.

`Cors::permissive()` allows all origins and request header names, with the seven
standard methods listed in `Cors::default()`. Credentials are disabled by
default. Configure explicit method names, including custom methods such as
QUERY; their configured order is retained in preflight responses. `max_age`
defaults to 600 seconds. Origin and request-header lists support `*`; method
lists must be explicit.

Call `Cors::validate()` at startup. Pass borrowed request metadata to
`Cors::preflight()`, and render the returned status, headers and static body.
Malformed and disallowed preflights return 400; permitted preflights return
200 with `OK`. For ordinary responses, `Cors::apply()` updates only headers.
It replaces upstream CORS fields, preserves repeated unrelated fields such as
Set-Cookie, and adds Vary: Origin without duplicating or replacing existing
Vary tokens. Requests with no Origin keep their response headers unchanged.

```rust
use brz_http_cors::{Cors, PreflightRequest};

let cors = Cors { allow_credentials: true, ..Cors::permissive() };
assert!(cors.validate());
let response = cors.preflight(PreflightRequest {
    method: "OPTIONS",
    origin: Some(b"https://app.example"),
    request_method: Some(b"GET"),
    request_headers: Some(b"authorization,content-type"),
}).unwrap();
assert_eq!(response.status, http::StatusCode::OK);
assert_eq!(response.body, b"OK");
```

## Development and release order

Keep the three repositories as sibling directories named `http-cors`,
`http-server`, and `http-gateway` while developing the shared policy. The two
consumers currently use versioned sibling path dependencies. Publish
`brz-http-cors` 0.0.1 first, then replace the consumers' development path
dependencies with registry dependencies and regenerate their lockfiles before
releasing those packages. The application must upgrade and explicitly enable
gateway CORS to use the new behavior.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```
