//! Response-local CORS decisions and the explicitly trusted internal HTTP hop.
use http::header::{HeaderMap, HeaderName, HeaderValue};

/// Reserved response metadata for a trusted internal server-to-gateway hop.
/// Consumers must remove it before forwarding a public response, and must only
/// honor it when the application explicitly trusts that origin's decisions.
pub const RESPONSE_CORS_HEADER: HeaderName = HeaderName::from_static("x-breeze-response-cors");

/// An explicit response decision. Status codes never implicitly disable CORS.
/// Insert `Skip` in `http::Response::extensions_mut()` for an in-process service.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ResponseCors {
    /// Use the configured boundary policy.
    #[default]
    Apply,
    /// Preserve response headers without adding CORS permissions or Origin variance.
    Skip,
}

impl ResponseCors {
    /// Consume internal metadata. Missing, invalid and repeated values use the
    /// normal policy; every value is removed regardless of validity or trust.
    pub fn take_from_headers(headers: &mut HeaderMap) -> Self {
        let mut values = headers.get_all(&RESPONSE_CORS_HEADER).iter();
        let skip = values.next().is_some_and(|value| value == "skip") && values.next().is_none();
        headers.remove(&RESPONSE_CORS_HEADER);
        if skip { Self::Skip } else { Self::Apply }
    }

    /// Encode a decision only on an explicitly enabled internal HTTP boundary.
    pub fn header_value(self) -> Option<HeaderValue> {
        (self == Self::Skip).then(|| HeaderValue::from_static("skip"))
    }
}
