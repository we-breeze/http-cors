//! Transport-independent CORS policy shared by Breeze HTTP runtimes.
//!
//! The application explicitly enables and configures CORS. Preflight handling
//! does not consult business routes, authenticators, or admission providers.

use http::StatusCode;
use http::header::{HeaderMap, HeaderName, HeaderValue, VARY};

const CORS_HEADERS: [&str; 6] = [
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "access-control-max-age",
];

/// Application origin policy. Method names are explicit and case-sensitive;
/// origins and request headers support the wildcard `*`.
#[derive(Clone, Debug)]
pub struct Cors {
    pub allow_origins: Vec<String>,
    pub allow_methods: Vec<String>,
    pub allow_headers: Vec<String>,
    pub expose_headers: Vec<String>,
    /// Additional request header names to include in preflight Vary responses.
    /// Origin (when reflected), Access-Control-Request-Method and
    /// Access-Control-Request-Headers are managed by the policy automatically.
    /// Names retain their configured spelling and order and are deduplicated
    /// case-insensitively. This does not grant permissions for any extension.
    pub extra_preflight_vary: Vec<String>,
    pub allow_credentials: bool,
    pub max_age: u64,
}

impl Default for Cors {
    fn default() -> Self {
        Self {
            allow_origins: Vec::new(),
            allow_methods: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
                .map(str::to_owned)
                .to_vec(),
            allow_headers: Vec::new(),
            expose_headers: Vec::new(),
            extra_preflight_vary: Vec::new(),
            allow_credentials: false,
            max_age: 600,
        }
    }
}

/// Borrowed request metadata; adapters need not buffer or inspect the body.
#[derive(Clone, Copy, Debug)]
pub struct PreflightRequest<'a> {
    pub method: &'a str,
    pub origin: Option<&'a [u8]>,
    pub request_method: Option<&'a [u8]>,
    pub request_headers: Option<&'a [u8]>,
}

/// A complete preflight decision for a transport adapter to render.
#[derive(Debug)]
pub struct Preflight {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: &'static [u8],
}

impl Cors {
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            allow_origins: vec!["*".into()],
            allow_headers: vec!["*".into()],
            ..Self::default()
        }
    }

    /// Validate once at listener or gateway construction.
    #[must_use]
    pub fn validate(&self) -> bool {
        self.allow_origins
            .iter()
            .all(|value| !value.is_empty() && HeaderValue::from_str(value).is_ok())
            && self
                .allow_methods
                .iter()
                .all(|value| value != "*" && http::Method::from_bytes(value.as_bytes()).is_ok())
            && self
                .allow_headers
                .iter()
                .chain(&self.expose_headers)
                .all(|value| value == "*" || HeaderName::from_bytes(value.as_bytes()).is_ok())
            && self
                .extra_preflight_vary
                .iter()
                .all(|value| value != "*" && HeaderName::from_bytes(value.as_bytes()).is_ok())
    }

    fn permits_origin(&self, origin: &str) -> bool {
        self.allow_origins
            .iter()
            .any(|allowed| allowed == "*" || allowed == origin)
    }

    fn varies_by_origin(&self) -> bool {
        self.allow_credentials || !self.allow_origins.iter().any(|allowed| allowed == "*")
    }

    fn origin_headers(&self, origin: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let reflected = self.varies_by_origin();
        // Denied origins must vary too: a cache must not reuse a denial for
        // an allowed origin, or an allowed response for a denied origin.
        if reflected {
            headers.insert(VARY, HeaderValue::from_static("Origin"));
        }
        if !self.permits_origin(origin) {
            return headers;
        }
        insert(
            &mut headers,
            "access-control-allow-origin",
            if reflected { origin } else { "*" },
        );
        if self.allow_credentials {
            headers.insert(
                "access-control-allow-credentials",
                HeaderValue::from_static("true"),
            );
        }
        headers
    }

    fn preflight_headers(&self, origin: Option<&str>) -> HeaderMap {
        let mut headers = origin.map_or_else(HeaderMap::new, |origin| self.origin_headers(origin));
        let mut vary = Vec::new();
        if self.varies_by_origin() {
            vary.push("Origin");
        }
        for name in [
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
        ]
        .into_iter()
        .chain(self.extra_preflight_vary.iter().map(String::as_str))
        {
            if !vary
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(name))
            {
                vary.push(name);
            }
        }
        insert(&mut headers, "vary", &vary.join(", "));
        headers
    }

    /// Returns `None` for ordinary requests, including OPTIONS without both
    /// preflight headers. A malformed preflight is rejected locally.
    #[must_use]
    pub fn preflight(&self, request: PreflightRequest<'_>) -> Option<Preflight> {
        if request.method != "OPTIONS" {
            return None;
        }
        let origin = request.origin?;
        let method = request.request_method?;
        let origin = std::str::from_utf8(origin).ok();
        let method = std::str::from_utf8(method).ok();
        let requested_headers = request.request_headers.map_or(Ok(""), std::str::from_utf8);
        let headers_allowed = requested_headers.as_ref().is_ok_and(|headers| {
            headers
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .all(|name| {
                    HeaderName::from_bytes(name.as_bytes()).is_ok()
                        && (self.allow_headers.iter().any(|value| value == "*")
                            || [
                                "accept",
                                "accept-language",
                                "content-language",
                                "content-type",
                            ]
                            .iter()
                            .any(|allowed| name.eq_ignore_ascii_case(allowed))
                            || self
                                .allow_headers
                                .iter()
                                .any(|allowed| name.eq_ignore_ascii_case(allowed)))
                })
        });
        let allowed = origin.is_some_and(|origin| self.permits_origin(origin))
            && method
                .is_some_and(|method| self.allow_methods.iter().any(|allowed| allowed == method))
            && headers_allowed;
        let mut headers = self.preflight_headers(origin);
        insert(
            &mut headers,
            "access-control-allow-methods",
            &self.allow_methods.join(", "),
        );
        insert(
            &mut headers,
            "access-control-max-age",
            &self.max_age.to_string(),
        );
        if let Ok(requested_headers) = requested_headers {
            if !requested_headers.is_empty() && headers_allowed {
                insert(
                    &mut headers,
                    "access-control-allow-headers",
                    requested_headers,
                );
            }
        }
        headers.insert(
            "content-type",
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        Some(Preflight {
            status: if allowed {
                StatusCode::OK
            } else {
                StatusCode::BAD_REQUEST
            },
            headers,
            body: if allowed {
                b"OK"
            } else {
                b"Disallowed CORS request"
            },
        })
    }

    /// Apply the outer policy to response headers without touching the body.
    /// Replaces upstream CORS fields and preserves all unrelated header values,
    /// including repeated Set-Cookie and Vary fields.
    pub fn apply(&self, origin: Option<&[u8]>, headers: &mut HeaderMap) {
        let Some(origin) = origin else {
            return;
        };
        for name in CORS_HEADERS {
            headers.remove(name);
        }
        let Ok(origin) = std::str::from_utf8(origin) else {
            return;
        };
        for (name, value) in &self.origin_headers(origin) {
            if name == VARY {
                let present = headers.get_all(VARY).iter().any(|existing| {
                    existing.to_str().is_ok_and(|existing| {
                        existing
                            .split(',')
                            .map(str::trim)
                            .any(|token| token == "*" || token.eq_ignore_ascii_case("origin"))
                    })
                });
                if !present {
                    headers.append(VARY, value.clone());
                }
            } else {
                headers.insert(name.clone(), value.clone());
            }
        }
        if self.permits_origin(origin) && !self.expose_headers.is_empty() {
            insert(
                headers,
                "access-control-expose-headers",
                &self.expose_headers.join(", "),
            );
        }
    }
}

fn insert(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}
