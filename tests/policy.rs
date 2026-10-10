use brz_http_cors::{Cors, PreflightRequest};
use http::StatusCode;
use http::header::{HeaderMap, HeaderValue, VARY};

const ORIGIN: &[u8] = b"https://app.example";

fn request() -> PreflightRequest<'static> {
    PreflightRequest {
        method: "OPTIONS",
        origin: Some(ORIGIN),
        request_method: Some(b"GET"),
        request_headers: Some(b"authorization,content-type,x-request-id"),
    }
}

#[test]
fn credentialed_preflight_reflects_origin_and_requested_headers() {
    let cors = Cors {
        allow_credentials: true,
        ..Cors::permissive()
    };
    let response = cors.preflight(request()).unwrap();
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, b"OK");
    assert_eq!(
        response.headers["access-control-allow-origin"],
        "https://app.example"
    );
    assert_eq!(response.headers["access-control-allow-credentials"], "true");
    assert_eq!(
        response.headers["access-control-allow-headers"],
        "authorization,content-type,x-request-id"
    );
    assert_eq!(response.headers["access-control-max-age"], "600");
    assert_eq!(
        response.headers["content-type"],
        "text/plain; charset=utf-8"
    );
    assert_eq!(
        response.headers[VARY],
        "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
    );
}

#[test]
fn exposed_headers_are_only_added_to_actual_responses() {
    let cors = Cors {
        expose_headers: vec!["X-Request-ID".into()],
        ..Cors::permissive()
    };
    for method in [b"GET".as_slice(), b"DISALLOWED", b"\xff"] {
        let response = cors
            .preflight(PreflightRequest {
                request_method: Some(method),
                ..request()
            })
            .unwrap();
        assert!(
            !response
                .headers
                .contains_key("access-control-expose-headers")
        );
    }
    let mut headers = HeaderMap::new();
    cors.apply(Some(ORIGIN), &mut headers);
    assert_eq!(headers["access-control-expose-headers"], "X-Request-ID");
}

#[test]
fn extra_preflight_vary_is_ordered_deduplicated_and_does_not_grant_permissions() {
    let cors = Cors {
        allow_credentials: true,
        extra_preflight_vary: [
            "origin",
            "ACCESS-CONTROL-REQUEST-METHOD",
            "X-Preflight-Variant",
            "x-preflight-variant",
            "Access-Control-Request-Private-Network",
        ]
        .map(str::to_owned)
        .to_vec(),
        ..Cors::permissive()
    };
    assert!(cors.validate());
    let response = cors.preflight(request()).unwrap();
    assert_eq!(
        response.headers[VARY],
        "Origin, Access-Control-Request-Method, Access-Control-Request-Headers, X-Preflight-Variant, Access-Control-Request-Private-Network"
    );
    assert!(
        !response
            .headers
            .contains_key("access-control-allow-private-network")
    );
    let mut headers = HeaderMap::new();
    cors.apply(Some(ORIGIN), &mut headers);
    assert_eq!(headers[VARY], "Origin");
}

#[test]
fn wildcard_origin_preflights_vary_by_method_and_headers() {
    let response = Cors::permissive().preflight(request()).unwrap();
    assert_eq!(response.headers["access-control-allow-origin"], "*");
    assert_eq!(
        response.headers[VARY],
        "Access-Control-Request-Method, Access-Control-Request-Headers"
    );
}

#[test]
fn denied_and_malformed_preflights_keep_the_full_vary_policy() {
    let cors = Cors {
        allow_origins: vec!["https://app.example".into()],
        extra_preflight_vary: vec!["X-Preflight-Variant".into()],
        ..Cors::default()
    };
    for origin in [b"https://other.example".as_slice(), b"\xff"] {
        let response = cors
            .preflight(PreflightRequest {
                origin: Some(origin),
                ..request()
            })
            .unwrap();
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers[VARY],
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers, X-Preflight-Variant"
        );
    }
}

#[test]
fn ordinary_options_and_other_methods_are_not_preflights() {
    let cors = Cors::permissive();
    for ordinary in [
        PreflightRequest {
            origin: None,
            ..request()
        },
        PreflightRequest {
            request_method: None,
            ..request()
        },
        PreflightRequest {
            method: "GET",
            ..request()
        },
    ] {
        assert!(cors.preflight(ordinary).is_none());
    }
}

#[test]
fn rejects_disallowed_origin_method_and_headers() {
    let cors = Cors {
        allow_origins: vec!["https://app.example".into()],
        allow_methods: vec!["GET".into()],
        allow_headers: vec!["authorization".into(), "x-request-id".into()],
        ..Cors::default()
    };
    assert_eq!(cors.preflight(request()).unwrap().status, StatusCode::OK);
    for denied in [
        PreflightRequest {
            origin: Some(b"https://other.example"),
            ..request()
        },
        PreflightRequest {
            request_method: Some(b"POST"),
            ..request()
        },
        PreflightRequest {
            request_headers: Some(b"x-disallowed"),
            ..request()
        },
        PreflightRequest {
            request_headers: Some(b"invalid header name"),
            ..request()
        },
        PreflightRequest {
            request_headers: Some(b"\xff"),
            ..request()
        },
        PreflightRequest {
            request_method: Some(b"\xff"),
            ..request()
        },
        PreflightRequest {
            origin: Some(b"\xff"),
            ..request()
        },
    ] {
        let response = cors.preflight(denied).unwrap();
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(response.body, b"Disallowed CORS request");
    }
}

#[test]
fn custom_method_and_method_order_are_configurable() {
    let cors = Cors {
        allow_methods: [
            "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "QUERY",
        ]
        .map(str::to_owned)
        .to_vec(),
        ..Cors::permissive()
    };
    assert!(cors.validate());
    let response = cors
        .preflight(PreflightRequest {
            request_method: Some(b"QUERY"),
            ..request()
        })
        .unwrap();
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response.headers["access-control-allow-methods"],
        "DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT, QUERY"
    );
}

#[test]
fn header_names_are_case_insensitive_and_safelisted_headers_are_allowed() {
    let cors = Cors {
        allow_headers: vec!["AUTHORIZATION".into()],
        ..Cors::permissive()
    };
    let response = cors
        .preflight(PreflightRequest {
            request_headers: Some(
                b"authorization, Content-Type, ACCEPT, accept-language, content-language",
            ),
            ..request()
        })
        .unwrap();
    assert_eq!(response.status, StatusCode::OK);
}

#[test]
fn outer_policy_replaces_upstream_cors_and_preserves_repeated_headers() {
    let cors = Cors {
        allow_credentials: true,
        expose_headers: vec!["X-Request-ID".into()],
        ..Cors::permissive()
    };
    let mut headers = HeaderMap::new();
    headers.append("set-cookie", HeaderValue::from_static("a=1"));
    headers.append("set-cookie", HeaderValue::from_static("b=2"));
    headers.append(VARY, HeaderValue::from_static("Accept-Encoding"));
    headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
    headers.insert(
        "access-control-allow-methods",
        HeaderValue::from_static("DELETE"),
    );
    cors.apply(Some(ORIGIN), &mut headers);
    cors.apply(Some(ORIGIN), &mut headers);
    assert_eq!(headers.get_all("set-cookie").iter().count(), 2);
    assert_eq!(
        headers
            .get_all("access-control-allow-origin")
            .iter()
            .count(),
        1
    );
    assert_eq!(
        headers["access-control-allow-origin"],
        "https://app.example"
    );
    assert_eq!(headers["access-control-expose-headers"], "X-Request-ID");
    assert!(!headers.contains_key("access-control-allow-methods"));
    assert_eq!(
        headers
            .get_all(VARY)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect::<Vec<_>>(),
        ["Accept-Encoding", "Origin"]
    );
}

#[test]
fn denied_origins_remove_upstream_permissions_and_still_vary() {
    let cors = Cors {
        allow_origins: vec!["https://app.example".into()],
        ..Cors::default()
    };
    let mut headers = HeaderMap::new();
    headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
    headers.insert(
        "access-control-allow-credentials",
        HeaderValue::from_static("true"),
    );
    cors.apply(Some(b"https://other.example"), &mut headers);
    assert!(!headers.contains_key("access-control-allow-origin"));
    assert!(!headers.contains_key("access-control-allow-credentials"));
    assert_eq!(headers[VARY], "Origin");
}

#[test]
fn ordinary_responses_vary_by_origin_including_absent_and_malformed_origins() {
    for cors in [
        Cors::permissive(),
        Cors {
            allow_credentials: true,
            ..Cors::permissive()
        },
        Cors {
            allow_origins: vec!["https://app.example".into()],
            ..Cors::default()
        },
    ] {
        for origin in [
            None,
            Some(ORIGIN),
            Some(b"https://other.example"),
            Some(b"\xff"),
        ] {
            let mut headers = HeaderMap::new();
            cors.apply(origin, &mut headers);
            assert_eq!(headers[VARY], "Origin");
            if origin.is_none() || origin == Some(b"\xff".as_slice()) {
                assert_eq!(headers.len(), 1);
            }
        }
    }
}

#[test]
fn absent_origin_preserves_response_fields_and_merges_vary_once() {
    let cors = Cors {
        allow_credentials: true,
        expose_headers: vec!["X-Request-ID".into()],
        ..Cors::permissive()
    };
    let mut headers = HeaderMap::new();
    headers.append(VARY, HeaderValue::from_static("Accept-Encoding"));
    headers.append(VARY, HeaderValue::from_static("Accept-Language"));
    headers.append("set-cookie", HeaderValue::from_static("a=1"));
    headers.append("set-cookie", HeaderValue::from_static("b=2"));
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert(
        "cache-control",
        HeaderValue::from_static("private, no-store"),
    );
    cors.apply(None, &mut headers);
    cors.apply(None, &mut headers);
    assert_eq!(
        headers
            .get_all(VARY)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect::<Vec<_>>(),
        ["Accept-Encoding", "Accept-Language", "Origin"]
    );
    assert_eq!(headers.get_all("set-cookie").iter().count(), 2);
    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(headers["cache-control"], "private, no-store");
    assert!(!headers.contains_key("access-control-allow-origin"));
    assert!(!headers.contains_key("access-control-allow-credentials"));
    assert!(!headers.contains_key("access-control-expose-headers"));
}

#[test]
fn existing_origin_and_vary_wildcard_are_not_extended() {
    let cors = Cors::permissive();
    for vary in ["Accept-Encoding, oRiGiN", "*"] {
        let mut headers = HeaderMap::new();
        headers.insert(VARY, HeaderValue::from_static(vary));
        cors.apply(None, &mut headers);
        cors.apply(Some(ORIGIN), &mut headers);
        assert_eq!(headers.get_all(VARY).iter().count(), 1);
        assert_eq!(headers[VARY], vary);
    }
}

#[test]
fn invalid_configuration_is_rejected() {
    assert!(Cors::default().validate());
    for cors in [
        Cors {
            allow_origins: vec!["bad\r\norigin".into()],
            ..Cors::default()
        },
        Cors {
            allow_methods: vec!["bad method".into()],
            ..Cors::default()
        },
        Cors {
            allow_methods: vec!["*".into()],
            ..Cors::default()
        },
        Cors {
            allow_headers: vec!["bad header".into()],
            ..Cors::default()
        },
        Cors {
            expose_headers: vec!["bad header".into()],
            ..Cors::default()
        },
        Cors {
            extra_preflight_vary: vec!["bad\r\nheader".into()],
            ..Cors::default()
        },
        Cors {
            extra_preflight_vary: vec!["*".into()],
            ..Cors::default()
        },
    ] {
        assert!(!cors.validate());
    }
}
