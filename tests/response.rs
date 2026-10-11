use brz_http_cors::{Cors, RESPONSE_CORS_HEADER, ResponseCors};
use http::{HeaderMap, HeaderValue, Response};

#[test]
fn explicit_skip_preserves_every_header_while_plain_500_keeps_cors() {
    let cors = Cors {
        allow_credentials: true,
        ..Cors::permissive()
    };
    for origin in [None, Some(b"https://app.example".as_slice())] {
        let mut response = Response::builder()
            .status(500)
            .header("vary", "Accept-Encoding")
            .header("set-cookie", "a=1")
            .header("set-cookie", "b=2")
            .body("error")
            .unwrap();
        let original = response.headers().clone();
        response.extensions_mut().insert(ResponseCors::Skip);
        cors.apply_response(origin, &mut response);
        assert_eq!(response.headers(), &original);
        assert_eq!(response.body(), &"error");
        response.extensions_mut().remove::<ResponseCors>();
        cors.apply_response(origin, &mut response);
        assert_eq!(response.headers().get_all("vary").iter().count(), 2);
        assert_eq!(response.headers().get_all("set-cookie").iter().count(), 2);
        assert_eq!(
            response
                .headers()
                .contains_key("access-control-allow-origin"),
            origin.is_some()
        );
    }
}

#[test]
fn internal_metadata_requires_one_exact_skip_and_is_always_consumed() {
    for values in [
        vec![],
        vec!["skip"],
        vec!["SKIP"],
        vec!["skip, skip"],
        vec!["invalid"],
        vec!["skip", "skip"],
    ] {
        let mut headers = HeaderMap::new();
        headers.insert("vary", HeaderValue::from_static("Accept-Encoding"));
        for value in &values {
            headers.append(&RESPONSE_CORS_HEADER, HeaderValue::from_str(value).unwrap());
        }
        assert_eq!(
            ResponseCors::take_from_headers(&mut headers),
            if values == ["skip"] {
                ResponseCors::Skip
            } else {
                ResponseCors::Apply
            }
        );
        assert!(!headers.contains_key(&RESPONSE_CORS_HEADER));
        assert_eq!(headers["vary"], "Accept-Encoding");
    }
    assert_eq!(ResponseCors::Apply.header_value(), None);
    assert_eq!(ResponseCors::Skip.header_value().unwrap(), "skip");
}
