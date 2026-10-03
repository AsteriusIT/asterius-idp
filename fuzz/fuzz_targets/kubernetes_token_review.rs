//! Closed review inputs cannot acquire response identity or echo credentials.
#![no_main]
use asterius_domain::kubernetes_online::{TokenReviewRequest, TokenReviewResponse};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|body: &[u8]| {
    let Ok(request) = TokenReviewRequest::parse(body) else {
        return;
    };
    assert!(body.len() <= 65536);
    assert!((1..=16384).contains(&request.credential().expose().len()));
    assert!(
        request
            .credential()
            .expose()
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
    );
    assert!((1..=16).contains(&request.audiences().len()));
    assert_eq!(
        request
            .audiences()
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        request.audiences().len()
    );
    for audience in request.audiences() {
        assert!(request.require_route_audience(audience).is_ok());
        let response = TokenReviewResponse::released(
            &request,
            audience,
            "asterius:controlled:cluster:subject".into(),
            Vec::new(),
        )
        .expect("bounded server identity");
        let output = serde_json::to_value(response).expect("closed serializable output");
        assert!(output.get("spec").is_none());
        assert!(output.get("metadata").is_none());
        assert!(output["status"]["user"].get("extra").is_none());
        assert_eq!(output["status"]["audiences"], serde_json::json!([audience]));
    }
});
