//! An untrusted target must not turn an arbitrary document into an owned mapping.
#![no_main]
use asterius_domain::outbound_scim::{Projection, UserProjection, parse_document, target_etag};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let projection = Projection::User(UserProjection {
        source_exists: true,
        immutable_alias: "ast-fixed-incarnation".into(),
        external_id: "urn:asterius:fixed".into(),
        work_email: None,
        active: true,
    });
    if let Ok(document) = parse_document(data, "W/\"1\"", &projection) {
        assert_eq!(document.etag, "W/\"1\"");
        assert!(target_etag(&document.etag).is_ok());
        assert!(document.active.is_some());
        assert!(document.members.is_empty());
    }
});
