//! Structural device inputs never manufacture transport possession or authority.
#![no_main]
use asterius_domain::managed_devices::{
    EnrollmentRequest, MAX_ALLOWED_CLIENTS, MAX_OBSERVATIONS, MAX_UPDATE_BYTES, SourceChange,
    Update,
};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;
fuzz_target!(|body: &[u8]| {
    let now = time::OffsetDateTime::from_unix_timestamp(1_800_000_000)
        .expect("fixed representable instant");
    if let Ok(update) = Update::parse(body, now) {
        assert!(body.len() <= MAX_UPDATE_BYTES);
        assert!((1..=MAX_OBSERVATIONS).contains(&update.observations.len()));
        assert!(update.source_generation > 0);
        assert_eq!(
            update
                .observations
                .iter()
                .map(|o| o.device_id)
                .collect::<BTreeSet<_>>()
                .len(),
            update.observations.len()
        );
        assert!(update.validate(now).is_ok());
        for observation in update.observations {
            assert!(!observation.device_id.is_nil());
            assert!(observation.sequence >= 0 && observation.enrollment_generation > 0);
            assert!(observation.expires_at > now.unix_timestamp());
        }
    }
    if let Ok(enrollment) = EnrollmentRequest::parse(body) {
        assert!(body.len() <= MAX_UPDATE_BYTES);
        assert!(!enrollment.user_id.as_uuid().is_nil());
        assert!(enrollment.allowed_client_ids.len() <= MAX_ALLOWED_CLIENTS);
        assert!(enrollment.validate().is_ok());
    }
    if let Ok(source) = SourceChange::parse(body) {
        assert!(body.len() <= MAX_UPDATE_BYTES);
        assert!(source.validate().is_ok());
    }
});
