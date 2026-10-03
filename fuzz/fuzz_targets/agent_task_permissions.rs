#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 32768 {
        return;
    }
    if let Ok(raw) = std::str::from_utf8(bytes) {
        let _ = asterius_domain::agent_tasks::parse_details(raw);
    }
    if let Ok(permissions) =
        serde_json::from_slice::<asterius_domain::agent_tasks::Permissions>(bytes)
    {
        let _ = permissions.validate();
        let mut grant = asterius_domain::Grant::new(
            asterius_domain::TenantId::new("fuzz"),
            asterius_domain::ClientId::new("fuzz"),
            time::OffsetDateTime::UNIX_EPOCH,
        );
        grant.scopes = permissions.scopes.clone();
        grant.resources = permissions.resources.clone();
        grant.authorization_details = permissions.authorization_details.clone();
        let _ = permissions.permits(&grant);
    }
});
