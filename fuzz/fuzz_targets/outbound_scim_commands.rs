//! Commands accept resource selections, never posted actor/key/path authority.
#![no_main]
use asterius_domain::{
    TenantId,
    outbound_scim::{parse_configure, parse_selection, parse_lifecycle},
};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(command) = parse_lifecycle(data) { assert!(command.validate().is_ok()); }
    if let Ok(command) = parse_selection(data) {
        assert!(command.sources.len() <= 100);
        assert!(command.kind().is_ok());
    }
    if let Ok(command) = parse_configure(data) {
        let binding = command.binding(&TenantId::new("source")).expect("valid");
        assert_eq!(binding.source_tenant.as_str(), "source");
        assert!(binding.target_admin_resource.ends_with("/admin/api/v1"));
    }
});
