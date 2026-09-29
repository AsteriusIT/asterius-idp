//! QR geometry for authenticator setup, generated locally without markup or requests.
use qrcodegen::{QrCode, QrCodeEcc};

/// Integer-only geometry; Askama still escapes every attribute. Not Debug: this
/// shape encodes a credential and must never enter diagnostic logs.
pub struct SetupQr {
    pub size: i32,
    pub modules: Vec<(i32, i32)>,
}

impl SetupQr {
    /// Oversized input retains the manual setup path rather than failing enrollment.
    #[must_use]
    pub fn new(uri: &str) -> Option<Self> {
        let code = QrCode::encode_text(uri, QrCodeEcc::Medium).ok()?;
        let mut modules = Vec::new();
        for y in 0..code.size() {
            for x in 0..code.size() {
                if code.get_module(x, y) {
                    modules.push((x + 4, y + 4));
                }
            }
        }
        Some(Self {
            size: code.size() + 8,
            modules,
        })
    }
}

impl std::fmt::Debug for SetupQr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SetupQr([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_geometry_has_a_quiet_zone_and_redacted_debug() {
        let code =
            SetupQr::new("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&issuer=Example").unwrap();
        assert!(
            code.modules
                .iter()
                .all(|&(x, y)| x >= 4 && y >= 4 && x < code.size - 4 && y < code.size - 4)
        );
        assert!(!code.modules.is_empty());
        assert_eq!(format!("{code:?}"), "SetupQr([REDACTED])");
    }

    #[test]
    fn oversized_setup_retains_the_manual_fallback() {
        assert!(SetupQr::new(&"x".repeat(10_000)).is_none());
    }
}
