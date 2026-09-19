//! Exact group-name parsing and bounded, non-misleading display metadata.
#![no_main]

use asterius_domain::{GroupMetadata, GroupName};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (String, String)| {
    let (name, display) = input;
    let admissible_name = !name.is_empty()
        && name.len() <= GroupName::MAX_LEN
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._:-".contains(&byte)
        });
    assert_eq!(GroupName::parse(&name).is_ok(), admissible_name);
    if let Ok(parsed) = GroupName::parse(&name) {
        assert_eq!(parsed.as_str(), name);
        assert_eq!(GroupName::parse(parsed.as_str()).unwrap(), parsed);
    }
    // A known valid machine name ensures arbitrary display text reaches its
    // validator even when the independently generated name is invalid.
    for candidate in [name.as_str(), "engineering"] {
        let parsed = GroupMetadata::parse(candidate, &display);
        let admissible_display = !display.is_empty()
            && display.len() <= GroupMetadata::MAX_DISPLAY_BYTES
            && display.trim() == display
            && display.chars().all(|c| {
                !c.is_control()
                    && !matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            });
        assert_eq!(
            parsed.is_ok(),
            GroupName::parse(candidate).is_ok() && admissible_display
        );
        if let Ok(parsed) = parsed {
            assert_eq!(parsed.name().as_str(), candidate);
            assert_eq!(parsed.display_name(), display);
            assert_eq!(
                GroupMetadata::parse(parsed.name().as_str(), parsed.display_name()).unwrap(),
                parsed
            );
        }
    }
});
