//! Management import identities must be bounded, canonical and round-trip stable.
#![no_main]
use libfuzzer_sys::fuzz_target;
use asterius_domain::declarative::Identity;
fuzz_target!(|data: &[u8]| {
    if let Ok(raw) = std::str::from_utf8(data) {
        if let Ok(identity) = Identity::parse(raw) {
            let encoded = identity.encode().expect("validated identity encodes");
            assert_eq!(Identity::parse(&encoded).expect("encoded identity parses"), identity);
        }
    }
});
