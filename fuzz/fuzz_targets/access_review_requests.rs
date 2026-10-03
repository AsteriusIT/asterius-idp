//! Posted ownership/review/decision data must remain bounded and fail closed.
#![no_main]
use asterius_domain::access_reviews::{parse_decision,parse_ownership,parse_review};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data:&[u8]| {
    if let Ok(request)=parse_ownership(data){ assert!(request.validate().is_ok());assert!(request.reviewers.len()<=20); }
    if let Ok(request)=parse_review(data){ assert!(!request.ownership_ids.is_empty());assert!(request.ownership_ids.len()<=200); }
    if let Ok(request)=parse_decision(data){ assert!(!request.reason.trim().is_empty());assert!(request.reason.chars().count()<=1000); }
});
