//! Checking that a client controls the sector it named — OIDC Registration §5.
//!
//! A pairwise client may register a `sector_identifier_uri`, and its host is
//! then the sector every `sub` this server mints for that client is derived in
//! (OIDC Core §8.1, [`asterius_domain::SectorIdentifier::of_client`]). Naming
//! is free, so on its own it proves nothing: two unrelated clients naming one
//! sector would be handed the *same* `sub` for the same user, which is the
//! correlation pairwise subjects exist to prevent — defeated for both of them,
//! by whichever of the two registered second.
//!
//! §5 closes that by making the name a claim the client has to back: the
//! document at the URI is "a JSON file containing an array of `redirect_uri`
//! values", and the authorization server verifies that every `redirect_uri`
//! the client registered is in it. Only somebody who can publish at the
//! sector's host can put a callback there, so the check is a proof of control
//! over the sector, resolved once at registration.
//!
//! # It uses the one outbound path
//!
//! The URI is a string a client wrote, so fetching it is exactly the SSRF
//! problem ADR-0006 settled for `jwks_uri`, and this module adds no second
//! answer to it: it holds no socket, no HTTP client and no timeout. It takes
//! [`asterius_domain::ports::ClientUrlFetcher`] — the port whose one implementation
//! is [`super::jwks::HttpsClientUrlFetcher`] — and so inherits the address guard,
//! the refusal to follow redirects, the body cap and the timeouts unchanged.
//! A sector document is served as `application/json`, which that adapter
//! already accepts.
//!
//! # It also refuses a client that has no sector to name
//!
//! One case needs no bytes at all: a pairwise client whose redirect URIs are
//! all loopback and which named no sector. RFC 8252 §7.3 gives that host to
//! every native client, so §8.1's redirect-host rule would put them all in one
//! sector. [`asterius_domain::SectorIdentifier::check_registration`] is that
//! rule, and it is called here so that both registration endpoints — RFC 7591's
//! `POST /register` and RFC 7592's `PUT` — get it from one place.
//!
//! What is left here is the decision about *what the bytes have to say*, and
//! even that is delegated: [`ClientRegistration::check_sector_identifier_document`]
//! is pure and lives in the domain. This module is the two lines between them.

use asterius_domain::ports::ClientUrlFetcher;
use asterius_domain::{ClientMetadataError, ClientRegistration, SectorIdentifier};

/// The metadata field every failure here is reported against.
const FIELD: &str = "sector_identifier_uri";

/// Resolves a registration's `sector_identifier_uri`, if it has one.
///
/// Called with a registration that has already been through
/// [`ClientRegistration`]'s own validation, so the URI is known to be an
/// absolute https URL with a host: this is only the part that needs the
/// network. A registration with nothing to verify returns `Ok` without a
/// fetch — see
/// [`ClientRegistration::sector_identifier_uri_to_verify`].
///
/// # Errors
///
/// Returns [`ClientMetadataError::Rejected`] when the document cannot be
/// fetched, is not a JSON array of strings, or omits a registered redirect
/// URI. The three are one error to the client on purpose: the registration is
/// refused either way, and distinguishing "I could not reach your host" from
/// "your host answered" for an arbitrary address is a network probe.
pub async fn verify(
    fetcher: &dyn ClientUrlFetcher,
    registration: &ClientRegistration,
) -> Result<(), ClientMetadataError> {
    // Before the fetch, and without one: a pairwise client whose redirect URIs
    // are all loopback has no sector to verify, and `ast-m9c.10` is that this
    // must be a refused registration document rather than an authorization
    // request that fails later for a reason the client cannot see. The rule
    // itself lives with [`SectorIdentifier::of_client`], which applies the same
    // call to rows written before it existed.
    SectorIdentifier::check_registration(registration)?;

    let Some(uri) = registration.sector_identifier_uri_to_verify() else {
        return Ok(());
    };
    let document = match fetcher.fetch(uri).await {
        Ok(document) => document,
        Err(error) => {
            // The reason is logged and not returned. It names the host, the
            // refused address or the status, and none of that is the
            // registering client's business.
            tracing::debug!(error = %error, "sector_identifier_uri fetch failed");
            return Err(ClientMetadataError::unreachable(FIELD));
        }
    };
    registration.check_sector_identifier_document(&document)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::{Capabilities, DomainError};
    use serde_json::json;

    /// A fetcher that answers from memory, so the rule can be tested without a
    /// socket — which is also the only way to test it, since the guard in
    /// [`super::super::ssrf`] refuses loopback.
    #[derive(Debug)]
    struct Canned(Result<Vec<u8>, &'static str>);

    #[async_trait::async_trait]
    impl ClientUrlFetcher for Canned {
        async fn fetch(&self, _url: &str) -> Result<Vec<u8>, DomainError> {
            self.0
                .clone()
                .map_err(|reason| DomainError::invalid(FIELD, reason))
        }
    }

    fn serving(body: &serde_json::Value) -> Canned {
        Canned(Ok(body.to_string().into_bytes()))
    }

    /// A pairwise client whose two redirect hosts force it to name a sector.
    fn pairwise() -> ClientRegistration {
        registration(&json!({
            "client_name": "RP",
            "subject_type": "pairwise",
            "sector_identifier_uri": "https://rp.example/sector.json",
            "redirect_uris": ["https://a.rp.example/cb", "https://b.rp.example/cb"],
            "jwks_uri": "https://rp.example/jwks.json",
        }))
    }

    fn registration(document: &serde_json::Value) -> ClientRegistration {
        ClientRegistration::from_json(document.to_string().as_bytes(), Capabilities::default())
            .expect("a valid registration document")
    }

    #[tokio::test]
    async fn a_document_listing_every_redirect_uri_completes_the_registration() {
        let fetcher = serving(&json!([
            "https://a.rp.example/cb",
            "https://b.rp.example/cb"
        ]));

        let outcome = verify(&fetcher, &pairwise()).await;

        assert!(outcome.is_ok(), "{outcome:?}");
    }

    #[tokio::test]
    async fn a_document_omitting_a_registered_redirect_uri_refuses_the_registration() {
        let fetcher = serving(&json!(["https://a.rp.example/cb"]));

        let error = verify(&fetcher, &pairwise())
            .await
            .expect_err("an incomplete document must be refused");

        assert_eq!(error.field(), FIELD);
    }

    /// The third failure mode: the host does not answer, or the guard refused
    /// its address. The registration fails closed rather than trusting a
    /// sector nobody confirmed.
    #[tokio::test]
    async fn a_document_that_cannot_be_fetched_refuses_the_registration() {
        let fetcher = Canned(Err("refusing to fetch"));

        let error = verify(&fetcher, &pairwise())
            .await
            .expect_err("an unreachable document must be refused");

        assert_eq!(error.field(), FIELD);
        assert_eq!(error.code(), "invalid_client_metadata");
    }

    /// Nothing is dereferenced for a client that named no sector: a public
    /// client cannot carry the field, and a pairwise client with one redirect
    /// host takes the sector from a host it has already demonstrated it
    /// controls.
    #[tokio::test]
    async fn a_client_that_named_no_sector_is_never_fetched_for() {
        let fetcher = Canned(Err("this must not be called"));
        let public = registration(&json!({
            "client_name": "RP",
            "redirect_uris": ["https://rp.example/cb"],
            "jwks_uri": "https://rp.example/jwks.json",
        }));

        let outcome = verify(&fetcher, &public).await;

        assert!(outcome.is_ok(), "{outcome:?}");
    }
}
