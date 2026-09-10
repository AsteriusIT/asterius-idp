//! RFC 8705 §2 client authentication, against certificates a CA really issued.
//!
//! The certificates here are made by the `openssl` command line, the way
//! `tests/tls_handshake.rs` makes the server's own. That is deliberate and it
//! is the point of the file: `crates/oidc/src/mtls.rs` has unit tests over DER
//! this repository encodes itself, and a parser tested only against its own
//! encoder agrees with itself and with nobody. Here the bytes come from an
//! independent implementation, and the RFC 4514 subject DN is compared against
//! what that implementation says the DN is.
//!
//! `openssl` is a *command*, not a crate: ADR-0004 and `deny.toml` ban linking
//! OpenSSL, and nothing here does. A machine without it skips, for the reason
//! the TLS handshake tests skip — the property is worth checking wherever the
//! tool exists and is not worth a hard dependency for everyone else.

use asterius_domain::ports::JwksFetcher;
use asterius_domain::{
    Capabilities, Client, ClientId, ClientRegistration, ClientRepository, ClientStatus,
    DomainError, Issuer, ReplayCheck, ReplayGuard, ReplayPurpose, Tenant, TenantId, TenantStatus,
};
use asterius_jose::client_keys::ClientKeyCache;
use asterius_oidc::client_auth::{AssertionRules, Attempt, ClientAuthError};
use asterius_oidc::mtls::ClientCertificate;
use asterius_server::client_auth::ClientAuthenticator;
use asterius_server::mtls::{TenantTrustAnchors, TrustAnchors};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use time::OffsetDateTime;

const ISSUER: &str = "https://as.example/t/demo";
const CLIENT: &str = "billing";

/// The subject the client certificate is issued with, in `openssl -subj` form.
const SUBJECT: &str = "/C=GB/O=Acme, Inc./CN=billing-client";

/// The SANs it carries, in `openssl` extension form.
const SANS: &str = "DNS:rp.example,URI:https://rp.example/id,IP:192.0.2.1,email:ops@rp.example";

// ---------------------------------------------------------------------------
// Certificates, from openssl
// ---------------------------------------------------------------------------

fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|output| output.status.success())
}

/// A CA, a client certificate it issued, and a self-signed certificate.
///
/// Built once per test in a self-cleaning directory, because a shared fixture
/// between tests that each need a *different* CA is a fixture that has to be
/// reasoned about.
struct Material {
    dir: PathBuf,
}

impl Drop for Material {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Material {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "asterius-mtls-{}-{name}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn run(&self, arguments: &[&str]) {
        let output = Command::new("openssl")
            .args(arguments)
            .current_dir(&self.dir)
            .output()
            .expect("run openssl");
        assert!(
            output.status.success(),
            "openssl {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// A self-signed CA certificate, `<name>.pem` with `<name>.key`.
    fn certificate_authority(&self, name: &str) {
        self.run(&[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.pem"),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign",
        ]);
    }

    /// A leaf certificate issued by `ca`, with the given extensions.
    fn issue(&self, name: &str, ca: &str, subject: &str, extensions: &str) {
        std::fs::write(self.path(&format!("{name}.ext")), extensions).expect("write extensions");
        self.run(&[
            "req",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.csr"),
            "-nodes",
            "-subj",
            subject,
        ]);
        self.run(&[
            "x509",
            "-req",
            "-in",
            &format!("{name}.csr"),
            "-CA",
            &format!("{ca}.pem"),
            "-CAkey",
            &format!("{ca}.key"),
            "-set_serial",
            "42",
            "-days",
            "1",
            "-extfile",
            &format!("{name}.ext"),
            "-out",
            &format!("{name}.pem"),
        ]);
    }

    /// A self-signed leaf: nobody vouches for it, which is RFC 8705 §2.2's
    /// whole case.
    fn self_signed(&self, name: &str, subject: &str) {
        self.run(&[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.pem"),
            "-days",
            "1",
            "-nodes",
            "-subj",
            subject,
        ]);
    }

    /// The DER of a PEM certificate.
    fn der(&self, name: &str) -> Vec<u8> {
        let out = self.path(&format!("{name}.der"));
        self.run(&[
            "x509",
            "-in",
            &format!("{name}.pem"),
            "-outform",
            "DER",
            "-out",
            &format!("{name}.der"),
        ]);
        std::fs::read(out).expect("read DER")
    }

    /// The base64 an `x5c` member carries (RFC 7517 §4.7).
    fn x5c(&self, name: &str) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(self.der(name))
    }

    /// What openssl says the subject DN is, in RFC 2253 / RFC 4514 string form.
    ///
    /// The external oracle: this is the whole reason the fixtures come from
    /// another implementation.
    fn subject_dn(&self, name: &str) -> String {
        let output = Command::new("openssl")
            .args(["x509", "-in", &format!("{name}.pem")])
            .args(["-noout", "-subject", "-nameopt", "RFC2253"])
            .current_dir(&self.dir)
            .output()
            .expect("run openssl");
        assert!(output.status.success(), "openssl x509 -subject failed");
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .strip_prefix("subject=")
            .expect("openssl prints `subject=<dn>`")
            .trim()
            .to_owned()
    }
}

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct FakeClients(HashMap<String, Client>);

#[async_trait::async_trait]
impl ClientRepository for FakeClients {
    async fn find(&self, client_id: &ClientId) -> Result<Option<Client>, DomainError> {
        Ok(self.0.get(client_id.as_str()).cloned())
    }
}

#[derive(Debug, Default)]
struct FakeReplay;

#[async_trait::async_trait]
impl ReplayGuard for FakeReplay {
    async fn claim(
        &self,
        _tenant: &TenantId,
        _purpose: ReplayPurpose,
        _subject: &str,
        _jti: &str,
        _expires_at: OffsetDateTime,
    ) -> Result<ReplayCheck, DomainError> {
        // mTLS consumes no `jti`: a certificate is not a one-time credential.
        // A test that reaches this has taken the assertion path by mistake.
        panic!("the mTLS path must not claim a replay identifier");
    }
}

#[derive(Debug)]
struct NoFetching;

#[async_trait::async_trait]
impl JwksFetcher for NoFetching {
    async fn fetch(&self, _url: &str) -> Result<Vec<u8>, DomainError> {
        panic!("a test reached the network; every fixture here has inline keys");
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn tenant(id: &str) -> Tenant {
    Tenant {
        id: TenantId::new(id),
        issuer: Issuer::parse(ISSUER).expect("issuer"),
        default_resource: "https://api.example/".to_owned(),
        custom_host: None,
        display_name: id.to_owned(),
        status: TenantStatus::Active,
        refresh: asterius_domain::RefreshPolicy::default(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn mtls_on() -> Capabilities {
    Capabilities {
        mtls: true,
        ..Capabilities::default()
    }
}

/// A registration document. `extra` carries whatever the method needs.
fn registration(method: &str, jwks: &Value, extra: &[(&str, Value)]) -> Client {
    let mut document = json!({
        "client_name": "Billing",
        "redirect_uris": ["https://rp.example/cb"],
        "grant_types": ["authorization_code"],
        "scope": "openid",
        "token_endpoint_auth_method": method,
        "jwks": jwks,
    });
    let object = document.as_object_mut().expect("object");
    for (key, value) in extra {
        object.insert((*key).to_owned(), value.clone());
    }
    Client {
        tenant: TenantId::new("demo"),
        id: ClientId::new(CLIENT),
        registration: ClientRegistration::from_json(
            &serde_json::to_vec(&document).expect("serialise"),
            mtls_on(),
        )
        .expect("a valid registration"),
        status: ClientStatus::Active,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

/// A JWK Set with no certificate: enough to register, never a match.
fn jwks_without_certificate() -> Value {
    json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": "k1"}]})
}

/// The same set, plus an `x5c` naming a certificate the client published.
fn jwks_with_certificate(x5c: &str) -> Value {
    json!({"keys": [
        {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": "k1"},
        {"kty": "EC", "crv": "P-256", "kid": "cert", "x5c": [x5c]},
    ]})
}

fn authenticator(anchors: TenantTrustAnchors) -> ClientAuthenticator {
    ClientAuthenticator::new(
        Arc::new(ClientKeyCache::new(Arc::new(NoFetching))),
        Arc::new(FakeReplay),
    )
    .expect("build")
    .with_trust_anchors(anchors)
}

fn anchors_for(tenant_id: &str, pem: &std::path::Path) -> TenantTrustAnchors {
    TenantTrustAnchors::from_map(BTreeMap::from([(
        TenantId::new(tenant_id),
        Arc::new(TrustAnchors::load(pem).expect("load anchors")),
    )]))
}

async fn authenticate(
    authenticator: &ClientAuthenticator,
    clients: &FakeClients,
    certificate: &ClientCertificate,
) -> Result<Client, ClientAuthError> {
    authenticator
        .authenticate(
            &tenant("demo"),
            clients,
            &Attempt {
                client_id: Some(CLIENT),
                certificate: Some(certificate),
                ..Attempt::default()
            },
            &AssertionRules::for_issuer(ISSUER),
            now(),
        )
        .await
}

fn clients_with(client: Client) -> FakeClients {
    let mut clients = FakeClients::default();
    clients.0.insert(CLIENT.to_owned(), client);
    clients
}

// ---------------------------------------------------------------------------
// RFC 4514: the parser against another implementation
// ---------------------------------------------------------------------------

/// The whole reason this file uses openssl. A subject DN rendered by this
/// server must be the string another implementation renders, or the byte-exact
/// comparison RFC 8705 §2.1 requires is a comparison against a name only this
/// server uses.
#[test]
fn the_subject_dn_matches_what_openssl_renders() {
    if !openssl_available() {
        eprintln!("skipping: openssl is not installed");
        return;
    }
    // Arrange
    let material = Material::new("dn");
    material.certificate_authority("ca");
    material.issue(
        "client",
        "ca",
        SUBJECT,
        &format!("extendedKeyUsage=clientAuth\nsubjectAltName={SANS}\n"),
    );
    let certificate = ClientCertificate::from_der(material.der("client")).expect("parse");

    // Act
    let names = certificate.subject().expect("names");

    // Assert
    assert_eq!(names.subject_dn, material.subject_dn("client"));
    // And the comma inside the O really is escaped, so the assertion above is
    // not two implementations agreeing on an unescaped string.
    assert!(names.subject_dn.contains("O=Acme\\, Inc."), "{names:?}");
}

/// The four SAN forms RFC 8705 §2.1.2 registers a metadata field for, read out
/// of a certificate another implementation encoded.
#[test]
fn the_san_entries_are_read_from_a_real_certificate() {
    if !openssl_available() {
        eprintln!("skipping: openssl is not installed");
        return;
    }
    // Arrange
    let material = Material::new("san");
    material.certificate_authority("ca");
    material.issue(
        "client",
        "ca",
        SUBJECT,
        &format!("extendedKeyUsage=clientAuth\nsubjectAltName={SANS}\n"),
    );
    let certificate = ClientCertificate::from_der(material.der("client")).expect("parse");

    // Act
    let names = certificate.subject().expect("names");

    // Assert
    assert_eq!(names.san_dns, vec!["rp.example".to_owned()]);
    assert_eq!(names.san_uri, vec!["https://rp.example/id".to_owned()]);
    assert_eq!(names.san_ip, vec!["192.0.2.1".to_owned()]);
    assert_eq!(names.san_email, vec!["ops@rp.example".to_owned()]);
}

// ---------------------------------------------------------------------------
// RFC 8705 §2.1: the PKI method
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_pki_client_authenticates_with_a_certificate_its_ca_issued() {
    if !openssl_available() {
        eprintln!("skipping: openssl is not installed");
        return;
    }
    // Arrange
    let material = Material::new("pki-ok");
    material.certificate_authority("ca");
    material.issue(
        "client",
        "ca",
        SUBJECT,
        &format!("extendedKeyUsage=clientAuth\nsubjectAltName={SANS}\n"),
    );
    let certificate = ClientCertificate::from_der(material.der("client")).expect("parse");
    let clients = clients_with(registration(
        "tls_client_auth",
        &jwks_without_certificate(),
        &[("tls_client_auth_san_dns", json!("rp.example"))],
    ));
    let authenticator = authenticator(anchors_for("demo", &material.path("ca.pem")));

    // Act
    let authenticated = authenticate(&authenticator, &clients, &certificate).await;

    // Assert
    assert_eq!(
        authenticated
            .expect("the CA vouched for it and the SAN matches")
            .id,
        ClientId::new(CLIENT)
    );
}

/// The registered value is compared exactly. This is the same CA, the same
/// client, and a name one character away from the registered one.
#[tokio::test]
async fn a_certificate_whose_name_is_not_the_registered_one_is_refused() {
    if !openssl_available() {
        eprintln!("skipping: openssl is not installed");
        return;
    }
    // Arrange
    let material = Material::new("pki-name");
    material.certificate_authority("ca");
    material.issue(
        "client",
        "ca",
        SUBJECT,
        &format!("extendedKeyUsage=clientAuth\nsubjectAltName={SANS}\n"),
    );
    let certificate = ClientCertificate::from_der(material.der("client")).expect("parse");
    let authenticator = authenticator(anchors_for("demo", &material.path("ca.pem")));

    for registered in ["RP.example", "rp.example.", "evil-rp.example", "rp.exampl"] {
        let clients = clients_with(registration(
            "tls_client_auth",
            &jwks_without_certificate(),
            &[("tls_client_auth_san_dns", json!(registered))],
        ));

        // Act
        let authenticated = authenticate(&authenticator, &clients, &certificate).await;

        // Assert
        assert_eq!(
            authenticated.err(),
            Some(ClientAuthError::AssertionNotVerified),
            "`{registered}` matched a certificate saying `rp.example`"
        );
    }
}

/// The name is only worth something because a CA vouched for it. A certificate
/// carrying exactly the registered subject, issued by a CA this tenant does
/// not name, authenticates nobody — this is the whole of §2.1.
#[tokio::test]
async fn a_certificate_from_an_untrusted_ca_is_refused_however_right_its_name_is() {
    if !openssl_available() {
        eprintln!("skipping: openssl is not installed");
        return;
    }
    // Arrange: two CAs, and a certificate from the one the tenant does not
    // trust, with the name the client registered.
    let material = Material::new("pki-ca");
    material.certificate_authority("trusted");
    material.certificate_authority("rogue");
    material.issue(
        "impostor",
        "rogue",
        SUBJECT,
        &format!("extendedKeyUsage=clientAuth\nsubjectAltName={SANS}\n"),
    );
    let certificate = ClientCertificate::from_der(material.der("impostor")).expect("parse");
    let clients = clients_with(registration(
        "tls_client_auth",
        &jwks_without_certificate(),
        &[("tls_client_auth_san_dns", json!("rp.example"))],
    ));
    let authenticator = authenticator(anchors_for("demo", &material.path("trusted.pem")));

    // Act
    let authenticated = authenticate(&authenticator, &clients, &certificate).await;

    // Assert
    assert_eq!(
        authenticated.err(),
        Some(ClientAuthError::AssertionNotVerified),
        "a CA this tenant never named minted a client"
    );
}

/// One process, several tenants. A CA tenant A trusts must not be able to mint
/// a client for tenant B.
#[tokio::test]
async fn one_tenants_anchors_are_not_offered_to_another() {
    if !openssl_available() {
        eprintln!("skipping: openssl is not installed");
        return;
    }
    // Arrange: the anchors are loaded under `other`, and the request arrives
    // at `demo`.
    let material = Material::new("pki-tenant");
    material.certificate_authority("ca");
    material.issue(
        "client",
        "ca",
        SUBJECT,
        &format!("extendedKeyUsage=clientAuth\nsubjectAltName={SANS}\n"),
    );
    let certificate = ClientCertificate::from_der(material.der("client")).expect("parse");
    let clients = clients_with(registration(
        "tls_client_auth",
        &jwks_without_certificate(),
        &[("tls_client_auth_san_dns", json!("rp.example"))],
    ));
    let authenticator = authenticator(anchors_for("other", &material.path("ca.pem")));

    // Act
    let authenticated = authenticate(&authenticator, &clients, &certificate).await;

    // Assert
    assert_eq!(
        authenticated.err(),
        Some(ClientAuthError::WrongMethodForClient),
        "another tenant's CA vouched for this tenant's client"
    );
}

/// A certificate the same CA issued for a *server*. Accepting it would let
/// anyone running an HTTPS host under a tenant's CA authenticate as a client.
#[tokio::test]
async fn a_server_certificate_from_the_right_ca_is_not_a_client_credential() {
    if !openssl_available() {
        eprintln!("skipping: openssl is not installed");
        return;
    }
    // Arrange
    let material = Material::new("pki-eku");
    material.certificate_authority("ca");
    material.issue(
        "server",
        "ca",
        SUBJECT,
        &format!("extendedKeyUsage=serverAuth\nsubjectAltName={SANS}\n"),
    );
    let certificate = ClientCertificate::from_der(material.der("server")).expect("parse");
    let clients = clients_with(registration(
        "tls_client_auth",
        &jwks_without_certificate(),
        &[("tls_client_auth_san_dns", json!("rp.example"))],
    ));
    let authenticator = authenticator(anchors_for("demo", &material.path("ca.pem")));

    // Act
    let authenticated = authenticate(&authenticator, &clients, &certificate).await;

    // Assert
    assert_eq!(
        authenticated.err(),
        Some(ClientAuthError::AssertionNotVerified),
        "a serverAuth certificate authenticated a client"
    );
}

/// A tenant with no anchors fails closed rather than reaching for some other
/// trust root.
#[tokio::test]
async fn a_tenant_with_no_anchors_cannot_use_the_pki_method() {
    if !openssl_available() {
        eprintln!("skipping: openssl is not installed");
        return;
    }
    // Arrange
    let material = Material::new("pki-none");
    material.certificate_authority("ca");
    material.issue(
        "client",
        "ca",
        SUBJECT,
        &format!("extendedKeyUsage=clientAuth\nsubjectAltName={SANS}\n"),
    );
    let certificate = ClientCertificate::from_der(material.der("client")).expect("parse");
    let clients = clients_with(registration(
        "tls_client_auth",
        &jwks_without_certificate(),
        &[("tls_client_auth_san_dns", json!("rp.example"))],
    ));
    let authenticator = authenticator(TenantTrustAnchors::default());

    // Act
    let authenticated = authenticate(&authenticator, &clients, &certificate).await;

    // Assert
    assert_eq!(
        authenticated.err(),
        Some(ClientAuthError::WrongMethodForClient)
    );
}

// ---------------------------------------------------------------------------
// RFC 8705 §2.2: the self-signed method
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_self_signed_client_authenticates_with_the_certificate_it_published() {
    if !openssl_available() {
        eprintln!("skipping: openssl is not installed");
        return;
    }
    // Arrange: nobody vouches for this certificate. It authenticates because
    // it is byte-for-byte the one in the client's JWK Set.
    let material = Material::new("self-ok");
    material.self_signed("client", SUBJECT);
    let certificate = ClientCertificate::from_der(material.der("client")).expect("parse");
    let clients = clients_with(registration(
        "self_signed_tls_client_auth",
        &jwks_with_certificate(&material.x5c("client")),
        &[],
    ));
    // No anchors at all: §2.2 needs none, and a deployment that had some must
    // not be quietly using them here.
    let authenticator = authenticator(TenantTrustAnchors::default());

    // Act
    let authenticated = authenticate(&authenticator, &clients, &certificate).await;

    // Assert
    assert_eq!(
        authenticated
            .expect("the client published this certificate")
            .id,
        ClientId::new(CLIENT)
    );
}

#[tokio::test]
async fn a_self_signed_certificate_the_client_never_published_is_refused() {
    if !openssl_available() {
        eprintln!("skipping: openssl is not installed");
        return;
    }
    // Arrange: two self-signed certificates with the *same subject*, so the
    // only thing that separates them is which one the client published.
    let material = Material::new("self-other");
    material.self_signed("published", SUBJECT);
    material.self_signed("impostor", SUBJECT);
    let certificate = ClientCertificate::from_der(material.der("impostor")).expect("parse");
    let clients = clients_with(registration(
        "self_signed_tls_client_auth",
        &jwks_with_certificate(&material.x5c("published")),
        &[],
    ));
    let authenticator = authenticator(TenantTrustAnchors::default());

    // Act
    let authenticated = authenticate(&authenticator, &clients, &certificate).await;

    // Assert
    assert_eq!(
        authenticated.err(),
        Some(ClientAuthError::AssertionNotVerified),
        "a certificate with the right subject but the wrong bytes authenticated"
    );
}

#[tokio::test]
async fn a_self_signed_client_with_no_x5c_authenticates_nobody() {
    if !openssl_available() {
        eprintln!("skipping: openssl is not installed");
        return;
    }
    // Arrange
    let material = Material::new("self-nokeys");
    material.self_signed("client", SUBJECT);
    let certificate = ClientCertificate::from_der(material.der("client")).expect("parse");
    let clients = clients_with(registration(
        "self_signed_tls_client_auth",
        &jwks_without_certificate(),
        &[],
    ));
    let authenticator = authenticator(TenantTrustAnchors::default());

    // Act
    let authenticated = authenticate(&authenticator, &clients, &certificate).await;

    // Assert
    assert_eq!(
        authenticated.err(),
        Some(ClientAuthError::AssertionNotVerified)
    );
}

// ---------------------------------------------------------------------------
// The dispatch
// ---------------------------------------------------------------------------

/// The two mTLS methods are not alternatives that get tried in turn. A client
/// registered for §2.1 is not authenticated by a certificate it happens to
/// have published, and the reverse.
#[tokio::test]
async fn the_two_mtls_methods_do_not_substitute_for_each_other() {
    if !openssl_available() {
        eprintln!("skipping: openssl is not installed");
        return;
    }
    // Arrange
    let material = Material::new("dispatch");
    material.certificate_authority("ca");
    material.issue(
        "client",
        "ca",
        SUBJECT,
        &format!("extendedKeyUsage=clientAuth\nsubjectAltName={SANS}\n"),
    );
    let certificate = ClientCertificate::from_der(material.der("client")).expect("parse");
    let anchors = anchors_for("demo", &material.path("ca.pem"));

    // A self-signed client that has published this very certificate, but a CA
    // also vouches for it: §2.2 is what applies, and it applies fully.
    let published = clients_with(registration(
        "self_signed_tls_client_auth",
        &jwks_with_certificate(&material.x5c("client")),
        &[],
    ));
    // A PKI client whose registered name this certificate carries, but which
    // has also published it: §2.1 is what applies.
    let pki = clients_with(registration(
        "tls_client_auth",
        &jwks_with_certificate(&material.x5c("client")),
        &[("tls_client_auth_san_dns", json!("rp.example"))],
    ));

    // Act & Assert: each authenticates under its own rule.
    assert!(
        authenticate(&authenticator(anchors.clone()), &published, &certificate)
            .await
            .is_ok()
    );
    assert!(
        authenticate(&authenticator(anchors), &pki, &certificate)
            .await
            .is_ok()
    );

    // And a PKI client with no anchors is refused even though its JWKS holds
    // the certificate, which is what "not alternatives" means.
    assert_eq!(
        authenticate(
            &authenticator(TenantTrustAnchors::default()),
            &pki,
            &certificate
        )
        .await
        .err(),
        Some(ClientAuthError::WrongMethodForClient)
    );
}

/// RFC 8705 §2: "the client MUST use the `client_id` request parameter".
/// Nothing inside a certificate names a client of *this* server.
#[tokio::test]
async fn a_certificate_without_a_client_id_names_nobody() {
    if !openssl_available() {
        eprintln!("skipping: openssl is not installed");
        return;
    }
    // Arrange
    let material = Material::new("no-client-id");
    material.self_signed("client", SUBJECT);
    let certificate = ClientCertificate::from_der(material.der("client")).expect("parse");
    let clients = clients_with(registration(
        "self_signed_tls_client_auth",
        &jwks_with_certificate(&material.x5c("client")),
        &[],
    ));

    // Act
    let authenticated = authenticator(TenantTrustAnchors::default())
        .authenticate(
            &tenant("demo"),
            &clients,
            &Attempt {
                certificate: Some(&certificate),
                ..Attempt::default()
            },
            &AssertionRules::for_issuer(ISSUER),
            now(),
        )
        .await;

    // Assert
    assert_eq!(authenticated.err(), Some(ClientAuthError::UnknownClient));
}

/// A `private_key_jwt` client is not authenticated by a certificate, however
/// good the certificate is.
#[tokio::test]
async fn a_private_key_jwt_client_is_not_authenticated_by_a_certificate() {
    if !openssl_available() {
        eprintln!("skipping: openssl is not installed");
        return;
    }
    // Arrange
    let material = Material::new("wrong-method");
    material.self_signed("client", SUBJECT);
    let certificate = ClientCertificate::from_der(material.der("client")).expect("parse");
    let clients = clients_with(registration(
        "private_key_jwt",
        &jwks_with_certificate(&material.x5c("client")),
        &[],
    ));

    // Act
    let authenticated = authenticate(
        &authenticator(TenantTrustAnchors::default()),
        &clients,
        &certificate,
    )
    .await;

    // Assert
    assert_eq!(
        authenticated.err(),
        Some(ClientAuthError::WrongMethodForClient)
    );
}

#[tokio::test]
async fn a_disabled_client_is_not_distinguishable_from_one_that_never_existed() {
    if !openssl_available() {
        eprintln!("skipping: openssl is not installed");
        return;
    }
    // Arrange
    let material = Material::new("disabled");
    material.self_signed("client", SUBJECT);
    let certificate = ClientCertificate::from_der(material.der("client")).expect("parse");
    let mut disabled = registration(
        "self_signed_tls_client_auth",
        &jwks_with_certificate(&material.x5c("client")),
        &[],
    );
    disabled.status = ClientStatus::Disabled;
    let authenticator = authenticator(TenantTrustAnchors::default());

    // Act
    let refused = authenticate(&authenticator, &clients_with(disabled), &certificate).await;
    let absent = authenticate(&authenticator, &FakeClients::default(), &certificate).await;

    // Assert
    assert_eq!(refused.err(), Some(ClientAuthError::UnknownClient));
    assert_eq!(absent.err(), Some(ClientAuthError::UnknownClient));
}
