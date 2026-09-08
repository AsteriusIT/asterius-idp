//! Real TLS handshakes against a running listener.
//!
//! FAPI 2.0 SP §5.2.1 requires TLS 1.2 or later, and §5.2.2 restricts cipher
//! suites on server-to-server endpoints to BCP 195. `http::tls` asserts the
//! *configuration*; this asserts what happens on the wire, because a
//! correct-looking rustls config that is never reached proves nothing.
//!
//! rustls cannot speak TLS 1.0 or 1.1, so the client is `openssl s_client`.
//! These tests skip when `openssl` is missing rather than failing: the property
//! is worth checking wherever a client exists, and is not worth a hard
//! dependency for everyone else.

use asterius_server::config::{ServerConfig, TlsConfig, TransportMode};
use asterius_server::http::server::{bind, serve_on, with_middleware};
use axum::Router;
use axum::routing::get;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How long a client may take before the test gives up on it.
const CLIENT_DEADLINE: Duration = Duration::from_secs(5);

/// A self-signed P-256 certificate for `localhost`, in a self-cleaning directory.
struct Material {
    dir: PathBuf,
    certificate: PathBuf,
    private_key: PathBuf,
}

impl Drop for Material {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn issue_certificate(name: &str) -> Material {
    let dir = std::env::temp_dir().join(format!("asterius-tls-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let certificate = dir.join("cert.pem");
    let private_key = dir.join("key.pem");

    let output = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ec"])
        .args(["-pkeyopt", "ec_paramgen_curve:P-256"])
        .arg("-keyout")
        .arg(&private_key)
        .arg("-out")
        .arg(&certificate)
        .args(["-days", "1", "-nodes", "-subj", "/CN=localhost"])
        .output()
        .expect("run openssl req");
    assert!(
        output.status.success(),
        "openssl req failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    Material {
        dir,
        certificate,
        private_key,
    }
}

fn tls_config(material: &Material) -> ServerConfig {
    // Built directly rather than parsed from TOML: the listener is what is
    // under test, and a test that also exercises the config parser can fail for
    // two unrelated reasons.
    ServerConfig {
        bind: "127.0.0.1:0".parse().expect("literal address"),
        mode: TransportMode::TerminateTls,
        tls: Some(TlsConfig {
            certificate: material.certificate.clone(),
            private_key: material.private_key.clone(),
        }),
        trusted_proxies: Vec::new(),
        request_body_limit: 64 * 1024,
        request_timeout: Duration::from_secs(10),
    }
}

/// Starts a TLS listener on an ephemeral port and returns its address and a
/// shutdown handle.
async fn start(config: ServerConfig) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = bind(&config).await.expect("bind");
    let addr = listener.local_addr().expect("local address");
    let app = with_middleware(Router::new().route("/", get(|| async { "ok" })), &config);
    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let shutdown = async move {
            let _ = rx.await;
        };
        serve_on(listener, &config, app, shutdown)
            .await
            .expect("serve");
    });

    // Let the accept loop reach its first await before a client arrives.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, tx)
}

/// Runs `openssl s_client` and reports whether the handshake completed.
///
/// `-no_ign_eof` is what keeps this quick: `s_client` otherwise sits in the
/// established session waiting for input, and a test that has to kill its own
/// client cannot cleanly distinguish a wedged client from a refused handshake.
/// With it, closing stdin closes the connection as soon as the handshake is
/// done, so a clean exit means success and a non-zero exit means refusal.
///
/// Stdin must carry at least one byte before it closes. Handed `/dev/null`,
/// `s_client` sees EOF before the handshake finishes and exits 0 having done
/// nothing and printed nothing — which looks exactly like success. Writing a
/// newline first is what `echo | openssl s_client` does, and it is load-bearing.
///
/// `-verify_return_error` is deliberately absent: the certificate is
/// self-signed, and trust is not what is being tested — the protocol version
/// and the cipher suite are.
fn s_client(addr: SocketAddr, extra: &[&str]) -> (bool, String) {
    let mut child = Command::new("openssl")
        .arg("s_client")
        .arg("-connect")
        .arg(addr.to_string())
        .args(["-servername", "localhost", "-no_ign_eof"])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn openssl s_client");

    {
        use std::io::Write as _;
        let mut stdin = child.stdin.take().expect("piped stdin");
        let _ = stdin.write_all(b"\n");
        // Dropping the handle closes stdin, which is what ends the session.
    }

    // Safety net: if s_client hangs anyway, fail the assertion rather than the
    // whole suite.
    let deadline = Instant::now() + CLIENT_DEADLINE;
    let exited = loop {
        match child.try_wait().expect("poll openssl s_client") {
            Some(status) => break Some(status),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };

    let output = child.wait_with_output().expect("collect openssl output");
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));

    // A client we had to kill was sitting in an established session, so the
    // handshake had in fact succeeded.
    (exited.is_none_or(|status| status.success()), text)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_1_3_and_1_2_complete_a_handshake() {
    if !openssl_available() {
        eprintln!("skipping: openssl is not installed");
        return;
    }
    let material = issue_certificate("modern");
    let (addr, shutdown) = start(tls_config(&material)).await;

    for (flag, expected) in [("-tls1_3", "TLSv1.3"), ("-tls1_2", "TLSv1.2")] {
        let (ok, output) = s_client(addr, &[flag]);
        assert!(ok, "{flag} did not complete a handshake:\n{output}");
        assert!(
            output.contains(expected),
            "{flag} did not negotiate {expected}:\n{output}"
        );
    }
    let _ = shutdown.send(());
}

/// FAPI 2.0 SP §5.2.1: TLS 1.2 is the floor. OpenSSL 3 disables 1.0 and 1.1 by
/// default, so the client is pushed down to security level 0 to make it try —
/// otherwise this would pass without the server ever being asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_1_0_and_1_1_are_refused() {
    if !openssl_available() {
        eprintln!("skipping: openssl is not installed");
        return;
    }
    let material = issue_certificate("legacy");
    let (addr, shutdown) = start(tls_config(&material)).await;

    for flag in ["-tls1", "-tls1_1"] {
        let (ok, output) = s_client(addr, &[flag, "-cipher", "DEFAULT@SECLEVEL=0"]);
        assert!(
            !ok,
            "{flag} completed a handshake, which it must not:\n{output}"
        );
    }
    let _ = shutdown.send(());
}

/// BCP 195: whatever gets negotiated must have forward secrecy and be AEAD.
/// This checks what was actually chosen, not what was configured.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_negotiated_cipher_suite_has_forward_secrecy_and_is_aead() {
    if !openssl_available() {
        eprintln!("skipping: openssl is not installed");
        return;
    }
    let material = issue_certificate("suites");
    let (addr, shutdown) = start(tls_config(&material)).await;

    let (ok, output) = s_client(addr, &["-tls1_2"]);
    assert!(ok, "handshake failed:\n{output}");

    let line = output
        .lines()
        .find(|l| l.contains("Cipher is") || l.trim_start().starts_with("Cipher    :"))
        .unwrap_or_default()
        .to_owned();
    assert!(!line.is_empty(), "no cipher suite reported:\n{output}");
    assert!(line.contains("ECDHE"), "no forward secrecy: {line}");
    assert!(
        line.contains("GCM") || line.contains("CHACHA20") || line.contains("POLY1305"),
        "not an AEAD suite: {line}"
    );
    assert!(
        !line.contains("CBC"),
        "CBC is not permitted by BCP 195: {line}"
    );

    let _ = shutdown.send(());
}

/// A cleartext request to the TLS port must not be answered. This is the mirror
/// of the HSTS requirement: a server that helpfully speaks plain HTTP on its
/// TLS port hands attacker A2 the downgrade that HSTS exists to prevent.
///
/// No `openssl` needed — this one is a bare socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cleartext_request_to_the_tls_port_gets_nothing() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    if !openssl_available() {
        eprintln!("skipping: openssl is needed to issue the test certificate");
        return;
    }
    let material = issue_certificate("cleartext");
    let (addr, shutdown) = start(tls_config(&material)).await;

    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write");

    let mut buffer = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buffer)).await;

    let body = String::from_utf8_lossy(&buffer);
    assert!(
        !body.contains("HTTP/1.1 200"),
        "the TLS port answered in cleartext: {body:?}"
    );
    assert!(
        !body.contains("Strict-Transport-Security"),
        "cleartext response: {body:?}"
    );

    let _ = shutdown.send(());
}
