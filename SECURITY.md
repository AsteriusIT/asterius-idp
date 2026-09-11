# Security policy

Asterius is an identity provider: a bug here is somebody else's authentication.
This file says how to tell us about one, what happens next, and what we will and
will not do.

> **Contact address: not set yet.** Reports should go to
> **`security@<to be defined by the project owner>`** — the domain is not
> registered at the time of writing, so *this placeholder is deliberate and this
> channel does not work yet*. Until the owner replaces it here (and publishes a
> matching `security.txt`), use a **private GitHub security advisory** on the
> repository: *Security → Report a vulnerability*. Please do not open a public
> issue for a vulnerability, and do not use a public discussion, a pull request
> or a social-media mention as a first contact.

## Supported versions

| Version | Supported |
|---|---|
| `main` | Yes — the only branch that receives fixes |
| tagged releases | None exist yet |

Asterius is **pre-alpha**: there is no tagged release, no published container
image for production, and no deployment we know of that is serving real users.
Nothing here is production-ready, and the FAPI 2.0 conformance report is a gate
on a release that has not happened. What that means for this policy:

- there is no back-porting, because there is nothing to back-port to: a fix
  lands on `main`;
- once a `1.0` is tagged, this table will name the release line that receives
  security fixes and for how long, and this paragraph will be replaced.

A vulnerability report about a checkout of `main` is in scope and welcome.

## Reporting a vulnerability

Include, as far as you can:

1. the version — a commit SHA of `main` — and how the instance was configured
   (`asterius.toml` with secrets removed, the transport mode, whether a reverse
   proxy terminates TLS);
2. what an attacker gains: which of the goals in
   [`docs/threat-model.md`](docs/threat-model.md) §1 it breaks (G1 authorization,
   G2 authentication, G3 session integrity, G4 delegation integrity), and which
   attacker capability it needs (§2, A1–A5);
3. reproduction — a request sequence, a script, a failing test, or a fuzz input.
   A `cargo fuzz` crash artefact is an excellent report;
4. whether the finding is already public anywhere, and whether you intend to
   publish;
5. how you want to be credited, or that you would rather not be.

Please report in English or French. Encrypted reporting (a PGP key, or the
advisory channel's own encryption) will be documented here when the contact
address is set.

## What we commit to

| Step | Target |
|---|---|
| Acknowledgement of your report | **3 working days** |
| First assessment — severity, whether we can reproduce it, and whether it is in scope | **10 working days** |
| Fix, mitigation, or a written explanation of why neither is possible yet | **90 days** from acknowledgement |
| Progress updates while that runs | at least every 14 days |

These are targets for a small project, not a contractual SLA. If a deadline is
going to slip, you will be told before it does, with a reason.

## Coordinated disclosure

- We ask you to keep the report private until a fix is available or **90 days**
  have passed since acknowledgement, whichever comes first.
- We will publish a GitHub security advisory (and a CVE where one applies) when
  the fix lands, naming you as the reporter unless you asked otherwise.
- If a vulnerability is being exploited in the wild, or is already public, the
  90 days do not apply: we will publish a mitigation as soon as we have one,
  and coordinate the timing with you.
- If we cannot fix something inside 90 days, we will say so publicly — the
  threat model already carries what is knowingly unfixed (§5) and what is
  undecided (§7), and a known-unfixable vulnerability belongs in the same place
  rather than in a drawer.
- You may publish your own write-up once the advisory is out. We would rather it
  be accurate than early, and we will review a draft on request.

## Safe harbour

If you make a good-faith effort to follow this policy, we will not pursue or
support legal action against you for your research, and we will treat your
report as authorised conduct. Good faith means, concretely:

- you test against **your own** instance — this repository ships a compose stack
  that runs from a checkout (see the README), so there is never a reason to test
  against somebody else's deployment;
- you do not access, modify or retain data that is not yours, and you stop as
  soon as you have proved the vulnerability;
- you do not degrade service for others: no denial-of-service testing, no
  spamming of a live instance, no automated scanning of a third party's
  deployment;
- you do not use social engineering, phishing or physical access against anyone;
- you give us the reporting window above before going public.

This safe harbour is what *this project* offers. It cannot bind a third party
who runs Asterius: if you find a vulnerability while looking at somebody else's
deployment, their policy governs what you may do there, not ours.

## Scope

**In scope** — anything in this repository:

- the `asterius` server and every crate under `crates/`;
- the admin console (`console/`) and the server-rendered end-user pages;
- the deployment material we publish: `Dockerfile`, `deploy/`, the example
  compose stack, and the documented configuration surface
  ([`docs/configuration.md`](docs/configuration.md));
- the documentation, where a wrong instruction produces an insecure deployment —
  a `docs/deployment/tls-and-proxy.md` example that leaves a forwarding header
  unstripped is a vulnerability in this repository, not a typo;
- the build and release pipeline under `.github/workflows/`.

**Out of scope:**

- **Third-party deployments of Asterius.** Report those to whoever runs them.
- **Known and documented limitations.** Read
  [`docs/threat-model.md`](docs/threat-model.md) §5 (accepted residual risks) and
  §7 (decisions pending review) first. A report that names one of those rows is
  still useful if it *changes the assessment* — a working exploit, or a
  consequence we did not see — and it is always useful as an argument for
  deciding a §7 question. It will not be treated as a new vulnerability.
- **Development values used as development values.** The example compose stack
  terminates no TLS, generates its own certificate and ships development
  secrets, all of it documented in `deploy/README.md`. Reporting that the demo
  stack is not production-hardened tells us what we already wrote down.
- **Anything requiring something the trust computing base assumes** (threat
  model §2): a compromised database host, an attacker with arbitrary SQL access,
  a broken TLS deployment, a compromised operator workstation, or a flaw in the
  operating system CSPRNG.
- **Missing hardening with no attack behind it.** A header we do not send, a
  cipher suite score, a dependency's advisory that does not reach a code path we
  execute — send it, but as an issue, not as a vulnerability. `cargo deny check
  advisories` already runs in CI.
- **Spam, DoS by volume, or automated-scanner output with no analysis.**

## What this project already does, so you can aim better

- [`docs/threat-model.md`](docs/threat-model.md) — the attacker model (FAPI 2.0
  A1–A5 plus agent threats), every control with its file and test, the accepted
  residual risks, and the artefact list an external reviewer should ask for
  (§8).
- [`docs/adr/`](docs/adr/README.md) — why the hard choices are what they are.
- `#![forbid(unsafe_code)]` in every crate, checked three ways
  (`scripts/check-no-unsafe.sh`, `scripts/check-geiger.sh`, and the compiler).
- A fuzz target for every parser and validator, gated by
  `scripts/check-fuzz-coverage.sh` and run nightly.
- `cargo deny check advisories bans licenses sources` on every change.
- The OpenID Foundation FAPI 2.0 conformance suite, nightly and as a release
  gate.
