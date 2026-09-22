# VEX

`asterius.openvex.json` is an [OpenVEX](https://openvex.dev) v0.2.0 document: the
project's own statement about advisories that a scanner reports against Asterius
but that do not affect it.

It exists because the two questions are different. An SBOM answers *what is in
this build*; an advisory database answers *what is known about those names*. The
join of the two is a list of candidates, not a list of exposures — a crate can be
in `Cargo.lock` and in no compiled artefact at all. VEX is where the project
records that distinction once, with its reasoning, instead of leaving every
operator to rediscover it from the lockfile.

A statement here is a claim the project stands behind. It carries a
`justification` from the OpenVEX vocabulary and an `impact_statement` that spells
out the check anyone can repeat. **Never add a statement to silence a finding
that has not been shown to be inert.** If the reasoning would not survive being
read aloud in an incident review, the finding is real and the fix is a dependency
change, not a VEX entry.

## Current statements

- **`CVE-2023-49092` / `RUSTSEC-2023-0071`** (`rsa`, Marvin timing attack) —
  `not_affected`, `vulnerable_code_not_in_execute_path`. The crate arrives only
  as an optional dependency of `sqlx-mysql`, and the workspace takes sqlx with
  `default-features = false` and the `postgres` backend only. It is in the
  lockfile and in no build.
- **`RUSTSEC-2026-0285`** (`rustls`, TLS 1.3 encryption-level confusion) —
  `not_affected`, `component_not_present`. The shipped lockfile was never on the
  affected 0.23.44; `fuzz/Cargo.lock` was, and has been bumped.

## Using it

```sh
trivy image --vex security/vex/asterius.openvex.json "$IMAGE"
trivy sbom  --vex security/vex/asterius.openvex.json image.cdx.json
```

Matching is by package URL, so a statement only applies where the product `@id`
matches the artefact being scanned — `pkg:oci/…` for the image,
`pkg:cargo/asterius` for the binary SBOM from `cargo-cyclonedx`.

`cargo deny` and `cargo audit` do not read VEX. `cargo deny` needs no entry for
either statement above: it judges the resolved crate graph rather than the raw
lockfile, so it already reports `advisories ok`. That is a useful independent
confirmation of the `rsa` reasoning, not a duplicate of it.

## Maintaining it

Bump the top-level `version` on every change, and refresh `timestamp` on the
document and on each statement you touch. A statement whose premise has changed
— the dependency was dropped, or the feature that excluded it was enabled — is
removed, not edited into something weaker.
