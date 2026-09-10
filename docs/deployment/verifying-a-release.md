# Verifying a release

Before an image reaches a deployment, two questions are worth answering with a
command rather than with trust:

1. **Did this image come out of this repository?** — the cosign signature.
2. **What is inside it?** — the SBOM.

Both are produced by [`.github/workflows/release.yml`](../../.github/workflows/release.yml)
on every `v*` tag, and both are checkable from the outside with no credential.

> **Status.** The workflow is written and lints clean under `actionlint`, and
> its SBOM step was run against this tree by hand. **It has not yet run on a
> tag** — there is no released version — so the commands below are the ones the
> workflow's own steps produce, not commands anyone has yet run against a real
> release. The first tag is the thing that proves this page. Until then, treat
> a failure here as possibly a bug in this page.

---

## 1. What a tag publishes

| Artefact | Where | Covers |
| --- | --- | --- |
| The image | `ghcr.io/asteriusit/asterius-idp:<tag>` and `@<digest>` | — |
| Signature | The registry, alongside the image | The **digest** |
| Image SBOM (CycloneDX) | cosign attestation on the image, *and* a release asset | Rust crates + the distroless base's Debian packages |
| Binary SBOM (CycloneDX) | Release asset | The Rust dependency graph of the `asterius` binary |
| `checksums.txt` | Release asset | The two SBOM files |

**Always pull by digest.** A tag is a name and a name can be re-pointed; the
signature is over the digest and nothing else. The release notes carry the
digest, and so does `docker inspect` once you have pulled.

You need [`cosign`](https://docs.sigstore.dev/cosign/installation/). Nothing
here needs a key: the release is signed **keyless**, so there is no public key
to distribute and no private key in the repository's secrets to leak. What you
check instead is the *identity* recorded in the short-lived certificate.

---

## 2. Verify the signature

```sh
IMAGE=ghcr.io/asteriusit/asterius-idp
TAG=v1.2.3
DIGEST=$(crane digest "$IMAGE:$TAG")   # or take it from the release notes

cosign verify \
  --certificate-identity "https://github.com/AsteriusIT/asterius-idp/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$IMAGE@$DIGEST"
```

Both `--certificate-*` flags are load-bearing and neither is optional:

- **`--certificate-identity`** is the workflow that signed, pinned to the tag.
  Without it any signature from any GitHub Actions workflow anywhere would
  satisfy the check — including one from a fork.
- **`--certificate-oidc-issuer`** is the identity provider that vouched for it.
  Without it, an identity string of the same shape from another issuer passes.

If you are verifying several tags in a script, relax the first flag to a regexp
rather than dropping it:

```sh
  --certificate-identity-regexp '^https://github\.com/AsteriusIT/asterius-idp/\.github/workflows/release\.yml@refs/tags/v'
```

A pass prints the certificate's subject and the Rekor transparency-log entry.
**A failure is a refusal to deploy**, not something to work around with
`--insecure-ignore-tlog`.

---

## 3. Read the bill of materials

### From the image, as a signed attestation

This is the copy that travels with the image, so it is the one to prefer: it
cannot be swapped out without breaking the signature.

```sh
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity "https://github.com/AsteriusIT/asterius-idp/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$IMAGE@$DIGEST" \
  | jq -r '.payload | @base64d | fromjson | .predicate' >image.cdx.json
```

Then, for the usual question — *is this affected by the advisory I just read?*

```sh
jq -r '.components[] | "\(.name) \(.version)"' image.cdx.json | sort | grep -i openssl
```

Or feed `image.cdx.json` to whatever consumes CycloneDX in your organisation
(`grype sbom:image.cdx.json`, Dependency-Track, trivy).

### From the release assets

The same document, plus one for the binary alone, attached to the GitHub
release:

```sh
gh release download "$TAG" --repo AsteriusIT/asterius-idp \
  --pattern '*.cdx.json' --pattern 'checksums.txt'
sha256sum --check checksums.txt
```

- `asterius-<tag>-binary.cdx.json` — the Rust dependency graph, from
  `cargo-cyclonedx` over the same `Cargo.lock` that `deny.toml` and the
  [supply-chain audit workflow](../../.github/workflows/audit.yml) judge. Use
  this one to answer "which crates are in this build".
- `asterius-<tag>-image.cdx.json` — that, plus glibc and the rest of the
  distroless base. Use this one to answer "is this *image* affected".

The two differ on purpose: the binary is not the image. A glibc advisory
appears only in the second, and no amount of reading `Cargo.lock` would have
found it.

---

## 4. Where each guarantee comes from

- **The tag was allowed to exist.** `release.yml` starts with `needs: gate`,
  which is [`release-gate.yml`](../../.github/workflows/release-gate.yml) called
  as a reusable workflow: no image is built unless a conformance run less than
  24 hours old was green under the waiver list in the tagged tree. See
  [`../certification.md`](../certification.md).
- **The signature names a workflow, not a person.** Keyless signing puts the
  repository, the workflow file and the ref into a certificate that lives for
  minutes, and records the signature in Rekor. There is no long-lived key, so
  there is nothing to steal and nothing to rotate.
- **The SBOM cannot be quietly replaced.** `cosign attest` signs the predicate
  with the same identity, so `verify-attestation` fails on a swapped document.
  The release asset is a convenience copy; when they disagree, the attestation
  is the one that counts.

---

## 5. What this does *not* prove

- **Not reproducibility.** Nobody can rebuild this image bit-for-bit today and
  get the same digest: the `Dockerfile` pins `rust:1.98-bookworm` by tag rather
  than by digest (it says so, and says to pin before cutting a release), and
  the apt layer resolves at build time. The signature proves *this repository
  built it*, not *you could build it again*.
- **Not that the SBOM is complete.** It lists what `cargo-cyclonedx` reads from
  `Cargo.lock` and what `syft` recognises in the image layers. Anything vendored
  or generated at build time that neither tool can see is absent from both.
- **Not that the dependencies are sound.** That is
  [`audit.yml`](../../.github/workflows/audit.yml), on a schedule, against
  advisory-db. An SBOM tells you what to look up; it does not do the looking.

---

Related: [`../runbooks/upgrade.md`](../runbooks/upgrade.md) (verify *before*
rolling), [`../../deploy/README.md`](../../deploy/README.md),
[`../threat-model.md`](../threat-model.md).
