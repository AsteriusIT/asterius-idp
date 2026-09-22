# syntax=docker/dockerfile:1.7
#
# The release image for the `asterius` binary.
#
# Three properties are load-bearing and every choice below serves one of them.
#
# **No shell, no package manager, nothing but the binary.** The runtime stage is
# distroless: an attacker who reaches remote code execution finds no `sh`, no
# `curl`, no `apt`, and nothing to pivot with. That is also why the health probe
# is HTTP-level (compose, Kubernetes) rather than an `exec` probe — there is
# nothing in here to exec.
#
# **Non-root, read-only root filesystem.** The process needs no write access to
# anything it ships with: configuration and key material are mounted read-only,
# and everything else it needs lives in PostgreSQL. See the `read_only: true`
# and `cap_drop` settings in deploy/compose/docker-compose.yml.
#
# **The binary is statically linked against musl, so the image carries no libc
# package at all.** It used to be glibc-linked on `distroless/cc`, because the
# musl build of aws-lc-rs (ADR-0004) once needed a hand-assembled toolchain.
# It no longer does: Debian's `musl-tools` and a stock `rustup` target are
# enough, and `deploy/README.md` records the check that showed it. What that
# buys is that the image's only Debian packages are ca-certificates and tzdata:
# a glibc advisory — including the disputed, never-to-be-fixed kind such as
# CVE-2019-1010022 — has nothing here to be a finding against.

# --- console ---------------------------------------------------------------
# The admin console is embedded in the binary (ADR-0009: one binary and one
# PostgreSQL), so its bundle has to exist before cargo runs. Its own stage, so
# that Node never reaches the build stage and a change to a `.rs` file does not
# reinstall npm packages.
FROM node:22-trixie-slim AS console

WORKDIR /console
COPY console/package.json console/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY console/ ./
# The console references the shared, vendored fonts at build time.
COPY crates/web/assets/fonts/ /crates/web/assets/fonts/
RUN npm run build

# --- build -----------------------------------------------------------------
# The toolchain is pinned to the workspace's `rust-version`. Pin it by digest
# before cutting a release: a tag can be re-pointed, and a release build should
# be reproducible from the Dockerfile alone.
FROM rust:1.98-trixie AS build

# Set by BuildKit from `--platform`; `amd64` or `arm64` here.
ARG TARGETARCH

# aws-lc-rs builds its own C and assembly; cmake, clang and nasm-free bindgen
# are what it needs. `musl-tools` is the `musl-gcc` wrapper that compiles that
# C against musl instead of glibc. `--no-install-recommends` keeps the build
# stage honest even though nothing from it reaches the final image.
RUN apt-get update \
    && apt-get install --no-install-recommends --yes cmake clang musl-tools \
    && rm -rf /var/lib/apt/lists/*

# The Rust musl target for the architecture being built. Written to a file so
# that the build step below reads the same value rather than a second copy of
# this mapping.
RUN case "$TARGETARCH" in \
      amd64) echo x86_64-unknown-linux-musl ;; \
      arm64) echo aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac > /rust-target \
    && rustup target add "$(cat /rust-target)"

WORKDIR /src

# The query metadata checked into .sqlx: the build must not need a database.
ENV SQLX_OFFLINE=true

# Deterministic output: no incremental artefacts, no `$HOME` leaking into
# debug paths, and one codegen unit (set in the release profile).
ENV CARGO_INCREMENTAL=0

COPY . .
# After the sources, so it is not overwritten: `console/dist` is gitignored and
# therefore absent from the context. Without it `build.rs` embeds nothing and
# the console answers 503.
COPY --from=console /console/dist ./console/dist

# `CC_<target>` rather than a bare `CC`: it points the `cc` crate (and, through
# it, aws-lc-sys's cmake) at `musl-gcc` for code compiled *for the target*
# only. Build scripts and proc-macros still compile for the host with the host
# compiler. The variable name takes the target triple with `-` as `_`.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    T="$(cat /rust-target)" \
    && export "CC_$(printf '%s' "$T" | tr '-' '_')=musl-gcc" \
    && cargo build --release --locked --bin asterius --target "$T" \
    && cp "/src/target/$T/release/asterius" /asterius

# --- runtime ---------------------------------------------------------------
# `static`: the binary brings its own libc (see above), so the base contributes
# only the CA bundle, tzdata and the passwd entry. `nonroot` gives uid/gid 65532,
# so the process has an identity even with the root filesystem read-only.
FROM gcr.io/distroless/static-debian13:nonroot AS runtime

COPY --from=build /asterius /usr/local/bin/asterius

USER nonroot:nonroot
WORKDIR /
EXPOSE 9443

# Not a shell form: there is no shell. Configuration comes from the file the
# orchestrator mounts, overridden by ASTERIUS__* variables.
ENTRYPOINT ["/usr/local/bin/asterius"]
CMD ["--config", "/etc/asterius/asterius.toml"]

LABEL org.opencontainers.image.title="asterius" \
      org.opencontainers.image.description="FAPI 2.0 OpenID Provider" \
      org.opencontainers.image.source="https://github.com/AsteriusIT/asterius-idp" \
      org.opencontainers.image.licenses="Apache-2.0"
