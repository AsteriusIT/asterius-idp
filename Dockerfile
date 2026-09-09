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
# **The binary is dynamically linked against glibc, not musl.** ADR-0004 puts
# the crypto on aws-lc-rs, whose musl story still means a hand-built toolchain,
# and a static build we cannot reproduce is worth less than a distroless one we
# can. `deploy/README.md` records this as a deliberate, revisitable choice.

# --- build -----------------------------------------------------------------
# The toolchain is pinned to the workspace's `rust-version`. Pin it by digest
# before cutting a release: a tag can be re-pointed, and a release build should
# be reproducible from the Dockerfile alone.
FROM rust:1.98-bookworm AS build

# aws-lc-rs builds its own C and assembly; cmake, clang and nasm-free bindgen
# are what it needs. `--no-install-recommends` keeps the build stage honest
# even though nothing from it reaches the final image.
RUN apt-get update \
    && apt-get install --no-install-recommends --yes cmake clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# The query metadata checked into .sqlx: the build must not need a database.
ENV SQLX_OFFLINE=true

# Deterministic output: no incremental artefacts, no `$HOME` leaking into
# debug paths, and one codegen unit (set in the release profile).
ENV CARGO_INCREMENTAL=0

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin asterius \
    && cp /src/target/release/asterius /asterius

# --- runtime ---------------------------------------------------------------
# `cc` rather than `static`: the binary is glibc-linked (see above). `nonroot`
# gives uid/gid 65532 and a passwd entry, so the process has an identity even
# with the root filesystem read-only.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

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
