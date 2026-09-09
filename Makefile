# Entry points that are not `cargo`.
#
# Deliberately thin. Everything of substance lives in scripts/, so that what CI
# runs and what a developer runs are the same file rather than two descriptions
# of the same intent — see the note on `browser sweep` in .github/workflows/ci.yml.
# `cargo` is not wrapped here at all: CONTRIBUTING.md is where the build is
# documented, and a `make test` would be a second place to keep it current.

.PHONY: help conformance conformance-keep

help:
	@echo 'make conformance       run the OIDF conformance suite against a local build'
	@echo 'make conformance-keep  the same, leaving the stack up to inspect'
	@echo
	@echo 'Everything else is cargo; see CONTRIBUTING.md.'

# `ast-83p.8`. Brings up PostgreSQL, Asterius and the OpenID Foundation
# conformance suite, runs the FAPI 2.0 Security Profile Final plan headless and
# exits non-zero if it did not pass — or if it did not really run.
#
# No secret, no account, no network access to anything but the pinned suite
# images. Takes tens of minutes: it is not, and must not become, part of the
# per-PR pipeline. conformance/README.md has the detail.
conformance:
	./scripts/conformance.sh

conformance-keep:
	./scripts/conformance.sh --keep
