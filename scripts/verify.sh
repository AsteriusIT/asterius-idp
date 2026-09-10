#!/usr/bin/env bash
# End-of-task verification: fmt, strict clippy, targeted tests.
#
#   ./scripts/verify.sh tenancy            # your scope, as a substring
#   ./scripts/verify.sh -p asterius-web    # or a package
#   ./scripts/verify.sh 'test(oidc)'       # or a nextest filterset
#
# Whatever scope you name, the whole-tree audits in `http::source_audit` are
# added to the filter. They scan every source file in the workspace, but they
# live in one crate, so a worker who filters on their own crate never runs them
# and the violation only surfaces in CI on main -- after the merge (ast-0z6).
set -euo pipefail
cd "$(dirname "$0")/.."

# The whole-tree audits: redirect status codes, SEE_OTHER confinement, Cookie
# header reads, absence of CORS (asterius-server), template and CSP rules
# (asterius-web), secret handling (asterius-domain). They belong to no single
# scope, and the pattern picks up any audit module a crate adds later.
AUDIT_FILTER='test(/(^|::)(source_audit|secret_audit)::/)'

# Turn the arguments a worker naturally types into one nextest filterset.
# Substrings become test(~sub); -p/--package becomes package(name); anything
# already shaped like a filterset is passed through. The pieces are ORed, then
# the audits are ORed on top, so no scope can drop them.
build_filter() {
  local parts=() arg
  while (($#)); do
    arg=$1
    shift
    case $arg in
      -p | --package)
        [[ $# -gt 0 ]] || {
          echo "verify: $arg needs a package name" >&2
          return 2
        }
        parts+=("package($1)")
        shift
        ;;
      -p=* | --package=*) parts+=("package(${arg#*=})") ;;
      # Already a filterset: a predicate call, a set operation or a negation.
      *'('*')'* | 'not '* | *' and '* | *' or '*) parts+=("($arg)") ;;
      '') ;;
      -*)
        echo "verify: unsupported flag '$arg'; pass a substring or a filterset" >&2
        return 2
        ;;
      *) parts+=("test(~$arg)") ;;
    esac
  done

  if ((${#parts[@]} == 0)); then
    # No scope named: still a well-formed expression, and still the audits.
    printf '%s\n' "$AUDIT_FILTER"
    return 0
  fi

  local user
  user=$(
    IFS='|'
    echo "${parts[*]}"
  )
  user=${user//|/ or }
  printf '(%s) or (%s)\n' "$user" "$AUDIT_FILTER"
}

self_test() {
  local got want failures=0
  check() {
    want=$1
    shift
    got=$(build_filter "$@")
    if [[ $got == "$want" ]]; then
      echo "ok   [$*] -> $got"
    else
      echo "FAIL [$*]"
      echo "  want: $want"
      echo "  got:  $got"
      failures=$((failures + 1))
    fi
  }

  check "$AUDIT_FILTER"
  check "(test(~tenancy)) or ($AUDIT_FILTER)" tenancy
  check "(package(asterius-web)) or ($AUDIT_FILTER)" -p asterius-web
  check "(package(asterius-web)) or ($AUDIT_FILTER)" --package=asterius-web
  check "(test(~a) or test(~b)) or ($AUDIT_FILTER)" a b
  check "((test(oidc))) or ($AUDIT_FILTER)" 'test(oidc)'

  # A wrong flag must stop the run, not be silently folded into the filter.
  if build_filter --jobs 4 >/dev/null 2>&1; then
    echo "FAIL [--jobs 4] should be rejected"
    failures=$((failures + 1))
  else
    echo "ok   [--jobs 4] rejected"
  fi

  # And the expressions must parse. nextest resolves the filterset before it
  # asks cargo to build, so an undefined cargo profile stops the run right
  # after that point: reaching the profile error proves the filterset parsed,
  # and costs no compilation.
  local expr out
  for expr in "$(build_filter)" "$(build_filter tenancy)" "$(build_filter -p asterius-web x)"; do
    out=$(SQLX_OFFLINE=true cargo nextest list -E "$expr" \
      --cargo-profile nextest-filterset-parse-check-only 2>&1 || true)
    if [[ $out == *nextest-filterset-parse-check-only* ]]; then
      echo "ok   parses: $expr"
    else
      echo "FAIL does not parse: $expr"
      printf '%s\n' "$out" | sed 's/^/  /' | head -8
      failures=$((failures + 1))
    fi
  done

  ((failures == 0)) || return 1
  echo "verify: self-test passed"
}

case ${1:-} in
  --self-test)
    self_test
    exit
    ;;
  --print-filter)
    shift
    build_filter "$@"
    exit
    ;;
esac

filter=$(build_filter "$@")

run() { printf '\n\033[1m==> %s\033[0m\n' "$*"; "$@"; }

run cargo fmt --all
SQLX_OFFLINE=true run cargo clippy --all-targets -- -D warnings
printf '\n\033[1m==> cargo nextest run -E %s\033[0m\n' "'$filter'"
SQLX_OFFLINE=true cargo nextest run -E "$filter"
