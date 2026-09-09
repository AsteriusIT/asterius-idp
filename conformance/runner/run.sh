#!/bin/sh
# Runs one conformance plan, inside the runner container.
#
# Started by `scripts/conformance.sh`, never by hand: it expects the suite
# checkout at /suite, the plan configurations at /plans and somewhere to put
# results at /results, all of which the compose file mounts.
#
# The plan is driven by the suite's own `run-test-plan.py` rather than by
# anything of ours. That script is what the OpenID Foundation's own CI uses, it
# knows how to wait for a module, how to retry a flake and what an expected
# failure is — a reimplementation would be a second opinion on the very thing
# we brought this suite in to stop having opinions about.
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: run.sh '<plan-name>[variant=value]...'" >&2
  exit 64
fi
plan="$1"

# Pinned, for the reason everything else here is pinned: the suite's own
# scripts/requirements.txt names no versions, and a runner that installs
# whatever is newest is a harness that can break without a commit.
# `--user`, into PYTHONUSERBASE: this container runs as the caller's uid so
# that the reports it writes belong to the caller, and that uid owns nothing
# system-wide.
pip install --user --quiet --no-cache-dir -r /runner/requirements.txt \
  || { echo "runner: could not install the suite's python dependencies" >&2; exit 69; }

# `--export-dir`: one result archive per plan, which is what a certification
# submission is made of and what the nightly job publishes.
mkdir -p /results/export
exec python3 /suite/scripts/run-test-plan.py \
  --export-dir /results/export \
  --verbose \
  "$plan" /plans/fapi2-sp-final.json
