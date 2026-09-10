#!/usr/bin/env python3
"""Read the conformance run's results back out of the suite, and gate on them.

Run by `scripts/conformance.sh` after `run-test-plan.py`, inside the runner
container, against the suite's own API. Standard library only: it must be able
to report that the run produced nothing even when nothing else worked.

It exists because of the failure mode this whole harness was written to avoid.
`run-test-plan.py` exits 0 when every module it ran passed — including when it
ran none, which is what a plan name with a typo, a suite that lost its database
or a variant combination with no modules in it all look like. A green pipeline
that tested nothing is worse than a red one, so:

  * zero plans, or zero executed modules, is a failure;
  * a run in which *no* module reached FINISHED is a failure, because nothing in
    it judged anything. One module that stopped early is not: the suite
    interrupts a test on purpose when a failed condition makes the rest of it
    meaningless, and that is a finding, which `run-test-plan.py`'s own exit code
    already reports;
  * a status or a result this script does not recognise is a failure, because
    an unrecognised value means the report format changed under us and the
    counts below are no longer counting what they say they are.

It also writes the HTML report per plan into /results, which is what the
nightly job publishes, and `verdict.json` beside it: one line per module, in a
shape that outlives the container. Applying the waivers to that file, and
deciding whether a release may be tagged on the strength of it, is
`scripts/conformance-verdict.py` — deliberately not here. This script runs
inside the runner container, which has the suite's API and nothing else; the
waivers name beads tickets, and whether a ticket is open is a question only the
repository can answer.
"""

import datetime
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

# Bumped when the shape of `verdict.json` changes in a way a reader has to know
# about. `scripts/conformance-verdict.py` refuses a version it does not know
# rather than reading fields that may have moved.
VERDICT_SCHEMA = 1

# TestModule.Status and TestModule.Result, from the suite's own source at the
# pinned release. A value outside these sets is a format change, not a result.
KNOWN_STATUSES = {
    "NOT_YET_CREATED",
    "CREATED",
    "CONFIGURED",
    "RUNNING",
    "WAITING",
    "INTERRUPTED",
    "FINISHED",
}
KNOWN_RESULTS = {"PASSED", "FAILED", "WARNING", "REVIEW", "SKIPPED", "UNKNOWN"}

# Results that mean a human has to look. Not a failure of *this* gate — the
# runner already decides pass and fail — but counted and printed, because
# "everything passed" and "everything was skipped" must not read the same.
NEEDS_ATTENTION = {"FAILED", "REVIEW", "WARNING", "SKIPPED", "UNKNOWN"}

EXIT_UNREACHABLE = 71
EXIT_EMPTY = 72
EXIT_UNKNOWN_FORMAT = 73


# The suite's ingress presents a certificate it generated for itself, on a
# private compose network that nothing outside the project can reach. Verifying
# it would mean teaching this container a certificate to prove nothing: the
# transport under test in this run is Asterius's, and that one *is* verified —
# by the suite, through the truststore scripts/conformance.sh builds for it.
# `run-test-plan.py` does the same thing under CONFORMANCE_DEV_MODE.
UNVERIFIED = ssl._create_unverified_context()  # noqa: SLF001


def api(base: str, path: str) -> object:
    with urllib.request.urlopen(base + path, timeout=60, context=UNVERIFIED) as response:
        return json.load(response)


def download(base: str, path: str, destination: str) -> None:
    with urllib.request.urlopen(base + path, timeout=300, context=UNVERIFIED) as response:
        with open(destination, "wb") as handle:
            while chunk := response.read(65536):
                handle.write(chunk)


def plan_list(payload: object) -> list:
    """The plan listing, whichever envelope the suite wrapped it in."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("data", "content", "results"):
            if isinstance(payload.get(key), list):
                return payload[key]
    raise TypeError(f"unrecognised plan listing: {type(payload).__name__}")


def plan_id(plan: dict) -> str:
    for key in ("_id", "id", "planId"):
        if plan.get(key):
            return str(plan[key])
    raise KeyError("a plan in the listing has no id")


def main() -> int:
    base = os.environ.get("CONFORMANCE_SERVER", "")
    if not base:
        print("report: CONFORMANCE_SERVER is not set", file=sys.stderr)
        return EXIT_UNREACHABLE
    if not base.endswith("/"):
        base += "/"
    results_dir = os.environ.get("CONFORMANCE_RESULTS", "/results")
    os.makedirs(results_dir, exist_ok=True)

    try:
        plans = plan_list(api(base, "api/plan?length=100"))
    except (urllib.error.URLError, ssl.SSLError, TimeoutError) as error:
        print(f"report: the suite API at {base} did not answer: {error}", file=sys.stderr)
        return EXIT_UNREACHABLE
    except (TypeError, ValueError) as error:
        print(f"report: the suite's plan listing is not readable: {error}", file=sys.stderr)
        return EXIT_UNKNOWN_FORMAT

    if not plans:
        print("report: the suite holds no test plan, so nothing was run", file=sys.stderr)
        return EXIT_EMPTY

    # Only this run's plans. The suite keeps every plan it has ever been given,
    # and `make conformance-keep` followed by a second run leaves two — counting
    # both would report a module as passing on the strength of a run that
    # happened before the change under test. `started` is ISO 8601 and UTC on
    # both sides, so a string comparison is the right one.
    since = os.environ.get("CONFORMANCE_SINCE", "")
    if since:
        plans = [plan for plan in plans if str(plan.get("started", "")) >= since]
        if not plans:
            print(
                f"report: the suite holds no test plan started at or after {since}, "
                "so this run created none",
                file=sys.stderr,
            )
            return EXIT_EMPTY

    total = 0
    attention: list[str] = []
    counts: dict[str, int] = {}
    unfinished: list[str] = []
    verdict: dict[str, object] = {
        "schema": VERDICT_SCHEMA,
        # UTC and second-resolution, because the release gate compares it with
        # `now` to decide whether the report is stale.
        "generated": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "since": os.environ.get("CONFORMANCE_SINCE", ""),
        "plan": os.environ.get("CONFORMANCE_PLAN", ""),
        "revision": os.environ.get("CONFORMANCE_REVISION", ""),
        "plans": [],
        "modules": [],
        "counts": counts,
    }
    verdict_plans: list[dict[str, str]] = verdict["plans"]  # type: ignore[assignment]
    verdict_modules: list[dict[str, str]] = verdict["modules"]  # type: ignore[assignment]

    for plan in plans:
        identifier = plan_id(plan)
        verdict_plans.append(
            {
                "id": identifier,
                "name": str(plan.get("planName", "")),
                "started": str(plan.get("started", "")),
            }
        )
        print(f"\nplan {identifier}: {plan.get('planName', '(unnamed)')}")
        for module in plan.get("modules", []):
            for instance in module.get("instances", []) or []:
                info = api(base, f"api/info/{instance}")
                status = info.get("status", "")
                # `or`, not a default: the suite writes a null result for a
                # module it interrupted before any verdict existed, and a null
                # is "we do not know yet" rather than a format we cannot read.
                result = info.get("result") or "UNKNOWN"
                name = info.get("testName", module.get("testModule", "?"))
                if status not in KNOWN_STATUSES or result not in KNOWN_RESULTS:
                    print(
                        f"report: {name} reports status {status!r} result {result!r}, "
                        "which this gate does not recognise; the suite's report "
                        "format has changed and these counts cannot be trusted",
                        file=sys.stderr,
                    )
                    return EXIT_UNKNOWN_FORMAT
                total += 1
                counts[result] = counts.get(result, 0) + 1
                verdict_modules.append(
                    {
                        "module": str(module.get("testModule", name)),
                        "name": str(name),
                        "result": result,
                        "status": status,
                        "log": f"{base}log-detail.html?log={instance}",
                    }
                )
                if status != "FINISHED":
                    unfinished.append(f"{name} ({status})")
                if result in NEEDS_ATTENTION:
                    attention.append(f"{result:8} {name}  {base}log-detail.html?log={instance}")
                print(f"  {result:8} {status:10} {name}")

        destination = os.path.join(results_dir, f"report-{identifier}.zip")
        try:
            download(base, f"api/plan/exporthtml/{identifier}", destination)
            print(f"  html report: {destination}")
        except (urllib.error.URLError, ssl.SSLError, TimeoutError) as error:
            # Not fatal on its own: the results above were read successfully, and
            # a missing archive must not be reported as a missing run.
            print(f"  could not export the html report: {error}", file=sys.stderr)

    # Written before the gates below, and whatever they decide: a run that
    # executed nothing is exactly the run whose verdict file somebody needs to
    # see, and a release gate that finds no file at all cannot tell "the report
    # is missing" from "the report is empty".
    verdict["modules"] = sorted(verdict_modules, key=lambda entry: entry["name"])
    verdict_path = os.path.join(results_dir, "verdict.json")
    with open(verdict_path, "w", encoding="utf-8") as handle:
        json.dump(verdict, handle, indent=2, sort_keys=False)
        handle.write("\n")
    print(f"\nverdict: {verdict_path}")

    print("\n--- summary -------------------------------------------------")
    print(f"plans:   {len(plans)}")
    print(f"modules: {total}")
    for result in sorted(counts):
        print(f"  {result:8} {counts[result]}")

    if total == 0:
        print(
            "\nreport: the plan ran zero test modules. A harness that runs "
            "nothing cannot be green; check the plan name and its variants.",
            file=sys.stderr,
        )
        return EXIT_EMPTY

    if len(unfinished) == total:
        print(
            "\nreport: not one module reached FINISHED. Nothing in this run "
            "judged anything; the server or the harness is broken rather than "
            "non-conformant.",
            file=sys.stderr,
        )
        for line in unfinished:
            print(f"  {line}", file=sys.stderr)
        return EXIT_EMPTY

    if unfinished:
        # Printed, not fatal here: an interrupted module is how the suite says
        # "a condition failed and the rest of this test would prove nothing".
        print("\nmodules that stopped before the end:")
        for line in unfinished:
            print(f"  {line}")

    if attention:
        print("\nresults needing attention:")
        for line in attention:
            print(f"  {line}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
