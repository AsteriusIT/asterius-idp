#!/usr/bin/env python3
"""Turn a conformance run's `verdict.json` into a release decision.

    scripts/conformance-verdict.py                              check the waiver file alone
    scripts/conformance-verdict.py conformance/.run/results/verdict.json
    scripts/conformance-verdict.py <verdict.json> --max-age-hours 24

`conformance/runner/report.py` writes `verdict.json` inside the runner
container: one line per module, and nothing decided. This script is the
decision, and it lives on the host because a waiver names a beads ticket and
the container has never heard of beads.

The rule, from `ast-p2l.1`:

  * PASSED, REVIEW, WARNING and SKIPPED are green. "100 % pass" is not what this
    plan produces and pretending otherwise would mean either lying or waiving
    forty modules: five REVIEW are the suite asking a human to look at a
    screenshot the harness already took, the WARNING is a registered claim the
    suite's list predates, and the SKIPPED is an algorithm ADR-0003 refuses to
    offer.
  * FAILED is red, and so is a module that finished with no verdict at all
    (UNKNOWN) — a module that judged nothing has not judged the server.
  * unless `conformance/waivers.json` names the module. A waiver is a decision
    to ship a known non-conformance, so it carries a ticket, and
    `crates/server/tests/conformance_plan.rs` fails the per-PR pipeline if that
    ticket is closed or unknown to beads. That check is deliberately in a place
    that runs on every pull request rather than here, where it would only be
    consulted at 3am.
  * a report older than `--max-age-hours` is not a report. The release gate
    passes 24: a tag says something about the tree it points at, and a verdict
    from last week says something about a different one.

Exit codes, distinct so that a workflow log says which of them happened:

    0   green
    72  the report describes no module
    73  the report or the waiver file cannot be read, or its schema is unknown
    74  a module failed and no waiver covers it
    75  the report is older than --max-age-hours
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys

# Results that need no waiver. UNKNOWN is deliberately absent: it is what
# `report.py` writes for a module the suite interrupted before any verdict
# existed, and "we never found out" is not a pass.
GREEN = {"PASSED", "REVIEW", "WARNING", "SKIPPED"}

KNOWN_SCHEMA = 1

EXIT_EMPTY = 72
EXIT_UNREADABLE = 73
EXIT_FAILED = 74
EXIT_STALE = 75

REQUIRED_WAIVER_FIELDS = ("module", "ticket", "reason", "recorded")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_WAIVERS = os.path.join(ROOT, "conformance", "waivers.json")


class Unreadable(Exception):
    """The input exists but is not something this script can act on."""


def load_waivers(path: str) -> dict[str, dict]:
    """The waiver file, keyed by module name, with its shape checked."""
    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except OSError as error:
        raise Unreadable(f"{path} cannot be read: {error}") from error
    except ValueError as error:
        raise Unreadable(f"{path} is not JSON: {error}") from error

    entries = document.get("waivers")
    if not isinstance(entries, list):
        raise Unreadable(f"{path} has no 'waivers' array")

    waivers: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise Unreadable(f"{path}: a waiver is not an object")
        missing = [field for field in REQUIRED_WAIVER_FIELDS if not entry.get(field)]
        if missing:
            raise Unreadable(
                f"{path}: the waiver {entry.get('module', '(unnamed)')!r} is missing "
                f"{', '.join(missing)}. A waiver without a ticket and a reason is a "
                "failure somebody decided to stop seeing."
            )
        module = str(entry["module"])
        if module in waivers:
            raise Unreadable(f"{path}: {module} is waived twice")
        waivers[module] = entry
    return waivers


def load_verdict(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except OSError as error:
        raise Unreadable(
            f"{path} cannot be read: {error}. A run that left no verdict is a run "
            "nothing can be concluded from."
        ) from error
    except ValueError as error:
        raise Unreadable(f"{path} is not JSON: {error}") from error
    schema = document.get("schema")
    if schema != KNOWN_SCHEMA:
        raise Unreadable(
            f"{path} declares schema {schema!r}, and this script knows {KNOWN_SCHEMA}. "
            "Reading it anyway would mean guessing at fields that may have moved."
        )
    return document


def age_hours(generated: str) -> float:
    stamp = generated.replace("Z", "+00:00")
    try:
        moment = datetime.datetime.fromisoformat(stamp)
    except ValueError as error:
        raise Unreadable(f"'generated' is not an ISO 8601 instant: {generated!r}") from error
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    return (now - moment).total_seconds() / 3600.0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "verdict",
        nargs="?",
        help="verdict.json from a run. Omitted: only the waiver file is checked.",
    )
    parser.add_argument("--waivers", default=DEFAULT_WAIVERS)
    parser.add_argument(
        "--max-age-hours",
        type=float,
        default=None,
        help="refuse a report older than this. The release gate passes 24.",
    )
    arguments = parser.parse_args(argv)

    try:
        waivers = load_waivers(arguments.waivers)
    except Unreadable as error:
        print(f"verdict: {error}", file=sys.stderr)
        return EXIT_UNREADABLE

    if arguments.verdict is None:
        print(f"{len(waivers)} waiver(s), all well-formed:")
        for module, waiver in sorted(waivers.items()):
            print(f"  {module}  ({waiver['ticket']}, recorded {waiver['recorded']})")
        return 0

    try:
        report = load_verdict(arguments.verdict)
        modules = report.get("modules") or []
        if not isinstance(modules, list):
            raise Unreadable("'modules' is not an array")
        age = age_hours(str(report.get("generated", "")))
    except Unreadable as error:
        print(f"verdict: {error}", file=sys.stderr)
        return EXIT_UNREADABLE

    print(f"report:   {arguments.verdict}")
    print(f"generated {report.get('generated')} ({age:.1f} h ago)")
    if report.get("revision"):
        print(f"revision  {report['revision']}")
    if report.get("plan"):
        print(f"plan      {report['plan']}")
    print(f"modules:  {len(modules)}")

    if not modules:
        print(
            "\nverdict: the report describes no module. A run that judged nothing "
            "cannot clear a release.",
            file=sys.stderr,
        )
        return EXIT_EMPTY

    unwaived: list[dict] = []
    waived: list[dict] = []
    for module in modules:
        result = str(module.get("result", "UNKNOWN"))
        if result in GREEN:
            continue
        name = str(module.get("module") or module.get("name") or "?")
        if name in waivers:
            waived.append({"name": name, "result": result, "waiver": waivers[name]})
        else:
            unwaived.append({"name": name, "result": result, "log": module.get("log", "")})

    if waived:
        print("\nwaived (a known non-conformance, with a ticket):")
        for entry in waived:
            waiver = entry["waiver"]
            print(f"  {entry['result']:8} {entry['name']}  -> {waiver['ticket']}")

    # Not fatal, and loud. A waiver whose module now passes is a workaround kept
    # past its cause, which is how the next regression gets hidden; but a
    # release blocked because something started working would be worse.
    stale = sorted(set(waivers) - {entry["name"] for entry in waived})
    if stale:
        print("\nwaivers that covered nothing in this run — remove them:")
        for module in stale:
            print(f"  {module}  ({waivers[module]['ticket']})")

    if unwaived:
        print("\nverdict: RED", file=sys.stderr)
        for entry in unwaived:
            print(f"  {entry['result']:8} {entry['name']}  {entry['log']}", file=sys.stderr)
        print(
            "\nEach of these is a module of the profile this server claims to implement, "
            "failing with nothing in conformance/waivers.json to say who is dealing with "
            "it. Fix it, or file a ticket and waive it deliberately.",
            file=sys.stderr,
        )
        return EXIT_FAILED

    if arguments.max_age_hours is not None and age > arguments.max_age_hours:
        print(
            f"\nverdict: the report is {age:.1f} h old, and this gate accepts "
            f"{arguments.max_age_hours:.0f} h. It describes a tree that is not the one "
            "being tagged. Run the conformance workflow against this revision.",
            file=sys.stderr,
        )
        return EXIT_STALE

    print("\nverdict: GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
