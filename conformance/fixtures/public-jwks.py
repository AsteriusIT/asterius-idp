#!/usr/bin/env python3
"""Print the public half of a client's JWKS from the suite's plan configuration.

    public-jwks.py conformance/plans/fapi2-sp-final.json client

The plan configuration holds the private keys, because the suite signs its
client assertions and DPoP proofs with them. The `clients` table must hold the
matching public keys. Deriving one from the other here, at seed time, is what
makes it impossible for the two to drift apart — the alternative, a second
committed file with the public halves in it, is a thing to forget to update.

Exits non-zero, with a sentence, when the configuration does not have the shape
this harness expects: a silently empty JWKS would register a client nothing can
authenticate as, and every test in the plan would fail for that one reason.
"""

import json
import sys

# The private components of every key type a JWK can carry (RFC 7517 §4, RFC
# 7518 §6). Removed rather than allow-listed: a member this script has never
# heard of must not travel into the database, and an unknown *public* member is
# a smaller problem than an unknown private one.
PRIVATE_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 64

    config_path, client = argv[1], argv[2]
    with open(config_path, encoding="utf-8") as handle:
        config = json.load(handle)

    keys = config.get(client, {}).get("jwks", {}).get("keys")
    if not keys:
        print(
            f"{config_path}: '{client}' has no jwks.keys; the seeded client "
            "would have no key to authenticate with",
            file=sys.stderr,
        )
        return 65

    public = [{k: v for k, v in key.items() if k not in PRIVATE_MEMBERS} for key in keys]
    if any("d" in key for key in public):
        print("a private component survived the filter", file=sys.stderr)
        return 65

    json.dump({"keys": public}, sys.stdout, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
