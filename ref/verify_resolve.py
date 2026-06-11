#!/usr/bin/env python3
"""ZTIP conformance — independent AINS RESOLVE + KEY-MATCH verifier (primitive v4).

Second implementation: reads vectors/resolve_v4.json and, for each offer, binds it against
the recorded resolve fixture per SPEC.md sec.9 — the name must resolve, be active, and its
public key must equal the offer's sender_pubkey (same encoding). Green = the name→key
binding interops, no vendor and no live network needed.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, "..", "vectors", "resolve_v4.json")
GREEN, RED, DIM, RST = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def bound(offer, fixture):
    rec = fixture.get(offer["claimed_aint"])
    if rec is None:                                   # unresolvable -> stays unbound (T-1)
        return False
    if rec.get("status") != "active":                # revoked / suspended
        return False
    return rec.get("public_key") == offer["sender_pubkey"]   # key-match (same encoding!)


def main():
    with open(VEC) as f:
        doc = json.load(f)
    fixture = doc["resolve_fixture"]
    print(f"ZTIP conformance — verifying {doc['primitive']} v{doc['version']}")

    all_ok = True
    for c in doc["cases"]:
        got = bound(c["offer"], fixture)
        passed = got == c["expect_bound"]
        all_ok = all_ok and passed
        mark = f"{GREEN}PASS{RST}" if passed else f"{RED}FAIL{RST}"
        print(f"  [{mark}] {c['name']:16s} {DIM}bound={str(got).lower()} (expect {str(c['expect_bound']).lower()}){RST}")

    print()
    if all_ok:
        print(f"{GREEN}YES IT PLAYS — name→key binding interops, no vendor needed.{RST}")
        return 0
    print(f"{RED}interop broken — resolve/key-match disagrees. Check the encoding (sec.4).{RST}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
