#!/usr/bin/env python3
"""ZTIP conformance — independent FRESH-ASSURANCE verifier (primitive v5).

Second implementation: reads vectors/fresh_v5.json and, for each session VINK, applies the
freshness gate per SPEC.md sec.10 — honored iff verify_at < fresh_until. A stale (stored or
replayed) session VINK is rejected; only a freshly-proven one counts. Green = the
fresh-assurance gate interops, no vendor needed.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, "..", "vectors", "fresh_v5.json")
GREEN, RED, DIM, RST = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def honored(vink, verify_at):
    return verify_at < vink["fresh_until"]      # fresh-at-use; nothing persisted survives this


def main():
    with open(VEC) as f:
        doc = json.load(f)
    verify_at = doc["verify_at"]
    print(f"ZTIP conformance — verifying {doc['primitive']} v{doc['version']} (verify_at={verify_at})")

    all_ok = True
    for c in doc["cases"]:
        got = honored(c["vink"], verify_at)
        passed = got == c["expect_honored"]
        all_ok = all_ok and passed
        mark = f"{GREEN}PASS{RST}" if passed else f"{RED}FAIL{RST}"
        print(f"  [{mark}] {c['name']:18s} {DIM}{c['vink']['key']} honored={str(got).lower()} (expect {str(c['expect_honored']).lower()}){RST}")

    print()
    if all_ok:
        print(f"{GREEN}YES IT PLAYS — fresh-assurance gate interops; stale = rejected, no vendor needed.{RST}")
        return 0
    print(f"{RED}interop broken — freshness gate disagrees. Fix the spec.{RST}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
