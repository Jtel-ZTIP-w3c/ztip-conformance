#!/usr/bin/env python3
"""ZTIP conformance — independent OFFER-FIRST CEREMONY verifier (primitive v6).

Second implementation: reads vectors/ceremony_v6.json and, for each case, runs the ceremony
state machine per SPEC.md sec.11 — stop at the first failing gate; bind ONLY at MATERIALIZE,
and only when not-expired AND accept AND validate. Green = the never-auto-bind invariant
interops. The whole point: an offer is a T-1 candidate until explicitly accepted and
validated; nothing binds by default.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, "..", "vectors", "ceremony_v6.json")
GREEN, RED, DIM, RST = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def ceremony(expired, accept, validate):
    if expired:
        return ("REQUEST", False)
    if not accept:
        return ("ACCEPT", False)
    if not validate:
        return ("VALIDATE", False)
    return ("MATERIALIZE", True)


def main():
    with open(VEC) as f:
        doc = json.load(f)
    print(f"ZTIP conformance — verifying {doc['primitive']} v{doc['version']}")

    all_ok = True
    for c in doc["cases"]:
        i = c["input"]
        stage, bound = ceremony(i["expired"], i["accept"], i["validate"])
        e = c["expect"]
        passed = stage == e["final_stage"] and bound == e["bound"]
        all_ok = all_ok and passed
        mark = f"{GREEN}PASS{RST}" if passed else f"{RED}FAIL{RST}"
        print(f"  [{mark}] {c['name']:14s} {DIM}-> {stage:12s} bound={str(bound).lower()} (expect {e['final_stage']}, bound {str(e['bound']).lower()}){RST}")

    print()
    if all_ok:
        print(f"{GREEN}YES IT PLAYS — never-auto-bind invariant holds; only MATERIALIZE binds.{RST}")
        return 0
    print(f"{RED}interop broken — ceremony state machine disagrees. Fix the spec.{RST}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
