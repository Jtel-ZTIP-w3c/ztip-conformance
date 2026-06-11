#!/usr/bin/env python3
"""ZTIP conformance — OFFER-FIRST CEREMONY test-vector generator (primitive v6).

An identity offer is NEVER auto-binding. It enters as a T-1 *candidate* and becomes a bound
T0 truth ONLY after: not expired (TTL) AND explicit local accept (consent) AND validation
(AINS/JIS/TIBET). Any earlier failure leaves it unbound — nothing materializes.

The stages: OFFER → REQUEST → ACCEPT → SEAL → VALIDATE → MATERIALIZE. `bound` stays false
through every stage and flips true ONLY at MATERIALIZE. v6 pins that invariant:

    bound := (not expired) AND accept AND validate
    and the ceremony stops at the first failing gate.

Mirrors OfferFirstCeremony.run() in :core. Pure logic — no crypto, no clock; the inputs are
the gate outcomes.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "vectors", "ceremony_v6.json")


def ceremony(expired, accept, validate):
    """Returns (final_stage, bound). Stops at the first failing gate."""
    if expired:
        return ("REQUEST", False)       # TTL refused before any consent
    if not accept:
        return ("ACCEPT", False)        # consent withheld -> candidate discarded
    if not validate:
        return ("VALIDATE", False)      # AINS/JIS/TIBET validation failed -> still a candidate
    return ("MATERIALIZE", True)        # T-1 candidate -> T0 truth (now, and only now, bound)


def main():
    inputs = [
        ("happy-path",   {"expired": False, "accept": True,  "validate": True}),
        ("expired",      {"expired": True,  "accept": True,  "validate": True}),
        ("no-consent",   {"expired": False, "accept": False, "validate": True}),
        ("validate-fail", {"expired": False, "accept": True,  "validate": False}),
    ]

    print("ZTIP conformance — offer-first ceremony v6")
    cases = []
    for name, inp in inputs:
        stage, bound = ceremony(inp["expired"], inp["accept"], inp["validate"])
        cases.append({"name": name, "input": inp,
                      "expect": {"final_stage": stage, "bound": bound}})
        print(f"  {'+' if bound else '-'} {name:14s} expired={str(inp['expired']).lower():5s} "
              f"accept={str(inp['accept']).lower():5s} validate={str(inp['validate']).lower():5s} "
              f"-> {stage:12s} bound={str(bound).lower()}")

    doc = {
        "primitive": "offer-first-ceremony",
        "version": 6,
        "stages": ["OFFER", "REQUEST", "ACCEPT", "SEAL", "VALIDATE", "MATERIALIZE"],
        "invariant": "bound is false at every stage and true ONLY at MATERIALIZE; bound := (not expired) AND accept AND validate. No auto-bind.",
        "cases": cases,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"  wrote {len(cases)} cases -> {os.path.relpath(OUT, os.path.join(HERE, '..'))}")


if __name__ == "__main__":
    main()
