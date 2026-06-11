#!/usr/bin/env python3
"""ZTIP conformance — FRESH-ASSURANCE test-vector generator (primitive v5).

Session VINKs (live_presence / rightful_holder) prove something true RIGHT NOW — a live
person, a face that matches the chip. They carry a short freshness window and are NEVER
persisted: a stored or replayed one is, by construction, stale. v5 pins the freshness gate.

A session VINK is honoured iff `verify_at < fresh_until`. Past that it must be re-proven; an
old one carries no weight — the anti-supercookie property in runtime form (matches the
SessionAttestation TTL in KIT/ID-Drop). Fixed verify_at -> deterministic.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "vectors", "fresh_v5.json")

VERIFY_AT = 1_750_000_000   # fixed reference clock (deterministic)
TTL = 120                   # the window a session attestation is minted with (seconds)


def session_vink(key, dt):
    """A session VINK whose freshness expires at verify_at + dt seconds."""
    return {"key": key, "ttl_seconds": TTL, "fresh_until": VERIFY_AT + dt}


def main():
    cases = [
        {"name": "fresh-live", "vink": session_vink("live_presence", +60),
         "expect_honored": True},
        {"name": "expired-live", "vink": session_vink("live_presence", -5),
         "expect_honored": False},
        {"name": "fresh-rightful", "vink": session_vink("rightful_holder", +30),
         "expect_honored": True},
        {"name": "replayed-rightful", "vink": session_vink("rightful_holder", -3600),
         "expect_honored": False},   # presented an hour late -> stale -> the supercookie defense
    ]

    print("ZTIP conformance — fresh-assurance v5")
    print(f"  verify_at : {VERIFY_AT}   (TTL minted: {TTL}s)")
    for c in cases:
        v = c["vink"]
        left = v["fresh_until"] - VERIFY_AT
        print(f"  {'+' if c['expect_honored'] else '-'} {c['name']:18s} {v['key']:16s} fresh_for={left:+5d}s honored={str(c['expect_honored']).lower()}")

    doc = {
        "primitive": "fresh-assurance",
        "version": 5,
        "verify_at": VERIFY_AT,
        "ttl_default_seconds": TTL,
        "rule": "honored := verify_at < fresh_until. Session VINKs are never persisted; a stored/replayed one is stale by construction.",
        "note": "Independent of the offer TTL (v2): even inside a still-valid offer, a session VINK only counts while fresh. Stale session VINKs drop; the document VINKs (18+/valid/NL) are unaffected.",
        "cases": cases,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"  wrote {len(cases)} cases -> {os.path.relpath(OUT, os.path.join(HERE, '..'))}")


if __name__ == "__main__":
    main()
