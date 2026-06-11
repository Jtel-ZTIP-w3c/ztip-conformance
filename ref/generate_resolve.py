#!/usr/bin/env python3
"""ZTIP conformance — AINS RESOLVE + KEY-MATCH test-vector generator (primitive v4).

An offer claims a `.aint`. v4 is the name→key binding: resolve the `.aint` over AINS to a
public key + status, and check `resolved.public_key == offer.sender_pubkey`. Only then may
the offer bind to that identity. A signature alone proves a key; the resolve proves the key
belongs to the claimed name.

Deterministic + OFFLINE: the resolve responses are a FIXED fixture (recorded), not a live
call. Keys are derived from fixed seeds (Ed25519, deterministic), reusing the v1 key.

CRITICAL interop point: the resolve record's `public_key` MUST be in the SAME encoding as the
offer's `sender_pubkey` (base64, SPEC sec.4). Mixing hex and base64 is the #1 key-match
breaker — the match is a direct string compare.
"""
import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "vectors", "resolve_v4.json")


def pub_b64(seed_phrase):
    seed = hashlib.sha256(seed_phrase).digest()
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    raw = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def main():
    OUR = pub_b64(b"ztip-conformance/vink-attestation/v1")  # the v1 / v2 identity key
    IMP = pub_b64(b"ztip-conformance/imposter-key")         # a different, valid Ed25519 key

    # Recorded AINS resolve responses (the offline fixture). Shape mirrors
    # GET /api/ains/resolve/<name> -> { record: { public_key, status, entity_type } }.
    fixture = {
        "vandemeent.aint": {"public_key": OUR, "status": "active", "entity_type": "idd"},
        "imposter.aint":   {"public_key": IMP, "status": "active", "entity_type": "idd"},
        "retired.aint":    {"public_key": OUR, "status": "revoked", "entity_type": "idd"},
        # "ghost.aint" is intentionally ABSENT -> unresolvable
    }

    def offer(aint, pub):
        return {"claimed_aint": aint, "sender_pubkey": pub}

    cases = [
        {"name": "key-match-active", "offer": offer("vandemeent.aint", OUR), "expect_bound": True},
        {"name": "key-mismatch",     "offer": offer("imposter.aint", OUR),  "expect_bound": False},
        {"name": "revoked",          "offer": offer("retired.aint", OUR),   "expect_bound": False},
        {"name": "unresolvable",     "offer": offer("ghost.aint", OUR),     "expect_bound": False},
    ]

    print("ZTIP conformance — AINS resolve + key-match v4")
    print(f"  our key : {OUR}")
    print(f"  imp key : {IMP}")
    for c in cases:
        o = c["offer"]
        rec = fixture.get(o["claimed_aint"])
        st = rec["status"] if rec else "—(absent)"
        print(f"  {'+' if c['expect_bound'] else '-'} {c['name']:16s} {o['claimed_aint']:16s} status={st:14s} bound={str(c['expect_bound']).lower()}")

    doc = {
        "primitive": "ains-resolve-keymatch",
        "version": 4,
        "binding_rule": "bound := resolve(claimed_aint) exists AND status=='active' AND record.public_key == offer.sender_pubkey",
        "encoding_note": "record.public_key and offer.sender_pubkey MUST share one encoding (base64, SPEC sec.4); hex vs base64 is the #1 key-match breaker.",
        "resolve_fixture": fixture,
        "cases": cases,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"  wrote {len(cases)} cases -> {os.path.relpath(OUT, os.path.join(HERE, '..'))}")


if __name__ == "__main__":
    main()
