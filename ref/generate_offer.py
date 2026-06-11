#!/usr/bin/env python3
"""ZTIP conformance — OFFER-ENVELOPE test-vector generator (primitive v2).

A signed VINK set never travels alone; it rides inside an *offer*. v2 pins the envelope
(the IdDropOffer wire-format) so a second implementation can validate a whole offer:
parse it, check the TTL, and verify the embedded vinks_sig over canonical(vinks) — which
IS v1. So v2 composes directly on v1.

Validity at v2 = (not expired at verify_at) AND (vinks_sig valid over canonical(vinks),
or an identity-only offer with no vinks and no sig). Name→key resolution is v4, not here.

Same fixed seed as v1 -> deterministic, reproducible. A FIXED verify_at is baked into the
vectors so "fresh" vs "expired" is deterministic (not wall-clock).
"""
import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "vectors", "offer_v2.json")

SEED = hashlib.sha256(b"ztip-conformance/vink-attestation/v1").digest()  # zelfde sleutel als v1
VERIFY_AT = 1_750_000_000  # vaste referentietijd voor TTL-checks (deterministisch)


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def vink_canonical(vinks):  # spiegelt SPEC.md sec.2 (== v1)
    parts = []
    for v in sorted(vinks, key=lambda x: x["key"]):
        parts.append(f'{v["key"]}={1 if v["granted"] else 0}{"d" if v.get("demo") else ""}')
    return "|".join(parts)


def main():
    sk = Ed25519PrivateKey.from_private_bytes(SEED)
    pub_b64 = b64(sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    def sign_vinks(vinks):
        return b64(sk.sign(vink_canonical(vinks).encode("utf-8"))) if vinks else None

    adult = [
        {"key": "age_18", "granted": True, "demo": False},
        {"key": "valid_document", "granted": True, "demo": False},
        {"key": "nationality_nld", "granted": True, "demo": False},
    ]
    other = [{"key": "age_18", "granted": False, "demo": False}]  # voor de tamper-case

    def offer(offer_id, ttl, vinks, sig=None):
        return {
            "offer_id": offer_id,
            "expires_at": VERIFY_AT + ttl,
            "sender_pubkey": pub_b64,
            "claimed_aint": "vandemeent.aint",
            "claim_class": "age_over_18",
            "semantic_type": "identity",
            "entity_class": "human",
            "vinks": vinks,
            "vinks_sig": sig if sig is not None else sign_vinks(vinks),
        }

    cases = [
        {"name": "fresh-valid", "offer": offer("ofr-aaaa1111", +30, adult),
         "expect_valid": True},
        {"name": "expired-ttl", "offer": offer("ofr-bbbb2222", -10, adult),
         "expect_valid": False},
        {"name": "tampered-sig", "offer": offer("ofr-cccc3333", +30, adult, sig=sign_vinks(other)),
         "expect_valid": False},  # fresh, maar sig hoort bij een ANDERE vink-set
        {"name": "identity-only", "offer": offer("ofr-dddd4444", +30, []),
         "expect_valid": True},   # geen vinks, geen sig = geldige identity-only offer
    ]

    print("ZTIP conformance — offer envelope v2")
    print(f"  public key : {pub_b64}")
    print(f"  verify_at  : {VERIFY_AT}")
    for c in cases:
        o = c["offer"]
        dt = o["expires_at"] - VERIFY_AT
        print(f"  {'+' if c['expect_valid'] else '-'} {c['name']:14s} ttl={dt:+4d}s vinks={len(o['vinks'])} expect_valid={str(c['expect_valid']).lower()}")

    doc = {
        "primitive": "offer-envelope",
        "version": 2,
        "composes_on": "vink-attestation v1 (vinks_sig is an Ed25519 signature over canonical(vinks))",
        "verify_at": VERIFY_AT,
        "validity_rule": "not expired (verify_at < expires_at) AND (vinks empty & sig null  OR  sig verifies over canonical(vinks))",
        "public_key_b64": pub_b64,
        "cases": cases,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"  wrote {len(cases)} cases -> {os.path.relpath(OUT, os.path.join(HERE, '..'))}")


if __name__ == "__main__":
    main()
