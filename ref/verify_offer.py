#!/usr/bin/env python3
"""ZTIP conformance — onafhankelijke OFFER-VERIFIER (primitive v2).

Tweede implementatie. Leest vectors/offer_v2.json, en valideert elke offer-envelope:
  1. TTL: verify_at < expires_at      (de offer is nog vers)
  2. vinks_sig: Ed25519-verify over de ZELF-herberekende canonical(vinks)  (== v1)
     — of een identity-only offer (geen vinks, geen sig).

Resolve/key-match (vendor-onafhankelijk vinden van de pubkey via .aint) is v4, niet hier.
Groen op alle gevallen = een vreemde kan een hele offer valideren uit de spec alleen.
"""
import base64
import json
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, "..", "vectors", "offer_v2.json")
GREEN, RED, DIM, RST = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def vink_canonical(vinks):  # onafhankelijke her-impl van SPEC.md sec.2
    parts = []
    for v in sorted(vinks, key=lambda x: x["key"]):
        parts.append(f'{v["key"]}={1 if v["granted"] else 0}{"d" if v.get("demo") else ""}')
    return "|".join(parts)


def sig_ok(pub_b64, msg, sig_b64):
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(
            base64.b64decode(sig_b64), msg.encode("utf-8"))
        return True
    except InvalidSignature:
        return False


def offer_valid(offer, verify_at):
    if verify_at >= offer["expires_at"]:
        return False  # TTL verlopen
    vinks = offer.get("vinks") or []
    sig = offer.get("vinks_sig")
    if not vinks:
        return sig is None  # identity-only: geen claims, geen handtekening
    if sig is None:
        return False
    return sig_ok(offer["sender_pubkey"], vink_canonical(vinks), sig)


def main():
    with open(VEC) as f:
        doc = json.load(f)
    verify_at = doc["verify_at"]
    print(f"ZTIP conformance — verifying {doc['primitive']} v{doc['version']} (verify_at={verify_at})")

    all_ok = True
    for c in doc["cases"]:
        got = offer_valid(c["offer"], verify_at)
        passed = got == c["expect_valid"]
        all_ok = all_ok and passed
        mark = f"{GREEN}PASS{RST}" if passed else f"{RED}FAIL{RST}"
        print(f"  [{mark}] {c['name']:14s} {DIM}valid={str(got).lower()} (expect {str(c['expect_valid']).lower()}){RST}")

    print()
    if all_ok:
        print(f"{GREEN}YES IT PLAYS — full offers validate. Envelope interops, no vendor needed.{RST}")
        return 0
    print(f"{RED}interop broken — offer validation disagrees. Fix the spec.{RST}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
