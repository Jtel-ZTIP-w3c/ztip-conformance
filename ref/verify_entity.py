#!/usr/bin/env python3
"""ZTIP conformance — independent ENTITY-CLASS verifier (primitive v8).

Second implementation: reads vectors/entity_v8.json and accepts an actor's proof per SPEC.md
sec.13 — the proof_type must be the lane allowed for the entity_class, and the signature must
verify under the actor's key. The handshake is identical across human / AI / IoT; only the
vocabulary differs. Green = one resolver carries many actor classes, no vendor needed.
"""
import base64
import json
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, "..", "vectors", "entity_v8.json")
GREEN, RED, DIM, RST = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def canonical(entity_class, proof_type, nonce):
    return f"jis-proof:v1:{entity_class}:{proof_type}:{nonce}"


def sig_ok(pub_b64, msg, sig_b64):
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(
            base64.b64decode(sig_b64), msg.encode("utf-8"))
        return True
    except InvalidSignature:
        return False


def accept(actor, lanes):
    if lanes.get(actor["entity_class"]) != actor["proof_type"]:    # wrong vocabulary for this class
        return False
    msg = canonical(actor["entity_class"], actor["proof_type"], actor["nonce"])
    return sig_ok(actor["key"], msg, actor["proof"])               # same crypto for every class


def main():
    with open(VEC) as f:
        doc = json.load(f)
    lanes = doc["lanes"]
    print(f"ZTIP conformance — verifying {doc['primitive']} v{doc['version']}")

    all_ok = True
    for c in doc["cases"]:
        got = accept(c["actor"], lanes)
        passed = got == c["expect_accept"]
        all_ok = all_ok and passed
        mark = f"{GREEN}PASS{RST}" if passed else f"{RED}FAIL{RST}"
        print(f"  [{mark}] {c['name']:16s} {DIM}{c['actor']['entity_class']}/{c['actor']['proof_type']} accept={str(got).lower()} (expect {str(c['expect_accept']).lower()}){RST}")

    print()
    if all_ok:
        print(f"{GREEN}YES IT PLAYS — one resolver, many actors; same handshake, swapped vocabulary.{RST}")
        return 0
    print(f"{RED}interop broken — entity-class disagrees. Fix the spec.{RST}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
