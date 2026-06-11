#!/usr/bin/env python3
"""ZTIP conformance — independent CHALLENGE-RESPONSE verifier (primitive v7).

Second implementation: reads vectors/challenge_v7.json and, for each response, applies the
JIS root handshake per SPEC.md sec.12 — verify the Ed25519 signature over the canonical of
the challenge IT expects, and require the challenge to still be fresh. A replayed/old or
wrong-key response fails. Green = the M2M handshake interops, no vendor needed.
"""
import base64
import json
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, "..", "vectors", "challenge_v7.json")
GREEN, RED, DIM, RST = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def canonical(ch):
    return f"jis-challenge:v1:{ch['agent_id']}:{ch['nonce']}:{ch['issued_at']}"


def sig_ok(pub_b64, msg, sig_b64):
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(
            base64.b64decode(sig_b64), msg.encode("utf-8"))
        return True
    except InvalidSignature:
        return False


def accept(ch, sig_b64, pubkey, verify_at):
    if not sig_ok(pubkey, canonical(ch), sig_b64):              # wrong key / replay of a different challenge
        return False
    if verify_at >= ch["issued_at"] + ch["ttl_seconds"]:        # stale
        return False
    return True


def main():
    with open(VEC) as f:
        doc = json.load(f)
    verify_at = doc["verify_at"]
    print(f"ZTIP conformance — verifying {doc['primitive']} v{doc['version']} (verify_at={verify_at})")

    all_ok = True
    for c in doc["cases"]:
        got = accept(c["challenge"], c["signature"], c["pubkey"], verify_at)
        passed = got == c["expect_accept"]
        all_ok = all_ok and passed
        mark = f"{GREEN}PASS{RST}" if passed else f"{RED}FAIL{RST}"
        print(f"  [{mark}] {c['name']:16s} {DIM}accept={str(got).lower()} (expect {str(c['expect_accept']).lower()}){RST}")

    print()
    if all_ok:
        print(f"{GREEN}YES IT PLAYS — M2M handshake interops; stale/replayed/wrong-key rejected.{RST}")
        return 0
    print(f"{RED}interop broken — challenge-response disagrees. Fix the spec.{RST}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
