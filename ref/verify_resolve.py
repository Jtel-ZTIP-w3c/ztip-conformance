#!/usr/bin/env python3
"""ZTIP conformance — independent AINS RESOLVE + KEY-MATCH verifier (primitive v4).

Second implementation of the hard rule: an AINS name is not an identity — it resolves to
one. Reads vectors/resolve_v4.json and binds an offer to a resolved record per SPEC.md sec.9:
resolves + active + proof verifies + (bound name → suffix recomputed from the key matches) +
canonical_actor consistent + resolved key == the expected key. Bind by KEY, never by label.
Green = the name→identity binding interops, no vendor, no live network.
"""
import base64
import hashlib
import json
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, "..", "vectors", "resolve_v4.json")
GREEN, RED, DIM, RST = "\033[32m", "\033[31m", "\033[2m", "\033[0m"

NAMESPACE = b"aint"
PROFILE_VERSION = b"1"


def bound_suffix(pub_b64):                       # independent re-impl of the suffix rule
    raw = base64.b64decode(pub_b64)
    h = hashlib.sha256(raw + b"|" + NAMESPACE + b"|" + PROFILE_VERSION).digest()
    return base64.b32encode(h).decode("ascii").lower().replace("=", "")[:6]


def name_suffix(name):                           # "<label>-<suffix>.aint" -> suffix, else None
    base = name[:-5] if name.endswith(".aint") else name
    return base.rsplit("-", 1)[1] if "-" in base else None


def sig_ok(pub_b64, msg, sig_b64):
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(
            base64.b64decode(sig_b64), msg)
        return True
    except InvalidSignature:
        return False


def bound(record, expected_key):
    if record is None:
        return False                                              # unresolvable
    if record.get("status") != "active":
        return False                                              # revoked / suspended
    pub = record["public_key"]
    caps = ",".join(sorted(record.get("capabilities", [])))
    msg = f"{record['name']}|{record['canonical_actor']}|{record['status']}|{record.get('surface','')}|{caps}".encode("utf-8")
    if not sig_ok(pub, msg, record["proof"]):                     # record forged / tampered
        return False
    if record.get("name_class") == "bound":                       # key-bound name: suffix MUST derive from key
        if name_suffix(record["name"]) != bound_suffix(pub):
            return False
    if record["canonical_actor"] != "jis:ed25519:" + pub:         # record internally consistent
        return False
    return pub == expected_key                                    # bind by KEY, never the label


def main():
    with open(VEC) as f:
        doc = json.load(f)
    fixture = doc["resolve_fixture"]
    print(f"ZTIP conformance — verifying {doc['primitive']} v{doc['version']} (name != identity)")

    all_ok = True
    for c in doc["cases"]:
        o = c["offer"]
        got = bound(fixture.get(o["claimed_aint"]), o["sender_pubkey"])
        passed = got == c["expect_bound"]
        all_ok = all_ok and passed
        mark = f"{GREEN}PASS{RST}" if passed else f"{RED}FAIL{RST}"
        print(f"  [{mark}] {c['name']:14s} {DIM}bound={str(got).lower()} (expect {str(c['expect_bound']).lower()}){RST}")

    print()
    if all_ok:
        print(f"{GREEN}YES IT PLAYS — name→identity binding interops; bound by key, not by name.{RST}")
        return 0
    print(f"{RED}interop broken — resolve/key-match disagrees. Check suffix/proof/encoding.{RST}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
