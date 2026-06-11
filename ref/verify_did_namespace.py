#!/usr/bin/env python3
"""ZTIP conformance — independent DID-AS-NAMESPACE verifier (primitive v9).

Second implementation of the one-way projection (SPEC.md sec.14):
  - projection : the did: document carries the jis key (jis -> did wrap is faithful).
  - static gate: a did: credential is recognized as a NAMESPACE name — verify the embedded
    key + its signed credential. Admitted as a name (did: is a name, not an instruction).
  - active gate: admission to ACT requires a FRESH proof over the verifier's own challenge.
    A static credential (a document) is not a live act -> refused. A live fresh-attestation
    is admitted. Capability gate (liveness), not an entity-class block.

Green = did: interops as a namespace (backwards-compat) AND the active gate structurally
declines static-only presenters — no vendor needed.
"""
import base64
import json
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, "..", "vectors", "did_namespace_v9.json")
GREEN, RED, DIM, RST = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def challenge_canonical(ch):
    return f"jis-challenge:v1:{ch['agent_id']}:{ch['nonce']}:{ch['issued_at']}"


def sig_ok(pub_b64, msg, sig_b64):
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(
            base64.b64decode(sig_b64), msg.encode("utf-8"))
        return True
    except InvalidSignature:
        return False


def projection_ok(did_document, jis_key):
    # the jis key must round-trip out of the did: document (a faithful wrap)
    vms = did_document.get("verificationMethod", [])
    return any(vm.get("publicKeyBase64") == jis_key for vm in vms)


def static_gate(presentation, jis_key):
    # recognize the name: a signed credential under the key
    if presentation.get("type") != "static-credential":
        return False
    return sig_ok(jis_key, presentation["payload"], presentation["sig"])


def active_gate(presentation, jis_key, challenge, verify_at):
    # admission to ACT: a FRESH proof over OUR challenge — a static document cannot be one
    if presentation.get("type") != "fresh-attestation":
        return False
    if verify_at >= challenge["issued_at"] + challenge["ttl_seconds"]:
        return False
    return sig_ok(jis_key, challenge_canonical(challenge), presentation["sig"])


def main():
    with open(VEC) as f:
        doc = json.load(f)
    key, ch, verify_at = doc["jis_key"], doc["challenge"], doc["verify_at"]
    print(f"ZTIP conformance — verifying {doc['primitive']} v{doc['version']}")

    all_ok = True
    for c in doc["cases"]:
        if c.get("check") == "projection":
            got = projection_ok(doc["did_document"], key)
        elif c["gate"] == "static":
            got = static_gate(c["presentation"], key)
        else:
            got = active_gate(c["presentation"], key, ch, verify_at)
        passed = got == c["expect"]
        all_ok = all_ok and passed
        mark = f"{GREEN}PASS{RST}" if passed else f"{RED}FAIL{RST}"
        print(f"  [{mark}] {c['name']:22s} {DIM}got={str(got).lower()} (expect {str(c['expect']).lower()}){RST}")

    print()
    if all_ok:
        print(f"{GREEN}YES IT PLAYS — jis wraps into did (recognized as a name); a static did cannot be promoted to a live act.{RST}")
        return 0
    print(f"{RED}interop broken — did-namespace disagrees. Fix the spec.{RST}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
