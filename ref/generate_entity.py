#!/usr/bin/env python3
"""ZTIP conformance — ENTITY-CLASS test-vector generator (primitive v8).

One resolver, many actors. The handshake is IDENTICAL for a human, an AI, or an IoT device:
resolve the actor's `.aint` to a JIS key, verify a signature under that key. What SWAPS is the
**proof vocabulary** the actor is allowed to present:

    human → biometric_presence     (fresh biometric / proximity + state credential)
    ai    → mandate_chain          (mandate + causal step; stateless between calls)
    iot   → substrate_continuity   (unbroken substrate / behaviour pattern)

So the crypto and the resolve are the same; only the *lane* differs. v8 pins that: a proof is
accepted iff its `proof_type` is the one allowed for the actor's `entity_class` AND the
signature verifies under the actor's key. A human presenting an AI's mandate proof is refused
— not because the signature is bad, but because the vocabulary doesn't match the class.

Fixed seeds -> deterministic, offline. Canonical: jis-proof:v1:<entity_class>:<proof_type>:<nonce>.
"""
import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "vectors", "entity_v8.json")

LANES = {
    "human": "biometric_presence",
    "ai": "mandate_chain",
    "iot": "substrate_continuity",
}


def keypair(seed_phrase):
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed_phrase).digest())
    raw = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sk, base64.b64encode(raw).decode("ascii")


def canonical(entity_class, proof_type, nonce):
    return f"jis-proof:v1:{entity_class}:{proof_type}:{nonce}"


def main():
    actor_sk, ACTOR = keypair(b"ztip-conformance/vink-attestation/v1")
    imp_sk, _ = keypair(b"ztip-conformance/imposter-key")

    def actor(entity_class, proof_type, nonce, sk):
        return {
            "entity_class": entity_class,
            "proof_type": proof_type,
            "nonce": nonce,
            "key": ACTOR,
            "proof": base64.b64encode(sk.sign(canonical(entity_class, proof_type, nonce).encode("utf-8"))).decode("ascii"),
        }

    cases = [
        {"name": "human-biometric", "actor": actor("human", "biometric_presence", "h1", actor_sk),
         "expect_accept": True},
        {"name": "ai-mandate", "actor": actor("ai", "mandate_chain", "a1", actor_sk),
         "expect_accept": True},
        {"name": "iot-continuity", "actor": actor("iot", "substrate_continuity", "i1", actor_sk),
         "expect_accept": True},
        {"name": "wrong-lane", "actor": actor("human", "mandate_chain", "w1", actor_sk),
         "expect_accept": False},   # human presenting an AI proof -> vocabulary mismatch
        {"name": "bad-signature", "actor": actor("ai", "mandate_chain", "b1", imp_sk),
         "expect_accept": False},   # right lane, wrong key
    ]

    print("ZTIP conformance — entity-class v8 (one resolver, many actors)")
    print(f"  actor key : {ACTOR}")
    for c in cases:
        a = c["actor"]
        print(f"  {'+' if c['expect_accept'] else '-'} {c['name']:16s} {a['entity_class']:6s} proof={a['proof_type']:20s} accept={str(c['expect_accept']).lower()}")

    doc = {
        "primitive": "entity-class",
        "version": 8,
        "lanes": LANES,
        "canonical": "jis-proof:v1:<entity_class>:<proof_type>:<nonce>",
        "rule": "accept := proof_type == lanes[entity_class] AND Ed25519_verify(key, proof, canonical). Same handshake for every class; only the proof vocabulary differs.",
        "cases": cases,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"  wrote {len(cases)} cases -> {os.path.relpath(OUT, os.path.join(HERE, '..'))}")


if __name__ == "__main__":
    main()
