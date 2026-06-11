#!/usr/bin/env python3
"""ZTIP conformance — DID-AS-NAMESPACE test-vector generator (primitive v9).

The asymmetry, made runnable (Jasper): you can always WRAP an active, hardware-bound L0
primitive (jis: + SSM) into a dumb, static envelope (did:), but you can NEVER promote a static
envelope into the active primitive. A snapshot is not a live process.

What this proves:
  1. **projection** — a jis identity projects into a valid did: document (backwards-compat).
  2. **static gate** — a did: document is *recognized*: resolve it as a NAMESPACE name, verify
     the key + its signed credential. It is admitted *as a name* (jis: treats did: as a name,
     never an instruction).
  3. **active gate** — admission to *act* requires a FRESH proof bound to the verifier's own
     challenge (a live act, v7). A static did: credential — however valid — is a document, not
     a live act over this challenge, so it is **refused**. A live jis: actor produces the fresh
     response and is admitted.

Honest framing: this is a *capability* gate (liveness), not an entity-class block. A
jis:-bearing AI passes the active gate; a static-only presenter (whatever holds it) does not.
"Presenting a static credential" ≠ "performing a live proof".

Fixed seed + fixed verify_at -> deterministic, offline.
"""
import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "vectors", "did_namespace_v9.json")

VERIFY_AT = 1_750_000_000
TTL = 30


def keypair(seed_phrase):
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed_phrase).digest())
    raw = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sk, base64.b64encode(raw).decode("ascii")


def doc_canonical(did_id, key):
    return f"did-doc:v1:{did_id}:{key}"


def challenge_canonical(ch):
    return f"jis-challenge:v1:{ch['agent_id']}:{ch['nonce']}:{ch['issued_at']}"


def main():
    sk, KEY = keypair(b"ztip-conformance/vink-attestation/v1")

    # jis identity projected into a did: document (the WRAP — backwards-compat).
    did_id = "did:web:vandemeent.aint"
    did_document = {
        "id": did_id,
        "verificationMethod": [{
            "id": did_id + "#k0",
            "type": "Ed25519VerificationKey2020",
            "publicKeyBase64": KEY,          # the jis key round-trips into the did doc
        }],
    }
    static_credential = {
        "type": "static-credential",
        "payload": doc_canonical(did_id, KEY),
        "sig": base64.b64encode(sk.sign(doc_canonical(did_id, KEY).encode())).decode("ascii"),
    }

    challenge = {"agent_id": "root_idd", "nonce": "n0nce-live", "issued_at": VERIFY_AT - 3, "ttl_seconds": TTL}
    fresh_attestation = {
        "type": "fresh-attestation",
        "sig": base64.b64encode(sk.sign(challenge_canonical(challenge).encode())).decode("ascii"),
    }

    cases = [
        {"name": "jis-to-did-projection", "check": "projection", "expect": True},
        {"name": "static-gate-did", "gate": "static", "presentation": static_credential, "expect": True},
        {"name": "active-gate-jis", "gate": "active", "presentation": fresh_attestation, "expect": True},
        {"name": "active-gate-did", "gate": "active", "presentation": static_credential, "expect": False},
    ]

    print("ZTIP conformance — did-as-namespace v9 (the one-way projection)")
    print(f"  jis key   : {KEY}")
    print(f"  did doc   : {did_id}  (carries the jis key)")
    for c in cases:
        what = c.get("check") or f"{c['gate']}-gate"
        print(f"  {'+' if c['expect'] else '-'} {c['name']:22s} {what:14s} expect={str(c['expect']).lower()}")

    doc = {
        "primitive": "did-namespace",
        "version": 9,
        "verify_at": VERIFY_AT,
        "principle": "wrap active->static always (jis->did); promote static->active never (a did: doc is a snapshot, not a live process). jis ⊋ did.",
        "jis_key": KEY,
        "did_document": did_document,
        "challenge": challenge,
        "static_gate": "recognize a did: name: verify the embedded key + its signed credential. Admitted AS A NAME (namespace, not instruction).",
        "active_gate": "admission to ACT requires a fresh proof over the verifier's own challenge (live act, v7). A static credential is a document, not a live act -> refused. Capability gate (liveness), not an entity-class block.",
        "cases": cases,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"  wrote {len(cases)} cases -> {os.path.relpath(OUT, os.path.join(HERE, '..'))}")


if __name__ == "__main__":
    main()
