#!/usr/bin/env python3
"""ZTIP conformance — CHALLENGE-RESPONSE test-vector generator (primitive v7).

The network form of the JIS root handshake (FIR/A, no proximity): a verifier issues a FRESH
challenge; the actor signs it with its Ed25519 key; the verifier checks the signature against
the actor's key AND that the challenge is still fresh AND that it is the challenge IT issued
(anti-replay). Mirrors JIS-001 verify_identity_request (X-Agent-ID / X-Challenge / X-Signature).

A response is accepted iff:
    sig verifies over canonical(challenge) under the expected key
    AND verify_at < challenge.issued_at + challenge.ttl_seconds         (fresh)
    (replay of an OLD challenge fails the sig check, because the verifier always verifies
     against the challenge IT currently expects, not the one the response was signed over.)

Fixed seeds + fixed verify_at -> deterministic, offline.
"""
import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "vectors", "challenge_v7.json")

VERIFY_AT = 1_750_000_000
TTL = 30  # a challenge is fresh for 30s


def keypair(seed_phrase):
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed_phrase).digest())
    raw = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sk, base64.b64encode(raw).decode("ascii")


def canonical(ch):
    return f"jis-challenge:v1:{ch['agent_id']}:{ch['nonce']}:{ch['issued_at']}"


def main():
    actor_sk, ACTOR = keypair(b"ztip-conformance/vink-attestation/v1")
    imp_sk, _ = keypair(b"ztip-conformance/imposter-key")

    def ch(nonce, issued_dt):
        return {"agent_id": "root_idd", "nonce": nonce, "issued_at": VERIFY_AT + issued_dt, "ttl_seconds": TTL}

    def sign(sk, challenge):
        return base64.b64encode(sk.sign(canonical(challenge).encode("utf-8"))).decode("ascii")

    c_fresh = ch("n0nce-aaaa", -5)          # issued 5s ago, TTL 30 -> fresh
    c_stale = ch("n0nce-bbbb", -60)         # issued 60s ago -> expired
    c_now   = ch("n0nce-cccc", -2)          # the challenge the verifier currently expects
    c_old   = ch("n0nce-dddd", -2)          # a DIFFERENT (replayed) challenge

    cases = [
        {"name": "valid-fresh",  "challenge": c_fresh, "pubkey": ACTOR,
         "signature": sign(actor_sk, c_fresh), "expect_accept": True},
        {"name": "bad-signature", "challenge": c_fresh, "pubkey": ACTOR,
         "signature": sign(imp_sk, c_fresh), "expect_accept": False},     # signed by the wrong key
        {"name": "stale-challenge", "challenge": c_stale, "pubkey": ACTOR,
         "signature": sign(actor_sk, c_stale), "expect_accept": False},   # valid sig, expired
        {"name": "replayed", "challenge": c_now, "pubkey": ACTOR,
         "signature": sign(actor_sk, c_old), "expect_accept": False},     # sig over a DIFFERENT challenge
    ]

    print("ZTIP conformance — challenge-response v7 (M2M / FIR-A)")
    print(f"  actor key : {ACTOR}")
    print(f"  verify_at : {VERIFY_AT}  (challenge TTL {TTL}s)")
    for c in cases:
        age = VERIFY_AT - c["challenge"]["issued_at"]
        print(f"  {'+' if c['expect_accept'] else '-'} {c['name']:16s} nonce={c['challenge']['nonce']:11s} age={age:+4d}s accept={str(c['expect_accept']).lower()}")

    doc = {
        "primitive": "challenge-response",
        "version": 7,
        "verify_at": VERIFY_AT,
        "canonical": "jis-challenge:v1:<agent_id>:<nonce>:<issued_at>",
        "rule": "accept := sig verifies over canonical(challenge) under pubkey AND verify_at < issued_at + ttl_seconds. The verifier verifies against the challenge IT expects, so a replayed/old response fails the sig check.",
        "cases": cases,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"  wrote {len(cases)} cases -> {os.path.relpath(OUT, os.path.join(HERE, '..'))}")


if __name__ == "__main__":
    main()
