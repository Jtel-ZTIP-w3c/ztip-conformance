#!/usr/bin/env python3
"""ZTIP conformance — AINS RESOLVE + KEY-MATCH test-vector generator (primitive v4).

The clean split (Codex/Jasper):
    identity  = key   -> jis:ed25519:<fingerprint>   (canonical; all trust binds here)
    namespace = .aint -> AINS resolves names to keys/capabilities/endpoints (NOT identity)
    surface   = SSM   -> what lane/type the record claims to be (without trusting name/payload)

So an AINS name is a semantic-namespace entry, not an identity. A resolver may use
hash-qualified `.aint` names for collision resistance, but every trust decision MUST bind to
the resolved JIS actor key.

Two name classes:
  - **alias**  (jasper.aint)               — human, mutable.
  - **bound**  (vandemeent-<suffix>.aint)  — namespace disambiguator, key-derived:
        suffix = base32( sha256(pubkey_raw || "|aint|1") )[:6]  (lowercase, no padding)
    It is NOT the identity — it's a stable, recomputable hint. A name that lies about the key
    is caught as a suffix mismatch.

Each record carries `surface` (SSM lane) + `capabilities`, and a `proof`: the actor's Ed25519
signature over `name|canonical_actor|status|surface|caps` so a resolver can't fabricate it.
Deterministic + OFFLINE (fixed seeds, no live call).
"""
import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "vectors", "resolve_v4.json")

NAMESPACE = b"aint"
PROFILE_VERSION = b"1"
SURFACE = "now.identity.resolve.normal"
CAPS = ["offer.issue", "vink.sign"]


def keypair(seed_phrase):
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed_phrase).digest())
    raw = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sk, base64.b64encode(raw).decode("ascii")


def bound_suffix(pub_b64):
    raw = base64.b64decode(pub_b64)
    h = hashlib.sha256(raw + b"|" + NAMESPACE + b"|" + PROFILE_VERSION).digest()
    return base64.b32encode(h).decode("ascii").lower().replace("=", "")[:6]


def canonical_actor(pub_b64):
    return "jis:ed25519:" + pub_b64


def proof_msg(name, actor, status, surface, caps):
    return f"{name}|{actor}|{status}|{surface}|{','.join(sorted(caps))}".encode("utf-8")


def proof(sk, name, actor, status, surface, caps):
    return base64.b64encode(sk.sign(proof_msg(name, actor, status, surface, caps))).decode("ascii")


def record(name, name_class, pub, sk, status, proof_override=None):
    actor = canonical_actor(pub)
    return {
        "name": name,
        "name_class": name_class,
        "canonical_actor": actor,
        "public_key": pub,
        "status": status,
        "surface": SURFACE,
        "capabilities": CAPS,
        "proof": proof_override if proof_override is not None else proof(sk, name, actor, status, SURFACE, CAPS),
    }


def main():
    our_sk, OUR = keypair(b"ztip-conformance/vink-attestation/v1")
    imp_sk, IMP = keypair(b"ztip-conformance/imposter-key")
    our_suf, imp_suf = bound_suffix(OUR), bound_suffix(IMP)

    n_bound = f"vandemeent-{our_suf}.aint"
    n_forged = "vandemeent-zzzzzz.aint"
    n_badproof = f"badproof-{our_suf}.aint"
    n_alias = "jasper.aint"
    n_imp = f"imposter-{imp_suf}.aint"
    n_revoked = f"retired-{our_suf}.aint"

    fixture = {
        n_bound:    record(n_bound, "bound", OUR, our_sk, "active"),
        n_forged:   record(n_forged, "bound", OUR, our_sk, "active"),     # valid proof, suffix lies
        n_badproof: record(n_badproof, "bound", OUR, our_sk, "active",
                           proof_override=proof(our_sk, "different-name", canonical_actor(OUR), "active", SURFACE, CAPS)),
        n_alias:    record(n_alias, "alias", OUR, our_sk, "active"),
        n_imp:      record(n_imp, "bound", IMP, imp_sk, "active"),
        n_revoked:  record(n_revoked, "bound", OUR, our_sk, "revoked"),
        # "ghost.aint" intentionally ABSENT
    }

    cases = [
        {"name": "bound-match",   "offer": {"claimed_aint": n_bound,    "sender_pubkey": OUR}, "expect_bound": True},
        {"name": "forged-suffix", "offer": {"claimed_aint": n_forged,   "sender_pubkey": OUR}, "expect_bound": False},
        {"name": "bad-proof",     "offer": {"claimed_aint": n_badproof, "sender_pubkey": OUR}, "expect_bound": False},
        {"name": "alias-match",   "offer": {"claimed_aint": n_alias,    "sender_pubkey": OUR}, "expect_bound": True},
        {"name": "key-mismatch",  "offer": {"claimed_aint": n_imp,      "sender_pubkey": OUR}, "expect_bound": False},
        {"name": "revoked",       "offer": {"claimed_aint": n_revoked,  "sender_pubkey": OUR}, "expect_bound": False},
        {"name": "unresolvable",  "offer": {"claimed_aint": "ghost.aint", "sender_pubkey": OUR}, "expect_bound": False},
    ]

    print("ZTIP conformance — AINS resolve + key-match v4 (name=namespace, key=identity, SSM=surface)")
    print(f"  our key : {OUR}  suffix={our_suf}  surface={SURFACE}")
    print(f"  imp key : {IMP}  suffix={imp_suf}")
    for c in cases:
        print(f"  {'+' if c['expect_bound'] else '-'} {c['name']:14s} {c['offer']['claimed_aint']:26s} bound={str(c['expect_bound']).lower()}")

    doc = {
        "primitive": "ains-resolve-keymatch",
        "version": 4,
        "model": "identity=jis:ed25519:key · namespace=.aint · surface=SSM. AINS names are namespace entries, not identities; all trust binds to the resolved JIS key.",
        "suffix_rule": "bound-name suffix = base32(sha256(pubkey_raw || '|aint|1'))[:6] lowercase — a namespace disambiguator, recompute from the resolved key and require a match.",
        "binding_rule": "bound := resolves AND status=='active' AND proof verifies over name|canonical_actor|status|surface|sorted(caps) AND (name_class!='bound' OR suffix matches key) AND canonical_actor=='jis:ed25519:'+public_key AND public_key == offer.sender_pubkey",
        "encoding_note": "public_key / sender_pubkey share one encoding (base64, SPEC sec.4). Bind by KEY, never by label.",
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
