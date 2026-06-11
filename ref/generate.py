#!/usr/bin/env python3
"""ZTIP conformance — VINK-attestation test-vector GENERATOR (primitive v1).

Bouwt de interop-vectoren voor het VINK-attestatie-primitief door het canonical-
algoritme uit SPEC.md te spiegelen en te tekenen met een VASTE Ed25519-seed.

Ed25519 is deterministisch (RFC 8032): vaste seed -> identieke pubkey + identieke
handtekeningen, elke run. Draai dit opnieuw en diff vectors/vink_v1.json -> byte-
identiek = reproduceerbaar (geen verborgen staat, geen vendor nodig).

Draai 'm en kijk de JSON zichzelf opbouwen. Daarna bewijst verify.py dat een TWEEDE,
onafhankelijke implementatie het ermee eens is.
"""
import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "vectors", "vink_v1.json")

# Vaste test-seed: SHA-256 van een gedocumenteerde zin -> 32 bytes, deterministisch.
# Dit is GEEN echte identiteit; puur voor conformance-vectoren.
SEED_PHRASE = b"ztip-conformance/vink-attestation/v1"
SEED = hashlib.sha256(SEED_PHRASE).digest()


def b64(raw: bytes) -> str:
    """Standaard base64 (gepad, geen line-wrap) — exact wat Android Base64.NO_WRAP geeft."""
    return base64.b64encode(raw).decode("ascii")


def vink_canonical(vinks) -> str:
    """SPEC.md sec.2 — spiegelt VinkCanon.canonical (Kotlin :core).

    Sorteer op key; '|'-join; elk item = key + '=' + ('1' als granted else '0')
    + ('d' als demo else ''). Dit is de EXACTE byte-string die getekend/geverifieerd
    wordt — één afwijking en de handtekening klopt niet meer.
    """
    parts = []
    for v in sorted(vinks, key=lambda x: x["key"]):
        tick = "1" if v["granted"] else "0"
        demo = "d" if v.get("demo") else ""
        parts.append(f'{v["key"]}={tick}{demo}')
    return "|".join(parts)


def main():
    sk = Ed25519PrivateKey.from_private_bytes(SEED)
    pub_raw = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    pub_b64 = b64(pub_raw)

    print("ZTIP conformance — VINK attestation v1")
    print(f"  seed phrase : {SEED_PHRASE.decode()}")
    print(f"  seed (hex)  : {SEED.hex()}")
    print(f"  public key  : {pub_b64}")
    print("  building cases:")

    # --- de positieve gevallen: echte VINK-sets zoals KIT/ID-Drop ze produceren ---
    positives = [
        ("adult-nl-genuine", [
            {"key": "age_18", "granted": True, "demo": False},
            {"key": "valid_document", "granted": True, "demo": False},
            {"key": "nationality_nld", "granted": True, "demo": False},
            {"key": "genuine_document", "granted": True, "demo": False},
        ]),
        ("live-session", [
            {"key": "age_18", "granted": True, "demo": False},
            {"key": "live_presence", "granted": True, "demo": False},
            {"key": "rightful_holder", "granted": True, "demo": False},
        ]),
        ("demo-flagged", [
            {"key": "age_18", "granted": True, "demo": True},
            {"key": "nationality_nld", "granted": True, "demo": True},
        ]),
        ("minor-denied", [
            {"key": "age_18", "granted": False, "demo": False},
            {"key": "valid_document", "granted": True, "demo": False},
        ]),
    ]

    cases = []
    for name, vinks in positives:
        canonical = vink_canonical(vinks)
        sig = sk.sign(canonical.encode("utf-8"))
        sig_b64 = b64(sig)
        cases.append({
            "name": name,
            "vinks": vinks,
            "canonical": canonical,
            "signature_b64": sig_b64,
            "expect_verify": True,
        })
        print(f"    + {name:18s} canonical={canonical!r}")
        print(f"    {'':20s}sig={sig_b64[:40]}…")

    # --- het negatieve geval: knoei met een gesigneerde set (age 1 -> 0) maar HOUD
    #     de oude handtekening. Canonical verschilt nu -> verify MOET falen. ---
    tampered = [
        {"key": "age_18", "granted": False, "demo": False},   # was True bij adult-nl-genuine
        {"key": "valid_document", "granted": True, "demo": False},
        {"key": "nationality_nld", "granted": True, "demo": False},
        {"key": "genuine_document", "granted": True, "demo": False},
    ]
    cases.append({
        "name": "tampered-age (negative)",
        "vinks": tampered,
        "canonical": vink_canonical(tampered),
        "signature_b64": cases[0]["signature_b64"],  # handtekening van adult-nl-genuine
        "expect_verify": False,
    })
    print(f"    - tampered-age        canonical={vink_canonical(tampered)!r}  (sig hoort bij adult-nl-genuine -> moet FALEN)")

    doc = {
        "primitive": "vink-attestation",
        "version": 1,
        "algorithm": "Ed25519",
        "message": "UTF-8 bytes of the canonical string (SPEC.md sec.2)",
        "encoding": "base64 standard, padded, no line-wrap (== Android Base64.NO_WRAP)",
        "seed_phrase": SEED_PHRASE.decode(),
        "seed_hex": SEED.hex(),
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
