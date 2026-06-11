#!/usr/bin/env python3
"""ZTIP conformance — onafhankelijke VINK-VERIFIER (primitive v1).

Dit is een TWEEDE implementatie. Hij vertrouwt de generator NIET: hij leest
vectors/vink_v1.json, HER-BEREKENT de canonical-string zelf uit de ruwe VINK-velden
(per SPEC.md sec.2) en verifieert de Ed25519-handtekening tegen de gepubliceerde
public key.

Groen op álle gevallen — inclusief het negatieve tamper-geval — betekent: een
implementatie die GEEN regel code met de offerer deelt, interopt met de offerer.
Dat is "survives the vendor", aantoonbaar. Run dit met je eigen taal en je hebt
hetzelfde antwoord. Exit 0 = interop.
"""
import base64
import json
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, "..", "vectors", "vink_v1.json")

GREEN, RED, DIM, RST = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def vink_canonical(vinks) -> str:
    """Onafhankelijke her-implementatie van SPEC.md sec.2 (geen import uit generate.py)."""
    parts = []
    for v in sorted(vinks, key=lambda x: x["key"]):
        tick = "1" if v["granted"] else "0"
        demo = "d" if v.get("demo") else ""
        parts.append(f'{v["key"]}={tick}{demo}')
    return "|".join(parts)


def verifies(pub_b64: str, canonical: str, sig_b64: str) -> bool:
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
    try:
        pub.verify(base64.b64decode(sig_b64), canonical.encode("utf-8"))
        return True
    except InvalidSignature:
        return False


def main() -> int:
    with open(VEC) as f:
        doc = json.load(f)

    pub_b64 = doc["public_key_b64"]
    print(f"ZTIP conformance — verifying {doc['primitive']} v{doc['version']} ({doc['algorithm']})")
    print(f"  public key: {pub_b64}")

    all_ok = True
    for c in doc["cases"]:
        recomputed = vink_canonical(c["vinks"])                 # niet vertrouwen: zelf bouwen
        canonical_match = recomputed == c["canonical"]          # spec-overeenkomst check
        ok = verifies(pub_b64, recomputed, c["signature_b64"])  # crypto-check op ONZE canonical
        passed = canonical_match and (ok == c["expect_verify"])
        all_ok = all_ok and passed
        mark = f"{GREEN}PASS{RST}" if passed else f"{RED}FAIL{RST}"
        verdict = "verify=true" if ok else "verify=false"
        print(f"  [{mark}] {c['name']:24s} {DIM}{verdict} (expect {str(c['expect_verify']).lower()}){RST}")
        if not canonical_match:
            print(f"          {RED}canonical mismatch!{RST} spec says {recomputed!r}, vector says {c['canonical']!r}")

    print()
    if all_ok:
        print(f"{GREEN}YES IT PLAYS — all cases interop. Independent impl agrees, no vendor needed.{RST}")
        return 0
    print(f"{RED}interop broken — a second implementation does NOT agree. Fix the spec/encoding.{RST}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
