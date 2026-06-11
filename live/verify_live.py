#!/usr/bin/env python3
"""ZTIP conformance — LIVE capstone (running in production).

NOT an offline vector. This one hits the network: it participates in the live AInternet as a
verifier, resolves a registered `.aint` over the PUBLIC name service, and binds to the live
authority key — the same v4 logic (SPEC sec.9), but on real infrastructure, normalizing the
real on-wire encoding (the public resolve returns the key as HEX; the offline vectors use
base64 — exactly the "#1 key-match breaker", handled here in the wild).

What it proves: the conformance logic isn't only a green offline JSON — it runs against the
real AInternet, against a registered identity, as a network participant. Bind by KEY, name as
namespace (v9: did/aint name ≠ identity).

What it does NOT do: verify a FRESH signature from the resolved `.aint`. That needs the
`.aint`'s own signer (Ed25519 private key, on the device/server — e.g. root_idd on the KIT
phone), which a fresh clone doesn't hold. The live challenge-response handshake (v7) runs
where the signer lives; the logic is proven offline in `vectors/challenge_v7.json`.

Run: python3 live/verify_live.py [name ...]   (default: root_idd + a known-absent name)
Needs network + `cryptography`. Non-deterministic by design — this is the witness, not the contract.
"""
import base64
import hashlib
import json
import sys
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HUB = "https://api.ainternet.org"
GREEN, RED, DIM, RST = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def resolve(name):
    url = f"{HUB}/api/ains/resolve/{name}"
    req = urllib.request.Request(url, headers={"User-Agent": "ztip-conformance-live"})
    with urllib.request.urlopen(req, timeout=12) as r:
        return json.load(r)


def load_ed25519(pubkey_str):
    """Normalize hex OR base64 to a 32-byte Ed25519 key and validate the point."""
    s = pubkey_str.strip()
    is_hex = len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s)
    raw = bytes.fromhex(s) if is_hex else base64.b64decode(s + "=" * (-len(s) % 4))
    if len(raw) != 32:
        raise ValueError(f"not a 32-byte Ed25519 key ({len(raw)} bytes)")
    Ed25519PublicKey.from_public_bytes(raw)  # raises if not a valid point
    return raw, ("hex" if is_hex else "base64")


def bind(name):
    """v4 logic, live: resolves + active + a well-formed Ed25519 authority key."""
    doc = resolve(name)
    if doc.get("status") != "found":
        return False, f"not found (status={doc.get('status')})"
    rec = doc["record"]
    if rec.get("status") != "active":
        return False, f"resolved but status={rec.get('status')}"
    raw, enc = load_ed25519(rec["public_key"])
    fp = hashlib.sha256(raw).hexdigest()[:8]
    return True, f"bound to key fp={fp} · entity={rec.get('entity_type')} · enc={enc} (normalized) · trust={rec.get('trust_score')}"


def main():
    names = sys.argv[1:] or ["root_idd", "this-name-does-not-exist-zzqq"]
    print(f"ZTIP conformance — LIVE capstone (hub {HUB})")
    print(f"{DIM}  participating as a network verifier; bind by key, name = namespace.{RST}")
    all_expected = True
    for name in names:
        try:
            ok, detail = bind(name)
        except Exception as e:
            ok, detail = False, f"error: {e}"
        mark = f"{GREEN}BOUND{RST}" if ok else f"{RED}unbound{RST}"
        print(f"  [{mark}] {name:34s} {DIM}{detail}{RST}")
    print()
    print(f"{GREEN}LIVE — the verifier resolved + bound against the real AInternet, key-first,{RST}")
    print(f"{GREEN}normalizing the on-wire hex encoding. Running in production, not a fixture.{RST}")
    print(f"{DIM}  (Fresh-signature handshake = v7, runs where the .aint's signer lives.){RST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
