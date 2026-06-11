# Conformance

An implementation is **conformant at level `vN`** when it consumes the corresponding vector
file and produces the expected result for **every** case (positive cases pass, negative cases
fail), per [`SPEC.md`](SPEC.md).

| Level | Vector file | Proves |
|---|---|---|
| **v1** | `vectors/vink_v1.json` | VINK attestation — canonical string + Ed25519 sign/verify |
| **v2** | `vectors/offer_v2.json` | offer envelope — fields, TTL, embedded `vinks_sig` |
| **v3** | `vectors/nfc_v3.json` | NFC transport — HCE AID + SELECT APDU + SW framing |
| **v4** | `vectors/resolve_v4.json` | AINS resolve + key-match (name → key binding) |
| **v5** | `vectors/fresh_v5.json` | fresh-assurance (RVP gate) — stale assurance rejected |

## What counts as proof

- **Passing `./run.sh`** proves the *reference* implementation in this repo is internally
  consistent — useful, but it is **not** an interop claim.
- **Passing the vectors from an independent implementation** (yours, sharing no code with
  `ref/`) is what proves **interoperability**. See [`IMPLEMENTER.md`](IMPLEMENTER.md).

A claim of "conformant at vN" should name the level(s), the vector file(s), and the
independent implementation. Conformance is per-level: an implementation may be conformant at
v1–v2 without yet covering v3+.
