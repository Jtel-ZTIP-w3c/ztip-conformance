# Implementer Guide

**Goal:** build an *independent* verifier (or generator) that agrees with the public vectors.

The point of this kit is that you do **not** need our code. The vectors in `vectors/` are the
contract; your implementation proves interoperability by matching them in your own language.

## Rules

1. Read the JSON vector files from `vectors/`.
2. Implement, **yourself**: the VINK canonicalization, Ed25519 signature verification, the
   offer TTL check, the NFC/APDU framing, the AINS resolve + key-match, and the freshness
   gate — per [`SPEC.md`](SPEC.md).
3. Match every `expect_*` field in the vectors (`expect_verify`, `expect_valid`,
   `expect_bound`, `expect_honored`, and the NFC `expect` block).
4. **Positive** cases must pass; **negative** cases must fail.
5. Your implementation may be in **any language**.
6. You may *read* this repo's reference scripts (`ref/`) for clarity — but conformance is
   measured against the **vectors**, never by importing the scripts.

## Why this matters

If you import our `verify.py` and run it, you have shown that our code agrees with our code.
That is internal consistency, not interoperability. Interop is two implementations that share
**no logic** producing the same verdicts on the same bytes. Re-implement, then compare.

When your verifier is green on `vectors/*.json`, open a PR adding `ref/verify.<yourlang>` — a
third independent witness for the next person.
