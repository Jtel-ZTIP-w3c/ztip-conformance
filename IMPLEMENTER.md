# Implementer Guide

**Goal:** build an *independent* verifier (or generator) that agrees with the public vectors.

The point of this kit is that you do **not** need our code. The vectors in `vectors/` are the
contract; your implementation proves interoperability by matching them in your own language.

## Rules

1. Read the JSON vector files from `vectors/`.
2. Implement, **yourself**, the check for each level (per [`SPEC.md`](SPEC.md)):

   | Level | What to implement |
   |---|---|
   | v1 | canonical VINK string + Ed25519 verify |
   | v2 | offer TTL + embedded VINK signature |
   | v3 | APDU parser + status-word (SW) codes |
   | v4 | AINS name ≠ identity — bind by key (+ bound-name suffix, record proof) |
   | v5 | freshness gate (honor only while fresh) |
   | v6 | never-auto-bind ceremony (bind only at MATERIALIZE) |
   | v7 | fresh challenge-response (verify over the issued challenge) |
   | v8 | entity-class proof lanes (human / AI / IoT) |
   | v9 | did as namespace; no did → live-act promotion |

3. Match every `expect_*` field in the vectors (`expect_verify`, `expect_valid`,
   `expect_bound`, `expect_honored`, `expect_accept`, the ceremony `expect`, the entity-class
   `expect_accept`, the v9 `expect`, and the NFC `expect` block).
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
