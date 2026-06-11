# ZTIP Conformance Kit

**Prove that ZTIP interoperates — without the vendor. Runnable, not readable.**

Most specs ask a reviewer to *read* a wall of text and trust it. This one asks them to
*run* a JSON and watch it go green in 30 seconds. That flips the dynamic: instead of
costing a reviewer time, it saves it — and the same artifact proves that a stranger can
re-implement the protocol from the spec alone and **interoperate without calling us**.

That is the bar for *infrastructure* (vs a product): can independent implementations talk
to each other with no shared code, no original team in the loop? Here is the proof, one
primitive at a time.

## Quickstart

```sh
./run.sh
# or:
python3 ref/generate.py   # builds the test vectors (watch the JSON assemble itself)
python3 ref/verify.py     # a SECOND, independent implementation checks them
```

Expected last line:

```
YES IT PLAYS — all cases interop. Independent impl agrees, no vendor needed.
```

## What you just proved

- `ref/generate.py` builds `vectors/vink_v1.json`: real VINK attestations, signed with a
  fixed Ed25519 key.
- `ref/verify.py` is a **separate implementation**. It does not trust the generator: it
  re-derives the canonical string from the raw fields (per [`SPEC.md`](SPEC.md)) and verifies
  every signature — including a negative tamper case that must (and does) fail.
- Two implementations agreeing on the same bytes, sharing no logic = **interop**. Add a
  third in your language; if it goes green on `vectors/vink_v1.json`, you interoperate too.

## Reproducible

The key comes from a fixed seed (`SHA-256("ztip-conformance/vink-attestation/v1")`) and
Ed25519 is deterministic — so re-running `generate.py` yields a **byte-identical**
`vectors/vink_v1.json`. Diff it; there is no hidden state. (Same spirit as
`tibet-triage upip-reproduce`.)

## Don't boil the ocean — one level at a time

We deliberately ship **one primitive at a time**, each runnable and verifiable before the
next unlocks. [`ROADMAP.md`](ROADMAP.md) is the live map: `v1 — VINK attestation` is live
now; it tells you exactly what to build (and run) next. Beat a level, the next appears.

## Add your implementation

1. Read [`SPEC.md`](SPEC.md) (byte-precise; ~1 page).
2. Implement the canonical string + Ed25519 verify in your language.
3. Run it against `vectors/vink_v1.json`. Green on all cases = conformant.
4. Open a PR adding `ref/verify.<yourlang>` — a third independent witness.

## Provenance

This kit mirrors the live, running implementation:
- **Source-available demo (ID-Drop):** https://github.com/Jtel-ZTIP-w3c/ID-Drop
- **IETF Internet-Draft (jis:):** https://datatracker.ietf.org/doc/draft-vandemeent-jis-identity/

Open. Use it, break it, re-implement it. That is the point.
