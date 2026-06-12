# ZTIP Conformance Kit

**Prove that ZTIP interoperates — without the vendor. Runnable, not readable.**

Most specs ask a reviewer to *read* a wall of text and trust it. This one asks them to
*run* a JSON and watch it go green in 30 seconds. That flips the dynamic: instead of
costing a reviewer time, it saves it — and the same artifact proves that a stranger can
re-implement the protocol from the spec alone and **interoperate without calling us**.

That is the bar for *infrastructure* (vs a product): can independent implementations talk
to each other with no shared code, no original team in the loop? Here is the proof, one
primitive at a time.

## What this repo is

This is an **interoperability kit, not an SDK.**

The conformance contract is the **vector files in `vectors/`** — not the scripts. The
scripts here (`ref/`) are only *one* implementation that generates and verifies those
vectors. To prove independent interoperability, implement your **own** verifier or generator
against the vectors (see [IMPLEMENTER.md](IMPLEMENTER.md) and [CONFORMANCE.md](CONFORMANCE.md)).
**Do not** import this repo's verifier as a library and call that "interop" — that only shows
our code agrees with itself. Passing `./run.sh` proves the *reference* implementation is
internally consistent; a *second, independent* implementation matching the vectors is what
proves interop.

> **Don't take our word for it — not even our scripts.** Run the vectors against your own code.
> That's zero-trust, applied to this repo itself: the protocol says *trust nothing up front,
> prove each fact*; so does its conformance kit.

## Quickstart

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt      # just: cryptography
./run.sh                             # runs v1–v9, each green
```

Python 3.8+; no network, no build, no monorepo. (Per level you can also run a single
generator/verifier pair, e.g. `python3 ref/generate.py && python3 ref/verify.py` for v1.) The
live capstone in [`live/`](live/README.md) is the one part that uses the network.

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

## Running in production (the live witness)

The vectors are the offline *contract*. [`live/verify_live.py`](live/README.md) is the
*witness*: it resolves a registered `.aint` over the **real** public AINS and binds to the
live key — same logic, production infrastructure, normalizing the real on-wire encoding.

```sh
python3 live/verify_live.py     # → BOUND root_idd (live), unbound for an absent name
```

Needs network; non-deterministic by design. Not a conformance vector — the proof that the
contract runs in the wild.

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

---

## Part of the conformance family

Four runnable kits, one per branch of the stack. Run any, implement your own verifier against its
vectors, interoperate with no vendor in the loop. Together they let a second implementation
reconstruct the whole spine from the vectors alone.

- [ztip-conformance](https://github.com/Jtel-ZTIP-w3c/ztip-conformance) — identity / attestation / ceremony
- [tibet-comms-conformance](https://github.com/Jtel-ZTIP-w3c/tibet-comms-conformance) — communication / routing
- [tibet-evidence-conformance](https://github.com/Jtel-ZTIP-w3c/tibet-evidence-conformance) — storage / evidence
- [tibet-security-conformance](https://github.com/Jtel-ZTIP-w3c/tibet-security-conformance) — policy / enforcement

Primitive atlas: https://github.com/Jtel-ZTIP-w3c/Jtel-ZTIP-w3c.github.io (INTEROP.md).
