# ZTIP Conformance — Roadmap

**One primitive at a time. Each one runnable and verifiable before the next unlocks.**

We are *not* trying to spec the whole stack in one go (don't boil the ocean). Each level
adds the next-smallest interop surface, with three artifacts:

1. a byte-precise section in `SPEC.md`,
2. test vectors in `vectors/`,
3. an independent verifier in `ref/` that goes green.

A developer (or you) beats a level by getting their own implementation green on its
vectors. Then the next level is the obvious thing to build. This file is the **live map**
— update the status column as levels land.

## The roots — where the game really begins

VINK (v1) was the fastest thing to turn green: self-contained, no network, byte-exact. But
it is **not the foundation**. Two systems first speak to each other not over a VINK, but
over the **jis identity handshake — FIR/A** (Fresh Identity Re-Attestation): each side
proves, with a fresh Ed25519 challenge→response, that it is a valid actor *right now*. That
is the genesis primitive. Everything here composes on **jis** (identity) and **tibet**
(signed intent / provenance). The map starts at the roots.

Two honest entry points: start at the **roots** (jis FIR/A) for first principles, or at
**v1 (VINK)** for the fastest green. They meet — VINK *is* jis-signing applied to a claim set.

## Status

| Level | Primitive | Adds | Status |
|------:|-----------|------|--------|
| **root** | **jis · identity / FIR-A** | Ed25519 keypair + `jis:` scheme + fresh challenge→signed response: "I'm a valid actor, *now*" — where two systems first handshake | ⬜ genesis |
| **root** | **tibet · intent token** | signed intent/event token + chain — "what happened, in order, provable" (provenance) | ⬜ genesis |
| **v1** | **VINK attestation** | jis-signing applied to a yes/no claim set: canonical string + Ed25519 sign/verify | ✅ **live** (`vink_v1.json`) |
| v2 | Offer envelope | the `IdDropOffer` JSON wire-format: fields, types, TTL, how `vinks`/`vinks_sig` embed | 🔜 **next** |
| v3 | NFC transport | HCE AID + SELECT APDU + payload framing — two independent stacks can physically tap | ⬜ |
| v4 | AINS resolve + key-match | `.aint` → pubkey resolution; verifier checks `resolved_pubkey == offer.sender_pubkey` | ⬜ |
| v5 | Fresh-assurance lane | session VINKs (`live_presence`/`rightful_holder`) with TTL; fresh-at-use, never persisted | ⬜ |
| v6 | Offer-first ceremony | the stages OFFER→…→MATERIALIZE; the T-1→T0 "never auto-bind" rule | ⬜ |
| v7 | Challenge-response (M2M) | the network form of the jis-root handshake: agent↔agent FIR/A, no proximity (JIS-001) | ⬜ |
| v8 | Entity-class profiles | same handshake, swapped proof vocabulary: human / AI / IoT — one resolver, many actors | ⬜ |

Legend: ✅ live · 🔜 next · ⬜ genesis/planned. The **roots** (jis/tibet) are the bedrock;
the numbered levels compose upward on them.

## What "next" looks like (v2 — Offer envelope)

The natural follow-on to v1. The signed VINK set never travels alone; it rides inside an
**offer**. v2 pins that envelope so a second implementation can parse and validate a whole
offer, not just a VINK set:

- **Spec:** the `IdDropOffer` fields (`offer_id`, `expires_at`, `sender_pubkey`,
  `claimed_aint`, `claim_class`, `semantic_type`, `entity_class`, `vinks`, `vinks_sig`, …),
  their types, and the **TTL rule** (`expired(now) := now >= expires_at`).
- **Vectors:** a few full offer JSONs — one fresh, one expired, one with a tampered
  `vinks_sig` — each with `expect_valid`.
- **Verifier:** parse offer → check not-expired → verify `vinks_sig` over
  `canonical(vinks)` (reusing v1) → report valid/invalid.

It composes directly on v1 (the signature check *is* v1), so it's a small, satisfying next
step — and it's the unit a Terminal actually reads off the tap.

## Why this order

Roots (jis identity / tibet intent) → leaf (VINK) → container → wire → name-binding →
freshness → ceremony → machine lane → general profiles. Each level only depends on the
ones above it, so a newcomer can stop at any depth and still have something that
interoperates. The deepest level (v8) is the
generalization across humans, AI, and IoT — the "common problem space" worth converging on
with peers.
