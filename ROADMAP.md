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

## Status

| Level | Primitive | Adds | Status |
|------:|-----------|------|--------|
| **v1** | **VINK attestation** | canonical string + Ed25519 sign/verify of a yes/no claim set | ✅ **live** (`vink_v1.json`) |
| v2 | Offer envelope | the `IdDropOffer` JSON wire-format: fields, types, TTL, how `vinks`/`vinks_sig` embed | 🔜 **next** |
| v3 | NFC transport | HCE AID + SELECT APDU + payload framing — two independent stacks can physically tap | ⬜ |
| v4 | AINS resolve + key-match | `.aint` → pubkey resolution; verifier checks `resolved_pubkey == offer.sender_pubkey` | ⬜ |
| v5 | Fresh-assurance lane | session VINKs (`live_presence`/`rightful_holder`) with TTL; fresh-at-use, never persisted | ⬜ |
| v6 | Offer-first ceremony | the stages OFFER→…→MATERIALIZE; the T-1→T0 "never auto-bind" rule | ⬜ |
| v7 | Challenge-response (M2M) | JIS-001: fresh challenge + Ed25519 response for machine-to-machine (no proximity) | ⬜ |
| v8 | Entity-class profiles | same handshake, swapped proof vocabulary: human / AI / IoT — one resolver, many actors | ⬜ |

Legend: ✅ live · 🔜 next · ⬜ planned.

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

Leaf → container → wire → name-binding → freshness → ceremony → machine lane → general
profiles. Each level only depends on the ones above it, so a newcomer can stop at any
depth and still have something that interoperates. The deepest level (v8) is the
generalization across humans, AI, and IoT — the "common problem space" worth converging on
with peers.
