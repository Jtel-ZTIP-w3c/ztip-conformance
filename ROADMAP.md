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
| **v2** | **Offer envelope** | the `IdDropOffer` JSON wire-format: fields, types, TTL, how `vinks`/`vinks_sig` embed | ✅ **live** (`offer_v2.json`) |
| **v3** | **NFC transport** | HCE AID + SELECT APDU + payload framing — two independent stacks can physically tap | ✅ **live** (`nfc_v3.json`) |
| **v4** | **AINS resolve + key-match** | `.aint` → pubkey resolution; verifier checks `resolved_pubkey == offer.sender_pubkey` | ✅ **live** (`resolve_v4.json`) |
| **v5** | **Fresh-assurance** (RVP control gate) | session VINKs (`live_presence`/`rightful_holder`) honored only while fresh — reject stale = untrusted-until-renewed (maps to L2 RVP, not the offer) | ✅ **live** (`fresh_v5.json`) |
| **v6** | **Offer-first ceremony** | the stages OFFER→…→MATERIALIZE; the T-1→T0 "never auto-bind" rule | ✅ **live** (`ceremony_v6.json`) |
| **v7** | **Challenge-response (M2M)** | the network form of the jis-root handshake: agent↔agent FIR/A, no proximity (JIS-001) | ✅ **live** (`challenge_v7.json`) |
| **v8** | **Entity-class profiles** | same handshake, swapped proof vocabulary: human / AI / IoT — one resolver, many actors | ✅ **live** (`entity_v8.json`) |
| **v9** | **DID-as-namespace** | the one-way projection: jis wraps into did (recognized as a name); a static did cannot be promoted to a live act | ✅ **live** (`did_namespace_v9.json`) |

Legend: ✅ live · 🔜 next · ⬜ genesis/planned. The **roots** (jis/tibet) are the bedrock;
the numbered levels compose upward on them.

**Beyond the ladder — the live capstone.** The nine levels above are offline & deterministic
(the contract). [`live/verify_live.py`](live/README.md) is the *witness*: it resolves a
registered `.aint` over the **real** public AINS and binds to the live key — the same v4
logic, on production infrastructure, normalizing the real hex encoding. Running in production,
not a fixture. (A fresh-signature handshake runs where the `.aint`'s signer lives; v7 proves
the logic offline.)

## v2 — Offer envelope (✅ live)

Done. `ref/generate_offer.py` + `ref/verify_offer.py` + `vectors/offer_v2.json` (fresh-valid,
expired-ttl, tampered-sig, identity-only) — all green. It composes directly on v1 (the
signature check *is* v1) and is the unit a Terminal reads off the tap. See `SPEC.md` sec.7.

## What "next" looks like (v3 — NFC transport)

The envelope (v2) now has to actually cross the air. v3 pins how two independent stacks
physically exchange it over NFC, so a third party's reader can read your offerer's tap:

- **Spec:** the HCE AID (`F0 49 44 44 52 4F 50` = "IDDROP"), the SELECT-by-DF-name APDU
  (`00 A4 04 00 <Lc> <AID>`), the response framing (offer JSON bytes + `90 00`), and the
  unknown-AID status (`6A 82`).
- **Vectors:** APDU byte-strings (hex) → expected response shape (is-select? payload? SW).
- **Verifier:** given a SELECT APDU + an offer, assemble/parse the response exactly as the
  reference `NfcOfferService` does — byte-for-byte.

This is the first level whose "transport" is bytes-on-the-wire rather than a JSON field, so
the vectors become hex APDUs. Still runnable, still no vendor.

## Why this order

Roots (jis identity / tibet intent) → leaf (VINK) → container → wire → name-binding →
freshness → ceremony → machine lane → general profiles. Each level only depends on the
ones above it, so a newcomer can stop at any depth and still have something that
interoperates. The deepest level (v8) is the
generalization across humans, AI, and IoT — the "common problem space" worth converging on
with peers.
