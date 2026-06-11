# ZTIP Conformance — VINK Attestation (primitive v1)

A VINK is one anonymous yes/no attribute claim ("18 or older", "valid passport",
"live person", …). A set of VINKs is signed by the holder's Ed25519 key so a verifier
(a Terminal) can check them — **unforgeable, and without revealing identity**. This is
the smallest load-bearing primitive of ZTIP: attestation, not identification.

This document is **byte-precise on purpose**. A second implementation, in any language,
that follows it will interoperate with the reference offerer (Android/KIT, ID-Drop) and
with `ref/verify.py` here — no shared code, no vendor in the loop. That is the whole point.

The normative source of truth is `VinkCanon.canonical` in the Kotlin `:core` module
(`nl.jasper.jtm.iddrop.VinkCanon`). This spec mirrors it exactly, and `vectors/vink_v1.json`
proves it.

---

## 1. A VINK

```
key      : string, ASCII, no '=' and no '|'        e.g. "age_18", "nationality_nld", "live_presence"
granted  : boolean                                  the tick itself
demo     : boolean (default false)                  true = bound to a clearly-labelled DEMO credential
```
A `label` may exist for humans; it is **not** part of the signed form (display only).

## 2. Canonical string (the byte-exact signed form)

Given a list of VINKs, the canonical string is:

1. **Sort** the VINKs by `key`, ascending, byte/codepoint order.
2. For each VINK, emit: `key` + `"="` + (`"1"` if `granted` else `"0"`) + (`"d"` if `demo` else `""`).
3. **Join** the items with a single `"|"` (U+007C).

No spaces, no trailing separator, no surrounding quotes.

```
adult-nl-genuine -> age_18=1|genuine_document=1|nationality_nld=1|valid_document=1
demo-flagged     -> age_18=1d|nationality_nld=1d
minor-denied     -> age_18=0|valid_document=1
```

One byte of difference here changes the signature. Be ruthless: same sort, same `d`
placement (immediately after the digit), same `|`.

## 3. Signing

- Algorithm: **Ed25519** (RFC 8032). No pre-hash; sign the message directly.
- Message: the **UTF-8 bytes** of the canonical string from §2 (canonical is ASCII in
  practice, so UTF-8 == ASCII bytes).
- `signature = Ed25519_sign(private_key, utf8(canonical))` → 64 raw bytes.

## 4. Encodings

- **Public key**: the raw 32-byte Ed25519 public key, **standard base64, padded, no
  line-wrap** (identical to Android `Base64.NO_WRAP`).
- **Signature**: the raw 64-byte signature, same base64.
- This is the encoding `AInternetIdentity.publicKeyBase64` / `signBase64` produce and the
  AINS resolve returns — so a verifier's `resolved_pubkey == offer.sender_pubkey` key-match
  succeeds. **Do not** mix in hex or unpadded/url-safe base64; that is the #1 interop breaker.

## 5. Verification

1. Recompute the canonical string from the raw VINK fields (§2) — **do not trust** a
   canonical handed to you.
2. `Ed25519_verify(public_key, signature, utf8(canonical))`.
3. (In a full offer) check the signer's `public_key` matches the claimed `.aint` via AINS
   resolve, and that the offer's TTL has not expired.

## 6. Test vectors & reproducibility

`vectors/vink_v1.json` contains positive cases and one negative (tamper) case. It is
**regenerable**: `ref/generate.py` derives the key from a fixed seed
(`SHA-256("ztip-conformance/vink-attestation/v1")`), and Ed25519 is deterministic, so
re-running produces a **byte-identical** file. Diff it — no hidden state.

To claim conformance: run your own implementation against `vectors/vink_v1.json`. Every
positive case must verify true, the negative case must verify false, and your recomputed
canonical must equal the vector's `canonical`. Green on all = you interoperate.

---

## 7. Offer envelope (v2)

A VINK set never travels alone — it rides inside an **offer**: outer metadata only, never
the binding identity payload. Fields (from `IdDropOffer`):

```
offer_id      : string
expires_at    : integer, epoch seconds   — TTL is MANDATORY
sender_pubkey : string, base64 Ed25519 public key (sec.4)
claimed_aint  : string                   — e.g. "vandemeent.aint"
claim_class   : string                   — e.g. "age_over_18"
semantic_type : string                   — e.g. "identity"
entity_class  : string (optional)        — "human" | "ai" | "iot" | "ioa"
vinks         : array of VINK (sec.1), default []
vinks_sig     : string|null              — base64 Ed25519 over canonical(vinks) (sec.2-4),
                                           or null when vinks is empty
```
Display-only fields (`display_name`, `preview_hash`, `ssm_class`) may be present and are
not security-relevant.

**TTL:** `expired(now) := now >= expires_at`. A verifier must reject an expired offer.

**Validity at v2** (composes on v1):

```
valid(offer, now) :=
    now < offer.expires_at
    AND ( offer.vinks is empty AND offer.vinks_sig is null         # identity-only
          OR  Ed25519_verify(offer.sender_pubkey,
                             offer.vinks_sig,
                             utf8(canonical(offer.vinks))) )        # == v1
```

Binding the `sender_pubkey` to `claimed_aint` via name resolution is **v4** (out of scope
here): v2 proves you can parse an envelope, enforce its TTL, and verify its embedded
attestation — the unit a Terminal reads off the tap.

Vectors: `vectors/offer_v2.json` carries a fixed `verify_at` (so fresh vs expired is
deterministic) and four cases: fresh-valid, expired-ttl, tampered-sig, identity-only.

---

## 8. NFC transport (v3)

The offer crosses the air over NFC Host Card Emulation. A verifier's reader SELECTs the
offerer's application by DF name; the offerer returns the offer bytes.

- **AID** (application identifier): `F0 49 44 44 52 4F 50` — `F0` (proprietary) + ASCII
  `"IDDROP"`.
- **SELECT** (by DF name): `00 A4 04 00 <Lc> <AID> [Le]` — CLA=`00`, INS=`A4`, P1=`04`,
  P2=`00`, then `Lc` = AID length, the AID bytes, optional `Le`.
- **Response** — a SELECT of our AID: `<offer JSON bytes> 90 00`. Any other command (wrong
  AID, non-SELECT, malformed/too-short): `6A 82` (file/app not found), no payload.

```
respond(apdu) :=
    apdu starts with 00 A4 04 00  AND  apdu data field == AID   →  offer ‖ 9000
    otherwise                                                   →  6A82
```

The reference Android HCE service (`NfcOfferService`) checks only the SELECT header,
because the platform routes APDUs to it by the registered AID (`apduservice.xml`). A
**non-platform** implementation (e.g. a reader, or a non-Android offerer) MUST check the
AID itself — the canonical behaviour above. The offer payload itself is validated by §7
(v2); v3 only pins the framing.

Vectors: `vectors/nfc_v3.json` — hex APDUs → expected `{select_for_aid, sw, payload}`:
select-iddrop, select-other-aid, non-select-read, too-short.

---

## 9. AINS resolve + key-match (v4)

An offer *claims* a `.aint`. A valid signature proves a key; it does **not** prove the key
belongs to that name. v4 is the name→key binding: resolve the `.aint` over AINS, and check
the resolved key against the offer's `sender_pubkey`.

Resolve shape (`GET /api/ains/resolve/<name>`):

```
{ "record": { "public_key": "<base64 Ed25519>", "status": "active" | "revoked" | …,
              "entity_type": "idd" | … } }
```

**Binding rule:**

```
bound(offer) :=
    resolve(offer.claimed_aint) exists
    AND  record.status == "active"
    AND  record.public_key == offer.sender_pubkey
```

A revoked `.aint` resolves to a signed **tombstone** (`status: "revoked"`) — it does not
vanish, and it does not bind. An absent name does not resolve and stays an unbound T-1
candidate.

> **Encoding — the #1 key-match breaker.** `record.public_key` and `offer.sender_pubkey`
> MUST be in the **same** encoding (base64, §4). The match is a direct string compare;
> hex-vs-base64 silently breaks it. If a deployment's resolve returns hex while offers carry
> base64, normalise one side before comparing — but the canonical wire form is base64.

Vectors: `vectors/resolve_v4.json` ships an offline `resolve_fixture` (no live call) and four
cases: key-match-active (binds), key-mismatch (different key), revoked (tombstone),
unresolvable (absent).

---

## 10. Fresh-assurance (v5)

Some VINKs aren't document facts — they're **session** facts proven *right now*:
`live_presence` (a live human, not a photo) and `rightful_holder` (the live face matches the
chip). They carry a short freshness window and are **never persisted**.

This is **RVP's runtime gate** (the control lane — not the offer/composition): honoring a
live attestation only while fresh and **rejecting stale assurance** is *untrusted-until-
renewed* in one check — the bridge between identity (a fresh attestation) and continuous
verification. See INTEROP.md L2 (RVP).

Each session VINK carries `fresh_until` (epoch seconds); it was minted with a `ttl_seconds`
window. The gate:

```
honored(session_vink, now) := now < session_vink.fresh_until
```

This is **independent of** the offer TTL (§7): even inside a still-valid offer, a session
VINK only counts while fresh. When it lapses it drops — the offer's document VINKs
(18+/valid/NL) are unaffected; only the live claim must be re-proven.

> **Why never persisted.** The freshness gate *is* the anti-supercookie enforcement: a
> stored or replayed session VINK arrives after its `fresh_until` and is, by construction,
> stale → rejected. "Fresh biometric at the moment of use, not a saved token." A verifier
> MUST NOT accept a session VINK whose freshness has lapsed, and MUST NOT cache one to
> shortcut a later check.

Vectors: `vectors/fresh_v5.json` carries a fixed `verify_at` and four cases: fresh-live,
expired-live, fresh-rightful, replayed-rightful (presented an hour late → rejected).

---

## 11. Offer-first ceremony (v6)

An identity offer is **never auto-binding**. It enters as a T-1 *candidate* and becomes a
bound T0 truth only after passing every gate, in order:

```
OFFER → REQUEST → ACCEPT → SEAL → VALIDATE → MATERIALIZE
```

- **TTL** (REQUEST): an expired offer is refused before anything else.
- **Consent** (ACCEPT): explicit local accept — there is no auto-accept (Heart-in-the-Loop).
- **Validation** (VALIDATE): AINS/JIS/TIBET trust outcome (byte+semantic+claim+causal).
- **MATERIALIZE**: the candidate becomes bound — and this is the *only* stage where `bound`
  is true.

**Invariant:**

```
bound := (not expired) AND accept AND validate
the ceremony stops at the first failing gate; bound is false at every stage but MATERIALIZE
```

So a stranger's offer can be presented, requested, even sealed — and still bind **nothing**
until a human accepts and the trust checks pass. "Pinning starts after truth exists; genesis
creates the first truth." Mirrors `OfferFirstCeremony.run()` in `:core`.

Vectors: `vectors/ceremony_v6.json` — four cases: happy-path (→ MATERIALIZE, bound),
expired (→ REQUEST), no-consent (→ ACCEPT), validate-fail (→ VALIDATE).
