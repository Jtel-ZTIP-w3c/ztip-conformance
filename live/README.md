# Live capstone — running in production

This directory is **not** part of the offline conformance ladder. The vectors in `../vectors/`
are the contract: reproducible, offline, deterministic, runnable by anyone. This is the
opposite by design — the **witness** that the same logic runs against the real AInternet.

```sh
python3 live/verify_live.py            # resolves root_idd (+ a known-absent name) live
python3 live/verify_live.py echo root_idd vandemeent   # any registered .aint names
```

## What it proves

`verify_live.py` participates in the live network as a verifier: it resolves a **registered
`.aint`** over the **public** name service (`https://api.ainternet.org`) and binds to the live
authority **key** — the same v4 logic (`SPEC.md` §9), but on real infrastructure. It:

- binds by **key**, treating the name as a namespace label (v9: name ≠ identity);
- **normalizes the on-wire encoding** — the public resolve returns the key as **hex**, the
  offline vectors use base64. That is exactly the "#1 key-match breaker" (`SPEC.md` §9),
  encountered and handled in the wild;
- accepts a live, active record and rejects an absent name.

So: the conformance kit isn't only a green JSON — it runs against the real AInternet, against
a registered identity, as a participant. That is the "running in production" proof.

## What it does NOT do (honest scope)

It does **not** verify a *fresh signature* from the resolved `.aint`. That needs the `.aint`'s
own Ed25519 **signer** (private key), which lives on the device/server (e.g. root_idd on the
KIT phone), not in a fresh clone. The live challenge-response handshake (v7) runs **where the
signer lives**; its logic is proven offline in `../vectors/challenge_v7.json`.

Non-deterministic by design (it depends on live network state). This is the witness; the
vectors are the contract.
