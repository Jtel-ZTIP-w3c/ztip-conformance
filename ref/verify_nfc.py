#!/usr/bin/env python3
"""ZTIP conformance — independent NFC-transport VERIFIER (primitive v3).

Second implementation: reads vectors/nfc_v3.json and, for each APDU, reproduces the
offerer's response framing per SPEC.md sec.8 — a SELECT-by-DF-name of OUR AID answers with
the offer + SW 9000; anything else answers SW 6A82. Green = the wire framing interops.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, "..", "vectors", "nfc_v3.json")
GREEN, RED, DIM, RST = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def respond(apdu_hex, aid, select_hdr, sw_ok, sw_unknown):
    """Reproduce the offerer: (select_for_aid, status_word, has_payload)."""
    b = bytes.fromhex(apdu_hex)
    hdr = bytes.fromhex(select_hdr)
    if len(b) < len(hdr) + 1:                 # need at least header + Lc
        return (False, sw_unknown, False)
    if b[:len(hdr)] != hdr:                    # not a SELECT-by-DF-name
        return (False, sw_unknown, False)
    lc = b[len(hdr)]
    data = b[len(hdr) + 1: len(hdr) + 1 + lc]
    if data != bytes.fromhex(aid):            # SELECT, but not OUR AID
        return (False, sw_unknown, False)
    return (True, sw_ok, True)                # SELECT of our AID -> offer + 9000


def main():
    with open(VEC) as f:
        doc = json.load(f)
    aid, hdr = doc["aid"], doc["select_header"]
    sw_ok, sw_unk = doc["sw_ok"], doc["sw_unknown"]
    print(f"ZTIP conformance — verifying {doc['primitive']} v{doc['version']} (AID={aid})")

    all_ok = True
    for c in doc["cases"]:
        sel, sw, pay = respond(c["apdu"], aid, hdr, sw_ok, sw_unk)
        e = c["expect"]
        passed = (sel == e["select_for_aid"] and sw.lower() == e["sw"].lower() and pay == e["payload"])
        all_ok = all_ok and passed
        mark = f"{GREEN}PASS{RST}" if passed else f"{RED}FAIL{RST}"
        print(f"  [{mark}] {c['name']:18s} {DIM}sw={sw} payload={str(pay).lower()} (expect sw={e['sw']}){RST}")

    print()
    if all_ok:
        print(f"{GREEN}YES IT PLAYS — NFC framing interops, no vendor needed.{RST}")
        return 0
    print(f"{RED}interop broken — APDU framing disagrees. Fix the spec.{RST}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
