#!/usr/bin/env python3
"""ZTIP conformance — NFC TRANSPORT test-vector generator (primitive v3).

The offer (v2) has to cross the air. v3 pins the NFC framing: a reader SELECTs our AID by
DF name; the offerer answers with the offer bytes + SW 9000, or refuses any other command
with SW 6A82. Vectors are APDU hex strings -> expected (select-for-our-AID?, SW, payload?).

The reference Android HCE service (NfcOfferService) checks only the SELECT header, because
the platform already routes by the registered AID (apduservice.xml). A NON-platform
implementation MUST check the AID itself — which is the canonical behaviour specified here.
This is the first level whose "transport" is bytes-on-the-wire (hex APDUs) rather than JSON.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "vectors", "nfc_v3.json")

AID = "f0494444524f50"     # F0 (proprietary) + "IDDROP"
SELECT_HDR = "00a40400"    # SELECT by DF name: CLA=00 INS=A4 P1=04 P2=00
SW_OK, SW_UNKNOWN = "9000", "6a82"


def select_apdu(aid_hex):
    """00 A4 04 00 <Lc> <AID> <Le=00>"""
    lc = len(aid_hex) // 2
    return f"{SELECT_HDR}{lc:02x}{aid_hex}00"


def main():
    cases = [
        {"name": "select-iddrop", "apdu": select_apdu(AID),
         "expect": {"select_for_aid": True, "sw": SW_OK, "payload": True}},
        {"name": "select-other-aid", "apdu": select_apdu("a0000002471001"),
         "expect": {"select_for_aid": False, "sw": SW_UNKNOWN, "payload": False}},
        {"name": "non-select-read", "apdu": "00b0000000",
         "expect": {"select_for_aid": False, "sw": SW_UNKNOWN, "payload": False}},
        {"name": "too-short", "apdu": "00a4",
         "expect": {"select_for_aid": False, "sw": SW_UNKNOWN, "payload": False}},
    ]

    print("ZTIP conformance — NFC transport v3")
    print(f'  AID        : {AID}  ("IDDROP")')
    print(f"  SELECT hdr : {SELECT_HDR}")
    for c in cases:
        e = c["expect"]
        print(f"  {'+' if e['select_for_aid'] else '-'} {c['name']:18s} apdu={c['apdu']:30s} -> sw={e['sw']} payload={str(e['payload']).lower()}")

    doc = {
        "primitive": "nfc-transport",
        "version": 3,
        "aid": AID,
        "select_header": SELECT_HDR,
        "sw_ok": SW_OK,
        "sw_unknown": SW_UNKNOWN,
        "note": ("Reference HCE checks only the SELECT header (platform routes by AID); a "
                 "non-platform impl MUST check the AID, as specified here. Payload on success "
                 "is the v2 offer JSON."),
        "cases": cases,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"  wrote {len(cases)} cases -> {os.path.relpath(OUT, os.path.join(HERE, '..'))}")


if __name__ == "__main__":
    main()
