#!/usr/bin/env sh
set -e
cd "$(dirname "$0")"
echo "### v1 — VINK attestation";         python3 ref/generate.py;         python3 ref/verify.py;         echo
echo "### v2 — offer envelope";           python3 ref/generate_offer.py;   python3 ref/verify_offer.py;   echo
echo "### v3 — NFC transport";            python3 ref/generate_nfc.py;     python3 ref/verify_nfc.py;     echo
echo "### v4 — AINS resolve + key-match"; python3 ref/generate_resolve.py; python3 ref/verify_resolve.py; echo
echo "### v5 — fresh-assurance";          python3 ref/generate_fresh.py;   python3 ref/verify_fresh.py
