#!/usr/bin/env sh
set -e
cd "$(dirname "$0")"
python3 ref/generate.py
echo
python3 ref/verify.py
