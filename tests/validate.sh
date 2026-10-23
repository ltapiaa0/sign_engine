#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PDF="$1"
CA="$2"
TRUST=1
[ "${3:-}" = "--no-trust" ] && TRUST=0
[ -x "$ROOT/build/verify" ] || "$ROOT/scripts/build.sh" verify.bend > /dev/null

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
cp "$PDF" "$W/input.pdf"
fail() { echo "$1"; exit 1; }

if command -v qpdf > /dev/null; then
  status=0
  qpdf --check "$W/input.pdf" > "$W/qpdf.txt" 2>&1 || status=$?
  [ "$status" -eq 0 ] || [ "$status" -eq 3 ] || fail "qpdf: $(tail -n 1 "$W/qpdf.txt")"
fi

pdfsig "$W/input.pdf" > "$W/pdfsig.txt" 2>&1 || true
total=$(grep -c "^Signature #" "$W/pdfsig.txt" || true)
valid=$(grep -c "Signature Validation: Signature is Valid." "$W/pdfsig.txt" || true)
[ "$total" -gt 0 ] && [ "$total" -eq "$valid" ] || fail "pdfsig: $valid of $total signature(s) valid"

(cd "$W" && "$ROOT/build/verify" > verify.txt)
sed -n '/^signature /p' "$W/verify.txt"
grep -q "^verify: $total signature(s), ok$" "$W/verify.txt" || fail "$(grep "^verify:" "$W/verify.txt" || echo "verify: no result")"

ca_print="$(openssl x509 -in "$CA" -noout -fingerprint -sha256)"
for k in $(seq 1 "$total"); do
  openssl cms -verify -inform DER -in "$W/sig$k.der" -content "$W/content$k.bin" -binary -noverify \
    -signer "$W/signer$k.pem" -out /dev/null > "$W/cms$k.txt" 2>&1 || fail "openssl: signature $k does not verify"
  if [ "$TRUST" = 1 ] && [ "$(openssl x509 -in "$W/signer$k.pem" -noout -fingerprint -sha256)" = "$ca_print" ]; then
    openssl cms -verify -inform DER -in "$W/sig$k.der" -content "$W/content$k.bin" -binary \
      -CAfile "$CA" -purpose any -out /dev/null > "$W/trust$k.txt" 2>&1 || fail "openssl: signature $k is not trusted by $CA"
  fi
done
echo "pdfsig, openssl and verify: $total valid signature(s)"
