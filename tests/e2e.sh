#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${SIGN_BIN:-$ROOT/build/sign}"
KEY_BITS="${KEY_BITS:-1024}"
[ -x "$BIN" ] || "$ROOT/scripts/build.sh" > /dev/null
[ -x "$ROOT/build/verify" ] || "$ROOT/scripts/build.sh" verify.bend > /dev/null
[ -x "$ROOT/build/mkpdf" ] || "$ROOT/scripts/build.sh" mkpdf.bend > /dev/null

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
openssl req -x509 -newkey "rsa:$KEY_BITS" -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
  -days 30 -subj "/C=CL/O=sign_engine/CN=E2E Test $KEY_BITS" 2>/dev/null

fail=0
sign() {
  local job="$WORK/job-$RANDOM$RANDOM"
  mkdir -p "$job"
  cp "$1" "$job/input.pdf"
  cp "$WORK/key.pem" "$job/key.pem"
  cp "${CERT_FILE:-$WORK/cert.pem}" "$job/cert.pem"
  printf 'reason=%s\nlocation=Santiago, Chile\ntime=20261023120000\n' "$3" > "$job/params.txt"
  (cd "$job" && "$BIN" > /dev/null)
  if [ -f "$job/output.pdf" ]; then
    cp "$job/output.pdf" "$2"
  else
    cat "$job/error.txt" > "$WORK/last_error.txt" 2>/dev/null || echo "no output" > "$WORK/last_error.txt"
    return 1
  fi
}
check() {
  if "$ROOT/tests/validate.sh" "$1" "$WORK/cert.pem" > "$WORK/val.log" 2>&1; then
    echo "PASS  $2"
  else
    echo "FAIL  $2"; sed 's/^/      /' "$WORK/val.log" | tail -15; fail=1
  fi
}
expect_error() {
  if sign "$1" "$WORK/unexpected.pdf" "$2"; then
    echo "FAIL  $2: signing should have failed"; fail=1
  elif grep -q "$3" "$WORK/last_error.txt"; then
    echo "PASS  $2: rejected ($(cat "$WORK/last_error.txt"))"
  else
    echo "FAIL  $2: unexpected error $(cat "$WORK/last_error.txt")"; fail=1
  fi
}

for f in "$ROOT"/tests/fixtures/*.pdf; do
  name="$(basename "$f" .pdf)"
  if sign "$f" "$WORK/$name-1.pdf" "First signature"; then
    check "$WORK/$name-1.pdf" "$name: one signature"
  else
    echo "FAIL  $name: could not sign ($(cat "$WORK/last_error.txt"))"; fail=1
  fi
done

for name in classic forms hybrid objstm; do
  [ -f "$WORK/$name-1.pdf" ] || continue
  if sign "$WORK/$name-1.pdf" "$WORK/$name-2.pdf" "Second signature"; then
    check "$WORK/$name-2.pdf" "$name: two signatures"
  else
    echo "FAIL  $name: could not sign a second time ($(cat "$WORK/last_error.txt"))"; fail=1
  fi
done

if [ -f "$WORK/classic-2.pdf" ] && sign "$WORK/classic-2.pdf" "$WORK/classic-3.pdf" "Third signature"; then
  check "$WORK/classic-3.pdf" "classic: three signatures ($(stat -c %s "$WORK/classic-2.pdf") byte input)"
else
  echo "FAIL  classic: could not sign a third time"; fail=1
fi

if sign "$ROOT/tests/fixtures/certified/p2.pdf" "$WORK/certified-p2-signed.pdf" "Approval of a certified document"; then
  check "$WORK/certified-p2-signed.pdf" "certified document (DocMDP P=2) + approval signature"
else
  echo "FAIL  certified document (P=2): could not sign ($(cat "$WORK/last_error.txt"))"; fail=1
fi
expect_error "$ROOT/tests/fixtures/certified/p1.pdf" "certified document (DocMDP P=1)" "does not allow changes"

cat "$WORK/cert.pem" "$WORK/key.pem" > "$WORK/bundle.pem"
CERT_FILE="$WORK/bundle.pem" expect_error "$ROOT/tests/fixtures/classic.pdf" "certificate file containing a private key" "must not contain a private key"

if [ "${LARGE:-0}" = "1" ]; then
  mkdir -p "$WORK/large"
  echo "${LARGE_PAGES:-60}" > "$WORK/large/pages.txt"
  (cd "$WORK/large" && "$ROOT/build/mkpdf" > /dev/null)
  if sign "$WORK/large/large.pdf" "$WORK/large-1.pdf" "Large document"; then
    check "$WORK/large-1.pdf" "large: one signature ($(stat -c %s "$WORK/large/large.pdf") bytes)"
  else
    echo "FAIL  large: could not sign ($(cat "$WORK/last_error.txt"))"; fail=1
  fi
fi

exit $fail
