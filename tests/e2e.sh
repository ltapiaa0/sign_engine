#!/usr/bin/env bash
# Pruebas de extremo a extremo: firma cada PDF de tests/fixtures con el
# binario compilado y valida el resultado con pyHanko y pdfsig. Luego firma
# por segunda vez algunos de los resultados (actualizaciones encadenadas).
#
#   tests/e2e.sh                 # llave RSA-1024 temporal (rápido)
#   KEY_BITS=2048 tests/e2e.sh   # llave RSA-2048 (lento, exige confianza)
#
# Requiere: openssl, python3 con pyhanko y pikepdf (pdfsig es opcional).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${SIGN_BIN:-$ROOT/build/sign}"
KEY_BITS="${KEY_BITS:-1024}"
[ -x "$BIN" ] || "$ROOT/scripts/build.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
openssl req -x509 -newkey "rsa:$KEY_BITS" -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
  -days 30 -subj "/C=CL/O=sign_engine/CN=Prueba E2E $KEY_BITS" 2>/dev/null
TRUST=()
[ "$KEY_BITS" -ge 2048 ] || TRUST=(--no-trust)

fail=0
sign() {  # sign <entrada.pdf> <salida.pdf> <motivo>
  local job="$WORK/job-$RANDOM$RANDOM"
  mkdir -p "$job"
  cp "$1" "$job/input.pdf"
  cp "$WORK/key.pem" "$WORK/cert.pem" "$job/"
  printf 'reason=%s\nlocation=Santiago, Chile\ntime=20261023120000\n' "$3" > "$job/params.txt"
  (cd "$job" && "$BIN" > /dev/null)
  if [ -f "$job/output.pdf" ]; then
    cp "$job/output.pdf" "$2"
  else
    echo "  error: $(cat "$job/error.txt" 2>/dev/null)"
    return 1
  fi
}
check() {  # check <pdf> <descripción>
  if python3 "$ROOT/tests/validate.py" "$1" "$WORK/cert.pem" "${TRUST[@]}" > "$WORK/val.log" 2>&1; then
    echo "OK    $2"
  else
    echo "FALLO $2"; sed 's/^/      /' "$WORK/val.log" | grep -v Traceback | tail -15; fail=1
  fi
}

for f in "$ROOT"/tests/fixtures/*.pdf; do
  name="$(basename "$f" .pdf)"
  if sign "$f" "$WORK/$name-1.pdf" "Primera firma"; then
    check "$WORK/$name-1.pdf" "$name: una firma"
  else
    echo "FALLO $name: no se pudo firmar"; fail=1
  fi
done

for name in classic forms objstm; do
  [ -f "$WORK/$name-1.pdf" ] || continue
  if sign "$WORK/$name-1.pdf" "$WORK/$name-2.pdf" "Segunda firma"; then
    check "$WORK/$name-2.pdf" "$name: dos firmas"
  else
    echo "FALLO $name: no se pudo firmar por segunda vez"; fail=1
  fi
done

exit $fail
