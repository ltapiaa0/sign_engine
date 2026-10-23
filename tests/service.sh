#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-8765}"
URL="http://127.0.0.1:$PORT"
[ -x "$ROOT/build/server" ] || "$ROOT/scripts/build.sh" server.bend > /dev/null

W="$(mktemp -d)"
openssl req -x509 -newkey rsa:1024 -nodes -keyout "$W/key.pem" -out "$W/cert.pem" -days 3 \
  -subj "/CN=Service Test" 2>/dev/null
printf 'token=secret\nkey=key.pem\ncert=cert.pem\nallowed_hosts=127.0.0.1:%s\nmax_pdf=1000000\n' "$PORT" > "$W/server.conf"
mkdir "$W/jobs"
(cd "$W" && exec systemd-socket-activate --inetd --accept --listen="127.0.0.1:$PORT" "$ROOT/build/server") \
  > "$W/activate.log" 2> "$W/server.log" &
SERVER=$!
trap 'kill "$SERVER" 2>/dev/null || true; rm -rf "$W"' EXIT
for _ in $(seq 1 50); do
  curl -s -o /dev/null "$URL/health" && break
  sleep 0.2
done

J='Content-Type: application/json'
A='Authorization: Bearer secret'
fail=0
expect() {
  if [ "$2" = "$3" ]; then
    echo "PASS  $1"
  else
    echo "FAIL  $1: expected $2, got $3"; fail=1
  fi
}
status() { curl -s -o "$W/body" -w '%{http_code}' "$@"; }
b64() { base64 -w0 "$1"; }

expect "health" 200 "$(status "$URL/health")"
expect "health reports the server key" 1 "$(grep -c '"server_key": true' "$W/body")"
expect "form" 200 "$(status "$URL/")"
expect "missing token" 401 "$(status -X POST "$URL/api/v1/sign" -H "$J" -d '{}')"
expect "foreign Host" 403 "$(status -H 'Host: evil.example' "$URL/health")"
expect "cross-origin request" 403 "$(status -X POST "$URL/api/v1/jobs" -H "$J" -H "$A" -H 'Origin: http://evil.example' -d '{}')"
expect "non-JSON body" 415 "$(status -X POST "$URL/api/v1/jobs" -H 'Content-Type: text/plain' -H "$A" -d '{}')"
expect "invalid JSON" 400 "$(status -X POST "$URL/api/v1/sign" -H "$J" -H "$A" -d '{x')"
expect "invalid base64" 400 "$(status -X POST "$URL/api/v1/sign" -H "$J" -H "$A" -d '{"pdf": "abc"}')"
expect "unknown path" 404 "$(status "$URL/api/v1/nope" -H "$A")"
expect "unknown method" 405 "$(status -X DELETE "$URL/health")"
expect "unknown job" 404 "$(status "$URL/api/v1/jobs/0123456789abcdef0123456789abcdef" -H "$A")"

{ printf '%%PDF-1.4\n'; head -c 1100000 /dev/zero; } > "$W/big.pdf"
printf '{"pdf": "%s"}' "$(b64 "$W/big.pdf")" > "$W/big.json"
expect "document above max_pdf (with Expect: 100-continue)" 413 \
  "$(status -X POST "$URL/api/v1/sign" -H "$J" -H "$A" --data-binary @"$W/big.json")"

printf '%%PDF-1.4\nno cross-reference data\n' > "$W/broken.pdf"
expect "document the signer rejects" 422 \
  "$(status -X POST "$URL/api/v1/sign" -H "$J" -H "$A" -d "{\"pdf\": \"$(b64 "$W/broken.pdf")\"}")"

expect "synchronous signing, raw PDF" 200 \
  "$(status -X POST "$URL/api/v1/sign" -H "$J" -H "$A" -H 'Accept: application/pdf' \
     -d "{\"pdf\": \"$(b64 "$ROOT/tests/fixtures/classic.pdf")\", \"location\": \"Ñuñoa\"}")"
cp "$W/body" "$W/sync.pdf"
expect "signed PDF validates" 0 "$("$ROOT/tests/validate.sh" "$W/sync.pdf" "$W/cert.pem" > "$W/val1" 2>&1; echo $?)"
expect "location is UTF-16" 1 "$(grep -ac '/Location <FEFF00D1007500F1006F0061>' "$W/sync.pdf")"

expect "synchronous signing, JSON" 200 \
  "$(status -X POST "$URL/api/v1/sign" -H "$J" -H "$A" -d "{\"pdf\": \"$(b64 "$ROOT/tests/fixtures/forms.pdf")\"}")"
sed -e 's/^{"pdf": "//' -e 's/"}$//' "$W/body" | base64 -d > "$W/sync2.pdf"
expect "JSON response validates" 0 "$("$ROOT/tests/validate.sh" "$W/sync2.pdf" "$W/cert.pem" > "$W/val2" 2>&1; echo $?)"

expect "job accepted" 202 \
  "$(status -X POST "$URL/api/v1/jobs" -H "$J" -H "$A" \
     -d "{\"pdf\": \"$(b64 "$ROOT/tests/fixtures/objstm.pdf")\", \"name\": \"Mallory\"}")"
id="$(sed -E 's/.*"id": "([0-9a-f]{32})".*/\1/' "$W/body")"
expect "job PDF while running" 409 "$(status "$URL/api/v1/jobs/$id/pdf" -H "$A")"
for _ in $(seq 1 120); do
  status "$URL/api/v1/jobs/$id" -H "$A" > /dev/null
  grep -q '"status": "running"' "$W/body" || break
  sleep 1
done
expect "job done" 1 "$(grep -c '"status": "done"' "$W/body")"
expect "job PDF" 200 "$(status "$URL/api/v1/jobs/$id/pdf" -H "$A")"
cp "$W/body" "$W/job.pdf"
expect "job PDF validates" 0 "$("$ROOT/tests/validate.sh" "$W/job.pdf" "$W/cert.pem" > "$W/val3" 2>&1; echo $?)"
expect "client name ignored with the server key" 1 "$(grep -c 'signer Service Test' "$W/val3")"

exit $fail
