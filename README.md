# sign_engine

A PDF digital signature engine written entirely in [Bend](https://bend-lang.com/):
reusable Bend libraries (bytes, SHA-256, big integers, RSA, ASN.1/DER, X.509,
CMS, DEFLATE, PDF, JSON, HTTP), a command line signer, an HTTP service and a
signature validator, all compiled to native code through HVM.

Signatures are **PAdES B-B** (`/SubFilter /ETSI.CAdES.detached`, RSA PKCS#1
v1.5, SHA-256) added through an incremental update. They validate in
poppler's `pdfsig`, in `openssl cms -verify` and in the Bend validator:

```
signature 1: ok, covers a revision of 19408 bytes, later updates only add signatures, signer E2E Test 1024
signature 2: ok, covers the whole file, signer E2E Test 1024
pdfsig, openssl and verify: 2 valid signature(s)
```

The design is documented in [`specs/`](specs/README.md), which is the source
of truth for behavior; source files intentionally carry no comments.

## Layout

```
lib/          Bend libraries (bytes, text, sha256, bigint, rsa, asn1, x509, cms, inflate, pdf,
              signer, json, http, clock, service, verify, mkpdf)
sign.bend     command line signer
server.bend   HTTP service (one request per process, behind socket activation)
verify.bend   signature validator used by the tests
mkpdf.bend    generator of large test documents
test.bend     unit tests
scripts/      build (Bend -> C -> runtime patch -> gcc) and local server
deploy/       systemd socket and service units, tmpfiles rule, configuration template
tests/        fixtures, validation, end-to-end and service tests (shell)
specs/        software design specification
```

## Requirements

- `cargo install hvm bend-lang` (tested with bend-lang 0.2.38 and hvm 2.0.22), gcc, GNU patch
- systemd for the service (`systemd-socket-activate` for local runs)
- For tests: OpenSSL, `pdfsig` (poppler-utils), curl, optionally qpdf

## Command line

```sh
scripts/build.sh                          # build/sign (patched HVM runtime, see specs/01)

mkdir job && cd job
cp document.pdf input.pdf && cp signer-key.pem key.pem && cp signer-cert.pem cert.pem
printf 'reason=Approval\nlocation=Santiago\ntime=20261023120000\n' > params.txt
../build/sign                             # writes output.pdf, or error.txt on failure
```

## HTTP service

Bend has no sockets, so the service follows the inetd model: systemd (or
`systemd-socket-activate` locally) accepts each connection and runs
`build/server` with the connection as standard input and output. Everything
else (HTTP, JSON, authentication, signing) happens in Bend.

```sh
scripts/build.sh server.bend
mkdir srv && cd srv && mkdir jobs
cp ../deploy/server.conf.example server.conf      # set token, key, cert
../scripts/serve.sh 127.0.0.1:8080

curl -s -X POST localhost:8080/api/v1/sign \
  -H 'Authorization: Bearer change-me' \
  -H 'Content-Type: application/json' -H 'Accept: application/pdf' \
  -d "{\"pdf\": \"$(base64 -w0 document.pdf)\", \"reason\": \"Approval\"}" \
  -o signed.pdf
```

For production, install `deploy/sign-engine.socket`, `deploy/sign-engine@.service`
and `deploy/sign-engine.tmpfiles`. See [specs/10-cli.md](specs/10-cli.md) and
[specs/11-http-service.md](specs/11-http-service.md) for the full contracts.

## Tests

```sh
bend run-rs test.bend                       # unit tests, expected: (95, [])
tests/e2e.sh                                # sign + validate every fixture (RSA-1024)
KEY_BITS=2048 tests/e2e.sh                  # same with RSA-2048
LARGE=1 tests/e2e.sh                        # also signs a generated 540 KB PDF
LARGE=1 LARGE_PAGES=750 tests/e2e.sh        # ... or a 6.7 MB one
tests/service.sh                            # HTTP service against the built server
tests/validate.sh signed.pdf root-cert.pem  # validate any signed PDF
```

## Limitations

Unencrypted documents and keys, RSA only, invisible signatures, no
timestamps or long-term validation data; documents certified with DocMDP
level 1 are refused. With RSA-2048, in the development container, a 2 KB
PDF takes about 73 s, a 640 KB PDF about 100 s and an 8 MB PDF about
8.5 minutes; the service accepts documents up to 8 MiB by default
(`max_pdf`). Each signing process can use up to about 4.5 GiB of memory (see
[specs/13-performance.md](specs/13-performance.md)).
