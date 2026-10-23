# 01 — Architecture

## 1. Components

```
 HTTP client ──JSON──▶ service/server.py ──files──▶ build/sign ──▶ output.pdf | error.txt
                         (Python, stdlib)           (sign.bend compiled to C by Bend/HVM)
```

| Component | Language | Responsibility |
|---|---|---|
| `lib/*.bend` | Bend | All parsing, encoding, hashing and cryptography. |
| `sign.bend` | Bend | Program entry point: reads the inputs (`Main/read_file`), calls `Signer/sign_pdf`, writes the result. |
| `build/sign` | C (generated) | Native binary produced by `scripts/build.sh` (`bend gen-c`, runtime patches, `gcc`). |
| `service/server.py` | Python | HTTP transport: validation, per-request working directory, process execution, job tracking. |
| `tests/` | Python, shell | Fixture generation, unit test generation, end-to-end validation. |

## 2. Module dependencies

Bend resolves `from lib/x import *` relative to the directory of the main
file, so every program (`sign.bend`, `test.bend`) lives in the repository
root and every library imports its dependencies with `lib/...` paths.

```
sign.bend ──▶ bytes
    └──────▶ signer ──▶ pdf ──▶ inflate ──▶ bytes
                │        └────▶ text ──▶ bytes
                ├────▶ cms ──▶ x509 ──▶ rsa ──▶ bigint ──▶ bytes
                │       │       ├─────▶ asn1 ──▶ bytes
                │       │       └─────▶ text
                │       ├────▶ sha256 ──▶ bytes
                │       └────▶ asn1
                └────▶ x509, rsa, asn1, sha256, bytes
```

| Module | Imports |
|---|---|
| `bytes` | — |
| `text` | `bytes` |
| `sha256` | `bytes` |
| `bigint` | `bytes` |
| `rsa` | `bytes`, `bigint` |
| `asn1` | `bytes` |
| `x509` | `bytes`, `text`, `asn1`, `rsa` |
| `cms` | `bytes`, `asn1`, `sha256`, `x509` |
| `inflate` | `bytes` |
| `pdf` | `bytes`, `text`, `inflate` |
| `signer` | `bytes`, `sha256`, `rsa`, `asn1`, `x509`, `cms`, `pdf` |
| `sign.bend` (program) | `bytes`, `signer` |
| `test.bend` (program) | every library except `signer` |

## 3. Signing pipeline

`Signer/sign_pdf(pdf, key, certs, params)` performs:

1. **Credentials.** `X509/read_rsa_key` parses the private key.
   `X509/cert_ders` returns the certificates of the certificate file and
   rejects files that contain a private key; the first certificate is the
   signer (`X509/read_cert_der`) and the rest form the chain, each of which
   must parse as a certificate.
2. **Document analysis.** `Pdf/analyze` finds `startxref`, loads every xref
   section reachable through `/Prev` and `/XRefStm` into one object map,
   resolves the catalog and the first page.
3. **Layout.** `Pdf/prepare` builds the incremental update twice: first with
   a placeholder `/ByteRange` of fixed width to learn the offsets, then with
   the final `/ByteRange`. Both builds have identical length by construction.
4. **Digest.** SHA-256 over `pdf ++ A ++ C`, where `A` is the update up to
   the `<` that opens `/Contents` and `C` the rest after the closing `>`.
5. **Signed attributes.** `Cms/signed_attrs(digest, cert)`; the bytes to sign
   are their DER `SET OF` encoding (`Cms/to_be_signed`).
6. **RSA.** `Rsa/sign_hash_checked` signs `SHA-256(to_be_signed)` with
   PKCS#1 v1.5 using CRT and verifies the result with the public key.
7. **CMS.** `Cms/assemble` builds the `ContentInfo`/`SignedData`.
8. **Output.** `Pdf/finish` writes the CMS as uppercase hexadecimal, padded
   with `0` to the reserved size, between `<` and `>`.

```
input.pdf ─┬─────────────────────────────────────────────────────────┐
           ▼                                                         │
     Pdf/analyze ──▶ Pdf/prepare ──▶ (A, C) ──▶ SHA-256(pdf++A++C)   │
                                         │            │              │
key.pem ──▶ X509/read_rsa_key            │   Cms/signed_attrs        │
cert.pem ─▶ X509/cert_ders ──────────────┼────────────┤              │
                                         │   Rsa/sign_hash_checked   │
                                         │            │              │
                                         │      Cms/assemble         │
                                         ▼            ▼              ▼
                                   Pdf/finish(pdf, A, C, cms) ──▶ output.pdf
```

## 4. Data model

- Binary data is `List(u24)` with values `0..255` ("bytes").
- Text from the outside world is UTF-8 bytes; Bend `String` values are only
  used for literals and error messages.
- Errors are `Result/Err(String)`; success values are `Result/Ok(value)`.
- Composite records use single-constructor `type`s (`RsaKey`, `CertInfo`,
  `PdfInfo`, `SigFields`) because `object` declarations break the Bend 0.2.38
  compiler when imported transitively (see [02-platform.md](02-platform.md)).

## 5. Runtime and build

- `scripts/build.sh [program.bend]` (default `sign.bend`) runs `bend gen-c`,
  patches the generated HVM runtime (below) and compiles it to
  `build/<program>` with `gcc -O2 -DTPC_L2=$TPC_L2`.
- `TPC_L2` (default 0) sets `2^TPC_L2` worker threads. The node and variable
  buffers are split evenly between the threads and each thread allocates only
  from its own share; with `TPC_L2=2` and the default buffers one thread ran
  out of memory while signing a 2 KB document. Only the single-thread build
  is tested; more threads need proportionally larger buffers (`MEM_L2`).
- Runtime patches. Each pattern must occur the expected number of times in
  the generated source or the build fails, so a different `hvm` version is
  detected instead of silently producing an unpatched binary.

| Patch | Reason |
|---|---|
| `HLEN` (high-priority redex bag per thread) from `2^16` to `2^25` | Erasing a list of `n` elements needs about `2n` slots; with `2^16` the runtime retried forever on any input above about 32 KiB. |
| `G_NODE_LEN` from `2^29` to `2^MEM_L2` (default 28) and `G_VARS_LEN` from `2^29` to `2^VARS_L2` (default `MEM_L2 + 1`, at most 29) | The allocator only reuses memory after walking its whole buffer, so resident memory approaches the buffer sizes: nodes take 8 bytes and variables 4, about 4 GiB in total with the defaults (6 GiB unpatched). Copies made by duplicating a list use about two variables per node, so the variable buffer gets twice as many slots. The buffers must hold the live data: about 26 nodes per input byte at the peak ([13-performance.md](13-performance.md#memory)). |
| Variable allocator partition | `vars_alloc` and `vars_alloc_1` computed the variable partition and its out-of-memory bound from `G_NODE_LEN`; they use `G_VARS_LEN`, so the variable buffer can be larger than the node buffer. |
| `ROOT` recomputed from `G_VARS_LEN` | It was fixed at the last slot of a `2^29` buffer. |
| Out of memory exits | The allocator printed `OOM` and kept scanning forever. `hvm_oom` writes `error.txt` (`runtime: out of memory`), prints `error: runtime: out of memory` and exits with status 1. |
| `readback_bytes` normalizes once | Writing a file normalized the whole net once per byte; each normalization starts the worker threads and spins at least 256 `sched_yield` calls per thread before stopping. The net is normalized before the loop and the list is then followed directly. |
| `expand` resolves constant definitions | Reading back an unexpanded reference ran a full normalization. Every cell built by `List/Cons` carries its tag as a reference to the constant definition `List/Cons/tag`, so writing `n` bytes ran `n` normalizations. Definitions without nodes or redexes whose root is a number are now resolved directly. |

The last two patches do not change results: after the initial
normalization no redex is pending, `expand` still normalizes for any other
reference, and calling a definition that has no nodes or redexes only links
its root number to the caller. Their effect on file output is measured in
[13-performance.md](13-performance.md).
- `bend run-c` uses the unpatched runtime of the installed `hvm` and is only
  suitable for small inputs (unit tests).
- HVM can evaluate independent subterms in parallel (for example the two
  RSA-CRT exponentiations), but see the thread note above.

## 6. Deployment

The service is a single Python process (`ThreadingHTTPServer`) that listens
on `127.0.0.1` by default, requires a bearer token and bounds concurrent and
queued signings (see [11-http-service.md](11-http-service.md)). It has no
TLS: it is meant to run behind a reverse proxy that terminates HTTPS.
