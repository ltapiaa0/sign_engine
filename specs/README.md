# sign_engine — Software Design Specification

This directory is the specification of `sign_engine`, a PDF digital signature
engine written in [Bend](https://bend-lang.com/). The specs are the source of
truth for behavior and design: **source files carry no comments**; anything a
reader needs to understand the code is documented here.

## Documents

| Document | Content |
|---|---|
| [00-requirements.md](00-requirements.md) | Scope, functional and non-functional requirements, acceptance criteria |
| [01-architecture.md](01-architecture.md) | Components, module dependencies, signing pipeline, build and runtime model |
| [02-platform.md](02-platform.md) | Bend 0.2 / HVM 2 constraints and the coding rules derived from them |
| [modules/bytes.md](modules/bytes.md) | `lib/bytes.bend` — byte lists, ASCII, hex, base64 |
| [modules/text.md](modules/text.md) | `lib/text.bend` — UTF-8, UTF-16BE, UTF-32BE |
| [modules/sha256.md](modules/sha256.md) | `lib/sha256.bend` — SHA-256 |
| [modules/bigint.md](modules/bigint.md) | `lib/bigint.bend` — arbitrary precision integers, Montgomery arithmetic |
| [modules/rsa.md](modules/rsa.md) | `lib/rsa.bend` — RSA PKCS#1 v1.5 signatures |
| [modules/asn1.md](modules/asn1.md) | `lib/asn1.bend` — DER and PEM |
| [modules/x509.md](modules/x509.md) | `lib/x509.bend` — private keys and certificates |
| [modules/cms.md](modules/cms.md) | `lib/cms.bend` — CMS SignedData with CAdES attributes |
| [modules/inflate.md](modules/inflate.md) | `lib/inflate.bend` — DEFLATE, zlib, PNG predictors |
| [modules/pdf.md](modules/pdf.md) | `lib/pdf.bend` — PDF reading and incremental signature update |
| [modules/signer.md](modules/signer.md) | `lib/signer.bend` — signing orchestration and parameters |
| [10-cli.md](10-cli.md) | `sign.bend` command line program |
| [11-http-service.md](11-http-service.md) | `service/server.py` HTTP API |
| [12-testing.md](12-testing.md) | Unit tests, fixtures, end-to-end validation |
| [13-performance.md](13-performance.md) | Cost model, measurements, optimization history |

## Conventions

- Requirements are identified as `FR-n` (functional) and `NFR-n`
  (non-functional) and referenced from the module specs and tests.
- Byte strings are written in hexadecimal (`30 0d 06 09 ...`); PDF syntax in
  `monospace`.
- "Bytes" always means a Bend `List(u24)` whose elements are in `0..255`.
- Function signatures use Bend notation. Functions whose name ends in `.go`
  or another suffix after a dot are internal helpers of the function with the
  base name.
- A change to behavior starts with a change to the corresponding spec, then
  the code, then the tests listed in [12-testing.md](12-testing.md).
