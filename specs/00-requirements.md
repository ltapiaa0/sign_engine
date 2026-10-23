# 00 — Requirements

## 1. Purpose

`sign_engine` adds digital signatures to PDF documents. It is written
entirely in Bend: reusable libraries (bytes, hashing, big integers, RSA,
ASN.1, X.509, CMS, DEFLATE, PDF, JSON, HTTP), a command line program, an
HTTP service that exposes the signing operation to web clients, and a
signature validator used by the tests.

## 2. Scope

In scope:

- PAdES baseline B-B signatures (ETSI EN 319 142-1) with
  `/SubFilter /ETSI.CAdES.detached`, SHA-256 and RSA PKCS#1 v1.5.
- Invisible signature fields added through a PDF incremental update.
- RSA private keys and X.509 certificates provided by the operator.
- A web API to submit documents and retrieve signed documents.

Out of scope (see [Future work](#7-future-work)): visible signature
appearances, timestamps (B-T), long-term validation data (B-LT/B-LTA),
certification (DocMDP) signatures, ECDSA, signature validation, encrypted
PDFs, encrypted private keys, HSM integration.

## 3. Glossary

| Term | Meaning |
|---|---|
| Bend / HVM | Bend is a high-level functional language compiled to HVM 2, a parallel interaction-net runtime (C, Rust and CUDA backends). |
| u24 | The only integer type available in Bend: unsigned 24-bit, arithmetic wraps modulo 2^24. |
| Interaction | The unit of work of HVM (one graph rewrite). Costs in this project are measured in interactions. |
| Limb | One digit of a big integer; here 12 bits. |
| CMS | Cryptographic Message Syntax (RFC 5652). |
| CAdES | CMS Advanced Electronic Signatures (ETSI EN 319 122). |
| PAdES | PDF Advanced Electronic Signatures (ETSI EN 319 142). |
| xref | PDF cross-reference data mapping object numbers to file offsets: a classic table (`xref` keyword), a cross-reference stream (`/Type /XRef`) or both (hybrid file, `/XRefStm`). |
| Object stream | A compressed stream (`/Type /ObjStm`) containing several PDF objects. |
| Incremental update | Data appended to a PDF (new and replaced objects, a new xref section and trailer) that leaves the previous bytes untouched. |
| ByteRange | The two byte ranges of the file covered by the signature: everything except the hexadecimal `/Contents` value. |
| CRT | Chinese Remainder Theorem, used to compute the RSA private operation modulo `p` and `q`. |
| CIOS | Coarsely Integrated Operand Scanning, a Montgomery multiplication algorithm. |

## 4. Functional requirements

| ID | Requirement | Acceptance criteria |
|---|---|---|
| FR-1 | Sign a PDF producing a PAdES B-B signature: CMS `SignedData`, detached, SHA-256 digest, RSA PKCS#1 v1.5, signed attributes `contentType`, `messageDigest` and `signingCertificateV2`, signer certificate embedded. | `pdfsig` reports `Signature is Valid`; `openssl cms -verify` verifies the CMS against the signed ranges, also with the signer certificate as the only trusted root; the Bend verifier accepts the CMS structure and attributes ([12-testing.md](12-testing.md#3-validation-testsvalidatesh-pdf-rootpem---no-trust)). |
| FR-2 | The signature covers the whole file except the `/Contents` hexadecimal string. | `/ByteRange [0 a b c]` with `a` = offset of `<`, `b` = offset after `>`, `b + c` = file length; the Bend verifier checks that the gap is exactly `/Contents` and that the newest signature covers the whole file. |
| FR-3 | Signing is an incremental update: the input bytes are an unchanged prefix of the output. Previous signatures stay valid and the update only adds a signature field. | For documents already signed, every earlier signature still validates and the Bend verifier's update analysis accepts every later update: only signature dictionaries, signature widgets and cross-reference streams are added, and only the catalog's `/AcroForm` and the pages' `/Annots` change. |
| FR-4 | Read PDF files with classic xref tables, cross-reference streams, hybrid files (`/XRefStm`), compressed object streams (FlateDecode with or without PNG predictors), linearized files and chains of incremental updates (`/Prev`). | The fixtures `classic`, `objstm`, `hybrid`, `linear` and `forms` are signed and validated once, all but `linear` twice, and `classic` three times (an input above 32 KiB). |
| FR-5 | Add the new field without breaking existing forms: keep existing `/AcroForm` entries and fields, existing page annotations and their indirect/direct structure. | `forms` fixture (indirect `/AcroForm`, indirect `/Fields`, indirect `/Annots`, an existing text field) validates after one and two signatures, including the update analysis. |
| FR-6 | Accept RSA private keys as PKCS#1 (`RSA PRIVATE KEY`) or unencrypted PKCS#8 (`PRIVATE KEY`), PEM or DER, selecting the key block by label. Accept certificates as PEM or DER; a PEM file may contain a chain, signer first. Reject a certificate file that contains a private key. | Unit tests `pem_*`; end-to-end test "certificate file containing a private key". |
| FR-7 | Reject a private key that does not match the certificate, and never output a signature that does not verify with the certificate's public key. | Error `signer: private key does not match the certificate`; `Rsa/sign_hash_checked` verifies before returning. |
| FR-8 | Signature dictionary metadata: `/Name` (default: certificate subject common name), `/Reason`, `/Location`, `/ContactInfo` from UTF-8 input, `/M` from a caller supplied UTC time (the service supplies the current time). | Unit test `pdf_text_utf16`; `tests/service.sh` checks the UTF-16 encoding of a non-ASCII `/Location`; `pdfsig` shows the signing time. |
| FR-9 | Command line program operating on fixed file names in the working directory (see [10-cli.md](10-cli.md)). | `tests/e2e.sh`. |
| FR-10 | HTTP service with synchronous and asynchronous signing, a web form, bearer token authentication and a server-held signing key, written in Bend (see [11-http-service.md](11-http-service.md)). | `tests/service.sh`. |
| FR-11 | Report failures as human readable messages without producing an output file. | `error.txt` (CLI) and HTTP 422 with `{"error": ...}` (service). |
| FR-12 | Respect certification signatures: refuse to sign documents certified with DocMDP level 1 (no changes); sign documents with levels 2 and 3 without invalidating the certification. | End-to-end tests with the fixtures `certified/p1.pdf` (rejected) and `certified/p2.pdf` (both signatures validate; the verifier checks the DocMDP level against the later update). |

## 5. Non-functional requirements

| ID | Requirement |
|---|---|
| NFR-1 | All program logic is implemented in Bend: document processing, cryptography, the HTTP protocol, JSON, request validation and signature validation. Other code is limited to a patch to the generated C runtime and shell scripts that build, run and test the programs; external programs only accept connections (systemd) and act as independent validators in tests (OpenSSL, `pdfsig`, `qpdf`, `curl`). |
| NFR-2 | Supported input size: PDF files below 2^24 bytes minus the reserved signature space (positions are `u24`); larger inputs are rejected before analysis. Processing time grows linearly with the document size (about 1 150 interactions per input byte plus the RSA operation) and so does peak memory (about 26 nodes per input byte); the default build signs documents of 8 MB within the default service timeout, and the service refuses documents above `SIGN_MAX_PDF` (8 MiB by default). See [13-performance.md](13-performance.md). |
| NFR-3 | Determinism: for the same document, key, certificate and parameters (including the time) the output is byte-for-byte identical. |
| NFR-4 | Key hygiene and access control: the service keeps the signing key on the server by default, requires a bearer token, rejects foreign `Host` and `Origin` headers, keeps documents only in memory for synchronous requests, stores job results under unguessable ids in a private directory that is cleaned up after one day, runs sandboxed with bounded concurrency, memory and time, and never logs request bodies. |
| NFR-5 | Fault safety: the RSA-CRT result is verified with the public key before use (protects against fault attacks that would leak the key). |
| NFR-6 | Toolchain: Linux, gcc, GNU patch, `bend-lang 0.2.38`, `hvm 2.0.22`; systemd for the service (`systemd-socket-activate` for local runs); tests additionally need OpenSSL, `pdfsig` (poppler-utils), `curl` and optionally `qpdf`. |
| NFR-7 | Performance is documented, not guaranteed: see [13-performance.md](13-performance.md). |
| NFR-8 | Source files contain no comments; all explanations live in these specs. All code, messages and documentation are in English. |

## 6. Constraints

- Bend has no sockets and compiled binaries take no command line arguments,
  hence the fixed-file CLI contract, the per-connection server behind socket
  activation and configuration files instead of arguments.
- Bend has only 24-bit integers (see [02-platform.md](02-platform.md)).
- The modular exponentiation is not constant time at the instruction level;
  the fixed 4-bit window keeps the sequence of multiplications independent of
  the exponent bits, but HVM gives no timing guarantees.

## 7. Future work

- Visible signatures (`/AP` appearance stream with text and image).
- RFC 3161 timestamps (PAdES B-T) and DSS/VRI data (B-LT, B-LTA).
- Remote/HSM signing using the two-step CMS API (`Cms/to_be_signed` then
  `Cms/assemble`).
- ECDSA P-256.
- Signature validation as a product feature: `lib/verify.bend` already
  validates the signatures this engine produces (test use only today);
  certificate chains, revocation and timestamps are not checked.
- Filling an existing empty signature field instead of always creating one.
- Evaluating field locks (`/Lock`) of existing signatures.
