# Module `lib/signer.bend`

Orchestrates the signing of a PDF (see the pipeline in
[01-architecture.md](../01-architecture.md#3-signing-pipeline)).

## API

| Function | Contract |
|---|---|
| `Signer/sign_pdf(pdf, key_bytes, cert_bytes, params_text) -> Result(List(u24), String)` | Signed PDF or the first error found. |
| `Signer/parse_params(text) -> List((key, value))` | `key=value` lines (see [10-cli.md](../10-cli.md#paramstxt)). |
| `Signer/param(params, key)` | First value for `key`, or `[]`. |

## Steps of `Signer/sign_pdf`

1. `X509/read_rsa_key(key_bytes)`.
2. `X509/cert_ders(cert_bytes)`: the first certificate is the signer
   (`X509/read_cert_der`), the remaining ones are the chain. Every chain
   element must parse as a certificate (`Signer/valid_chain`), otherwise
   `certificate: invalid certificate in the chain`.
3. `Signer/sign_checked` — parameters: `Signer/sig_size` reads `sig_size` (default
   `Signer/DEFAULT_SIG_SIZE`, 8192). Values outside `1024..262144`
   (`Signer/MAX_SIG_SIZE`) fail with
   `signer: sig_size must be between 1024 and 262144`.
4. Size guard: a document longer than `2^24 - 1 - 65536 - 2·sig_size` bytes
   fails with `pdf: document too large (limit 16 MiB)` before any position is
   computed (`Signer/longer_than`), because positions are `u24` (NFR-2).
5. `Pdf/analyze(pdf)`.
6. `Signer/sign_with`:
   - fails with `signer: private key does not match the certificate` when the
     key modulus differs from the certificate modulus (FR-7);
   - `SigFields` from the parameters, with `name` defaulting to the
     certificate's subject common name;
   - `Pdf/prepare`, SHA-256 of the covered bytes, `Cms/signed_attrs`,
     `Rsa/sign_hash_checked` over `SHA-256(Cms/to_be_signed(attrs))`,
     `Cms/assemble`, `Pdf/finish`.

## Internal helpers

| Function | Purpose |
|---|---|
| `Signer/parse_lines`, `Signer/param.go` | Line loop of `Signer/parse_params`; lookup loop of `Signer/param`. |
| `Signer/or_default(v, d)` | `v`, or `d` when `v` is empty. |
| `Signer/split_certs(certs)` | `(first, rest)` of the certificate list. |
| `Signer/valid_chain(chain)` | `1` when every chain element parses as a certificate. |
| `Signer/sig_size(ps)`, `Signer/longer_than(xs, n)` | Reserved CMS size from the parameters; `1` if `xs` has more than `n` elements. |
| `Signer/sign_checked`, `Signer/sign_with` | Steps 3–6 above. |
