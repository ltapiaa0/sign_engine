# 10 — Command line program (`sign.bend`)

## Contract

Compiled binaries produced by Bend take no arguments, so the program works on
fixed file names in the current working directory.

| File | Direction | Content |
|---|---|---|
| `input.pdf` | in | Document to sign (< 16 MiB). |
| `key.pem` | in | RSA private key: PKCS#1 or unencrypted PKCS#8, PEM or DER. |
| `cert.pem` | in | Signer certificate, PEM or DER. A PEM file may contain the chain (signer first). |
| `params.txt` | in, optional | Signature parameters (below). |
| `output.pdf` | out | Signed document, written only on success. |
| `error.txt` | out | UTF-8 error message, written only on failure. |

A missing or unreadable input file is read as empty and reported by the
corresponding parser (for example `pdf: missing %PDF- header`).

`key.pem` may contain other PEM blocks: the first `RSA PRIVATE KEY` or
`PRIVATE KEY` block is used. `cert.pem` must contain only `CERTIFICATE`
blocks: a file that contains a private key is rejected so that the key can
never be embedded in the signature.

Standard output receives `ok` or `error: <message>`.

## `params.txt`

UTF-8 text, one `key=value` per line. The key and the value are trimmed;
lines without `=` are ignored; the first `=` separates key and value; later
duplicates of a key are ignored.

| Key | Meaning | Default |
|---|---|---|
| `name` | `/Name` of the signature | Subject common name of the certificate |
| `reason` | `/Reason` | omitted |
| `location` | `/Location` | omitted |
| `contact` | `/ContactInfo` | omitted |
| `time` | `/M`, UTC, `YYYYMMDDHHmmSS`; written as `(D:YYYYMMDDHHmmSSZ)` | omitted |
| `sig_size` | Bytes reserved for the CMS in `/Contents`, `1024..262144`; increase it when embedding long certificate chains | `8192` |

The time is supplied by the caller because HVM only exposes a monotonic clock.

## Running

```sh
scripts/build.sh                    # build/sign
cd job && /path/to/build/sign
```

`bend run-c sign.bend` also works but uses the unpatched runtime, which hangs
on documents above about 32 KiB and writes the output at about 0.4 ms per
byte (rule P-21).

## Program structure

`main` reads the four input files with `Main/read_file`, calls
`Signer/sign_pdf` and writes either `output.pdf` (`IO/FS/write_file`) or
`error.txt`, then prints the status line (rule P-12). The value returned by
`main` is `0` on success and `1` on failure, but the process exit status is
`0` in both cases; it is `1` only when the runtime runs out of memory
(`error.txt` then contains `runtime: out of memory`). Callers therefore test
for `output.pdf`.

The reading helpers live in `sign.bend` rather than in a library because of
rule P-22.

| Function | Behavior |
|---|---|
| `Main/read_file(path)` | Opens the file (`IO/FS/open`, mode `"r"`), reads it with `Main/read_chunks`, closes it and returns its bytes; `[]` when it cannot be opened. |
| `Main/read_chunks(fd, chunks)` | Reads `Main/CHUNK` (1 MiB) bytes at a time until a read returns no data, then joins the chunks in file order (`Main/reverse`) and applies `Bytes/from_io` (rules P-5, P-5b). A failed read returns `[]` instead of the data read so far: a prefix of a PDF with incremental updates can end with an earlier complete revision, which must never be signed by accident. |
| `Main/reverse(xs, acc)` | Reverses the list of chunks onto `acc`. |
