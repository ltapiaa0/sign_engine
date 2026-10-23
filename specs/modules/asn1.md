# Module `lib/asn1.bend`

DER encoding and decoding (ITU-T X.690) and PEM armor (RFC 7468).

## Decoding

A decoded element is `(tag, content, raw, rest)`: the identifier octet, the
content octets, the complete encoding (header and content) and the remaining
input.

| Function | Contract |
|---|---|
| `Der/read_len(xs) -> (len, length_octets, rest)` | Short form (`< 0x80`) or long form (`0x8n` followed by `n` big-endian octets, `n ≤ 3`); `length_octets` are the octets as read. |
| `Der/read(xs)` | Reads one element. Empty input yields tag `0`. Truncated input yields the available bytes (no error). |
| `Der/children(content)` | List of `(tag, content, raw)` for the elements of a constructed value. |
| `Der/child(content, i)` | The `i`-th child; tag `0` when it does not exist. `Der/nth` is the list accessor. |
| `Der/int_value(content)` | INTEGER content as unsigned big-endian bytes without leading zeros. |

Only single-octet tags are supported (all tags used by X.509 and CMS fields
read by this project are single-octet). Indefinite lengths (BER) are not
supported.

## Encoding

| Function | Result |
|---|---|
| `Der/len_bytes(n)` | Minimal length octets for `n < 2^24`. |
| `Der/tlv(tag, content)` | `tag ‖ length ‖ content`. |
| `Der/seq(items)` | SEQUENCE (`30`) of the concatenated items. |
| `Der/set(items)` | SET OF (`31`) with items sorted by their encodings, as DER requires. |
| `Der/int(bs)` | INTEGER from unsigned big-endian bytes: leading zeros removed, `00` prepended when the top bit is set, `02 01 00` for zero. |
| `Der/octet_string(bs)` | OCTET STRING (`04`). |
| `Der/null` | `05 00`. |
| `Der/oid(content)` | OBJECT IDENTIFIER (`06`) from already encoded sub-identifiers. |
| `Der/ctx(n, content)` | Constructed context-specific tag `[n]` (`A0 | n`). |

## PEM

| Function | Contract |
|---|---|
| `Pem/decode_all(xs) -> List((label, der))` | Every `-----BEGIN <label>-----` / `-----END <label>-----` block, base64-decoded, in order, with its label (for example `CERTIFICATE`, `PRIVATE KEY`). Lines containing `:` inside a block (RFC 1421 headers) are skipped. Input without `-----BEGIN` is treated as a single DER value with an empty label. |
| `Pem/is_label(label, name)` | `1` if the label equals the literal `name`. |

`Pem/blocks` is the line-by-line state machine, `Pem/label` extracts the label
from a `BEGIN` line and `Pem/reverse` reverses the collected base64 lines.
Callers select blocks by label (see [x509.md](x509.md)); no function returns
"the first block" regardless of its type.

## Tests

`der_len`, `der_int_pad`, `der_int_zero`, `der_read`, `pem` in `test.bend`;
CMS output validated by `openssl cms -verify`, `pdfsig` and the Bend verifier
in every end-to-end test.
