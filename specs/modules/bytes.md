# Module `lib/bytes.bend`

Byte list utilities used by every other module.

## Representation

A byte string is a `List(u24)` whose elements are in `0..255`. Positions and
lengths are `u24`. `Bytes/NONE` (`0xFFFFFF`) means "not found".

## API

### Construction and access

| Function | Contract |
|---|---|
| `Bytes/from_io(xs) -> List(u24)` | Masks every element with `0xFF`. Mandatory for data read with `IO/FS` (rule P-5). |
| `Bytes/len(xs) -> u24` | Number of elements. |
| `Bytes/concat(xs, ys)` | `xs ++ ys`. |
| `Bytes/join(xss)` | Concatenation of a list of byte strings. |
| `Bytes/take(xs, n)` / `Bytes/drop(xs, n)` | First `n` elements / all but the first `n` (shorter input is not an error). |
| `Bytes/at(xs, i) -> u24` | Element `i`, `0` when out of range. |
| `Bytes/reverse(xs)` | Reversed list (`Bytes/reverse.go` is the accumulator loop). |
| `Bytes/repeat(b, n)` | `n` copies of `b`. |
| `Bytes/pad_left(xs, n, b)` / `Bytes/pad_right(xs, n, b)` | Pads with `b` up to length `n`; longer inputs are returned unchanged. |
| `Bytes/strip_zeros(xs)` | Removes leading `0` elements. |
| `Bytes/split(xs, n) -> (front, back)` | `take` and `drop` in one pass (rule P-14). |
| `Bytes/measure(xs) -> (n, xs)` | Length and the same list, rebuilt in one pass, for lists that are needed after their length is known (HTTP bodies, PDF objects). |
| `Bytes/pop(xs) -> (head, tail)` | First element (`0` when empty) and the rest. |
| `Bytes/strip_prefix(xs, prefix) -> (ok, rest)` | `(1, xs without prefix)` when `xs` starts with `prefix`, otherwise `(0, xs)` rebuilt without copying. |

### Comparison and search

| Function | Contract |
|---|---|
| `Bytes/equal(xs, ys) -> u24` | `1` if equal element-wise and same length. |
| `Bytes/starts_with(xs, prefix) -> u24` | `1` if `prefix` is a prefix of `xs` (the empty prefix always matches). |
| `Bytes/compare(a, b) -> u24` | Lexicographic order: `0` if `a < b`, `1` if equal, `2` if `a > b`; a proper prefix is smaller. |
| `Bytes/sort(xss)` | Insertion sort of byte strings by `Bytes/compare` (stable). Used for DER `SET OF`. |
| `Bytes/find(xs, needle) -> u24` | Position of the first occurrence, or `Bytes/NONE`. |
| `Bytes/rfind(xs, needle) -> u24` | Position of the last occurrence, or `Bytes/NONE`. |

`Bytes/find` makes one pass over `xs` (`Bytes/find.go`). Only where the
current byte equals the first byte of the needle does it split off
`len(needle)` bytes and compare them; after a mismatch it continues with
those bytes minus the first put back in front of the rest. The cost is one
comparison per position plus `O(len(needle))` per first-byte match, and `xs`
is never copied (rule P-15). The empty needle is found at position `0`.

`Bytes/rfind` reverses `xs` once while counting its length `n`
(`Bytes/reverse_len`), finds the reversed needle at position `p` of the
reversed input and returns `n - p - len(needle)`. Finding the last
`startxref` of a 644 KB file costs about 8 M interactions (484 M with the
earlier window-based search).

### ASCII text and numbers

| Function | Contract |
|---|---|
| `Bytes/from_string(s)` | ASCII bytes of a Bend `String` literal (each character must be `< 0x80`). |
| `Bytes/is_space(c)` | PDF white-space: `00 09 0A 0C 0D 20`. |
| `Bytes/is_digit(c)` | `'0'..'9'`. |
| `Bytes/skip_spaces(xs)` / `Bytes/trim(xs)` | Drop leading white-space / leading and trailing white-space. |
| `Bytes/from_u24(n)` | Decimal ASCII representation, no leading zeros (`0` → `"0"`). |
| `Bytes/from_u24_padded(n, width)` | Decimal, left-padded with `'0'` to `width`. |
| `Bytes/parse_u24(xs) -> (value, digits, rest)` | Parses leading decimal digits; `digits = 0` when `xs` does not start with a digit. Values wrap above 2^24-1. |
| `Bytes/lines(xs)` | Splits on `LF`; every `CR` is dropped; a trailing empty line is not produced. |

### Big-endian integers

| Function | Contract |
|---|---|
| `Bytes/from_uint_be(n, width)` | The low `8·width` bits of `n` as `width` bytes, big-endian. |
| `Bytes/to_uint_be(xs) -> u24` | Big-endian value of up to 3 bytes (longer inputs wrap). |

### Hexadecimal

| Function | Contract |
|---|---|
| `Bytes/to_hex(xs)` / `Bytes/to_hex_upper(xs)` | Two ASCII hex digits per byte, lowercase / uppercase. |
| `Bytes/from_hex(xs)` | Decodes hex digits, ignoring every non-hex character. An odd final digit is completed with `0` (PDF hex string semantics). |
| `Bytes/hex_digit(n)`, `Bytes/hex_digit_upper(n)`, `Bytes/hex_value(c)` | Digit helpers; `hex_value` returns `0xFF` for non-hex characters. |

### Base64 (RFC 4648)

| Function | Contract |
|---|---|
| `Bytes/to_base64(xs)` | Standard alphabet with `=` padding. |
| `Bytes/from_base64(xs)` | Accepts the standard and URL-safe alphabets, ignores characters outside the alphabet (line breaks, spaces) and stops at the first `=`. |
| `Bytes/from_base64_strict(xs) -> (ok, n, bytes)` | Decodes and validates in one pass: only the standard alphabet, length a multiple of 4, `=` only as the last one or two characters. `n` is the number of bytes decoded; `ok = 0` for any other input. |
| `Bytes/b64_char(n)`, `Bytes/b64_value(c)`, `Bytes/b64_std(c)` | Alphabet helpers; `b64_value` returns `0xFE` for `=` and `0xFF` for other characters; `b64_std` is 1 for characters of the standard alphabet. |

`Bytes/from_base64.go(xs, acc, n)` keeps `n < 8` pending bits in `acc`; every
6-bit symbol is appended and a byte is emitted when 8 or more bits are
available.


## Internal helpers

| Function | Purpose |
|---|---|
| `Bytes/reverse_len(xs, acc, n)` | Reverses `xs` and counts its elements in one pass (used by `Bytes/rfind`). |

## Tests

`hex`, `hex_decode`, `base64_enc_*`, `base64_dec_*`, `base64_strict`,
`base64_strict_invalid`, `find`, `rfind`, `find_none`, `measure`, `decimal`,
`parse_u24`, `from_io`, `sort` in `test.bend`.
