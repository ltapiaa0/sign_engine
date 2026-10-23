# Module `lib/text.bend`

Unicode conversions between byte encodings and lists of code points
(`List(u24)`).

## API

| Function | Contract |
|---|---|
| `Text/utf8_decode(xs)` | UTF-8 bytes to code points. Lead bytes `< 0xC0` that are not valid UTF-8 (stray continuation bytes, Latin-1 text) are passed through as code points `0x80..0xBF`; missing continuation bytes read as `0`. |
| `Text/utf8_encode(cps)` | Code points to UTF-8 (1 to 4 bytes each). |
| `Text/utf16be_encode(cps)` | Code points to UTF-16BE; code points above U+FFFF become surrogate pairs. |
| `Text/utf16be_decode(xs)` | UTF-16BE to code points, combining surrogate pairs; an unpaired high surrogate becomes U+FFFD; an odd final byte is completed with `0`. |
| `Text/utf32be_decode(xs)` | UTF-32BE to code points. |
| `Text/valid(c)` | `c`, or U+FFFD (`Text/REPLACEMENT`) when `c > 0x10FFFF`. |

Every function that produces code points or encodes them applies
`Text/valid`, so invalid input never produces values outside the Unicode
range.

## Users

- `Pdf/text_string`: UTF-8 parameters to PDF text strings (UTF-16BE).
- `X509/text_utf8`: certificate string types to UTF-8.

## Tests

`pdf_text_utf16`, `text_utf8_roundtrip`, `text_utf16_decode` (including a
4-byte UTF-8 character and its surrogate pair) and `x509_bmp_cn`.
