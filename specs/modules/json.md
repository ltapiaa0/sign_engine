# Module `lib/json.bend`

JSON (RFC 8259) parsing and encoding for the HTTP service.

## Values

```
type Json:
  Str { bytes }      UTF-8 bytes, escapes decoded
  Num { raw }        the number exactly as written
  Bool { val }       1 or 0
  Null
  Arr { items }      list of Json
  Obj { entries }    list of (key bytes, Json) in document order
```

## Parsing

| Function | Contract |
|---|---|
| `Json/parse(xs) -> (ok, Json)` | Parses one value surrounded by optional white-space (space, tab, LF, CR). `ok = 0` for invalid JSON or trailing data. |
| `Json/value(xs, depth) -> (ok, Json, rest)` | One value; nesting deeper than `Json/MAX_DEPTH` (64) fails. |
| `Json/string(xs) -> (ok, bytes, rest)` | The characters after an opening quote up to the closing one. Control characters (`< 0x20`) are rejected; bytes `>= 0x80` are copied unchanged. |
| `Json/escape(xs)` | `\" \\ \/ \b \f \n \r \t` and `\uXXXX`. A high surrogate followed by `\u` and a low surrogate is combined into one code point; any other surrogate becomes U+FFFD (Python's decoder keeps lone surrogates, which cannot be encoded as UTF-8 later). Code points are written with `Text/utf8_encode`. |
| `Json/number(xs, state)` | Number grammar of RFC 8259 as a state machine (`Json/num_next`, accepting states from `Json/accepting`): optional `-`, `0` or a non-zero digit followed by digits, optional fraction, optional exponent. `01`, `1.` and `-` are rejected. |
| `Json/object(xs, depth)`, `Json/members`, `Json/array`, `Json/items` | Containers; a trailing comma is an error. |

Every step consumes the input list once and passes the rest on (rule
P-14), so parsing a request body of several megabytes is linear and keeps no
copy of the body. Keys are not deduplicated; `Service/split_pdf` and
`Service/lookup` decide which occurrence wins.

## Encoding

| Function | Contract |
|---|---|
| `Json/quote(bytes)` | `"` + content + `"`, escaping `"`, `\`, LF, CR, tab and other control characters (`\u00XX`); UTF-8 bytes are copied unchanged. |
| `Json/member(key, value)` | `"key": value` (`value` is already encoded). |
| `Json/object_text(members)` | `{m1, m2, ...}` with `", "` separators, the format of Python's `json.dumps`. |
| `Json/bool_text(b)` | `true` or `false`. |

## Internal helpers

| Function | Purpose |
|---|---|
| `Json/ws` | Skips white-space. |
| `Json/unescape(c)` | Byte for a one-character escape, `0xFF` if invalid. |
| `Json/hex4(xs, v, n, used)` | Up to four hexadecimal digits; also returns the digits consumed so that `Json/low` can put them back. |
| `Json/low(xs)` | Reads `\uDC00`–`\uDFFF` after a high surrogate, or returns the input unchanged. |
| `Json/reverse`, `Json/members_text`, `Json/quote.go` | List helpers. |

## Tests

`json_parse` (escapes, surrogate pair, nested values), `json_lone_surrogate`,
`json_invalid` (eleven invalid documents), `json_quote`, `json_object_text`.
