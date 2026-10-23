# Module `lib/http.bend`

HTTP/1.1 request heads and responses (RFC 9110, RFC 9112) for the service.

## Requests

```
type Request:
  New { method, path, headers }
```

| Function | Contract |
|---|---|
| `Http/parse(head) -> (ok, Request)` | `head` is everything up to and including the empty line. The request line must have exactly three space-separated words: method, a target starting with `/`, and a version starting with `HTTP/1.`. `path` is the target without query (`?`) or fragment (`#`). Header lines are `name: value`; names are tokens (no spaces, controls or `:`) and are lowercased; values are trimmed. Folded lines (leading space or tab) and lines without `:` make the request invalid. Parsing stops at the first empty line. |
| `Http/header(headers, name) -> (count, value)` | Number of headers called `name` (lowercase) and the value of one of them; callers reject duplicates where it matters. |
| `Http/content_length(value) -> (status, n)` | `status` 0 with the value, 1 for a missing or non-decimal value, 2 for values above `2^24 - 1` (detected while parsing, so values never wrap). |
| `Http/media_type(value)` | Lowercased media type without parameters (`application/json; charset=utf-8` → `application/json`). |
| `Http/origin_host(origin)` | Lowercased `host[:port]` of an `Origin` value (`scheme://host[:port]`), or empty when there is no `://`. |
| `Http/same(a, b)` | Equality that always walks the whole common length (no early exit on the first difference) for comparing the bearer token. |
| `Http/lower(xs)` | ASCII lowercase. |

## Responses

| Function | Contract |
|---|---|
| `Http/response(status, content_type, extra, body)` | `HTTP/1.1 <status> <reason>`, `Content-Type`, `Content-Length`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `Connection: close`, the `extra` header lines (each ending in CRLF), an empty line and the body. The body length is computed in the same pass that copies it (`Bytes/measure`). |
| `Http/reason(status)` | Reason phrase of every status the service uses. |
| `Http/continue()` | `HTTP/1.1 100 Continue` followed by an empty line, sent before reading a body announced with `Expect: 100-continue`. |

## Internal helpers

`Http/words` (split on spaces), `Http/request_line`, `Http/headers`,
`Http/token`, `Http/path`, `Http/until_slash`, `Http/same.go`,
`Http/content_length.go`.

## Tests

`http_parse`, `http_invalid`, `content_length`, `http_helpers`,
`http_response` in `test.bend`.
