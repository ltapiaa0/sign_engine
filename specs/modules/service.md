# Module `lib/service.bend`

Pure request handling of the HTTP service: everything `server.bend` does
except reading and writing. The behavior seen by clients is specified in
[11-http-service.md](../11-http-service.md); this document maps it to
functions.

## Configuration

```
type Conf:
  New { token, key, cert, hosts, max_pdf, sig_size, client_keys, anonymous, jobs, job_timeout, error }
```

`Service/conf(text)` reads `server.conf` (`key=value` lines, parsed with
`Signer/parse_params`). Numbers are parsed with overflow detection
(`Service/number`: values above `2^24 - 1` become `2^24 - 1`). `max_pdf` is
capped at the format limit `2^24 - 1 - 65536 - 2·sig_size`. `error` is empty
or the message returned with status 500 for every request
(`Service/conf_error`): `sig_size` outside `1024..262144`, or no `token`
without `anonymous=1`. `hosts` are the comma-separated `allowed_hosts`,
trimmed and lowercased (`Service/hosts`).

## Phase 1: request head

`Service/route(conf_text, head, complete) -> Route`

```
type Route:
  Reply { status, response }             answer now
  Body { kind, length, expect, accept_pdf }   read the body; kind 1 = jobs
  Status { id }                          GET /api/v1/jobs/<id>
  Download { id }                        GET /api/v1/jobs/<id>/pdf
```

Checks in order: header size (`complete` 2 → 431, 0 → 400), configuration
(500), request syntax (400), exactly one `Host` in the allow-list (403),
`Origin` (403), then per method: `Service/get` (`/`, `/health`, then
authentication and job paths) and `Service/post_head` (path, authentication,
media type, `Transfer-Encoding`, `Content-Length`, body limit
`Service/max_body = max_pdf / 3 · 4 + 1 000 004`, capped at `2^24 - 1`).
Other methods get 405. `Service/auth` accepts exactly one
`Authorization: Bearer <token>` header (compared with `Http/same`), or any
request when `anonymous=1` and no token is set. `Service/job_path` accepts
exactly 32 lowercase hexadecimal characters as job id, which keeps paths
built from it inside the jobs directory.

## Phase 2: request body

`Service/post(conf_text, kind, accept_pdf, body, key_file, cert_file, stat, uptime, rand) -> Outcome`

```
type Outcome:
  Reply { status, response }
  Sign { mode, id, pdf, key, cert, params }    mode 0 JSON, 1 raw PDF, 2 job
```

1. `Json/parse`; not JSON → 400, not an object → 400.
2. `Service/split_pdf` separates the `pdf` member from the others in one
   pass, so the large value is never copied by later lookups (the last `pdf`
   member wins; for the other members `Service/lookup` also returns the last
   occurrence because the list is reversed).
3. `Service/pdf_field`: a non-empty string, strict base64
   (`Bytes/from_base64_strict`), `%PDF-` in the first 1024 bytes
   (`Service/pdf_header`, which splits the decoded bytes instead of copying
   them) and at most `max_pdf` bytes (413).
4. `Service/fields`: `reason`, `location`, `contact` and `name` must be
   strings or null, at most 512 characters (`Service/chars` counts UTF-8
   code points), with each run of CR/LF replaced by one space and the result
   trimmed (`Service/one_line`). `key`/`cert` in the request require
   `client_keys=1` (403), must both be strings (400), and enable `name`;
   otherwise the server key and certificate files must be non-empty (500).
5. `Service/sign` builds the outcome; a job needs 16 random bytes (hex id),
   otherwise 500. The signer parameters are the non-empty text fields, the
   current time (`Service/time_param`, omitted when `/proc` is unreadable)
   and `sig_size`.

## Responses and jobs

| Function | Contract |
|---|---|
| `Service/signed(mode, result)` | 200 with the PDF (mode 1) or `{"pdf": "<base64>"}`; 422 with the signer's message. |
| `Service/accepted(id)` | 202 `{"id": ..., "status": "running"}`. |
| `Service/state_running(stat, uptime)` | Job record `running\n<days>\n<secs>\n`. |
| `Service/outcome(result)` | `(ok, pdf, message)` from the signer result in one match, so the signed PDF is not copied. |
| `Service/state_final(running, stat, uptime, ok, message)` | `done\n<cd>\n<cs>\n<fd>\n<fs>\n` or `error\n...\n<message>\n` (the message on one line). |
| `Service/job_status(id, record, stat, uptime, timeout)` | 200 with `id`, `status`, `created`, `finished`, `error`. A `running` record older than `job_timeout` seconds is reported as `error` "the signer stopped before finishing" (the process was killed, ran out of memory or the machine restarted). An unreadable record → 500. |
| `Service/job_done`, `Service/job_conflict`, `Service/job_download`, `Service/job_missing`, `Service/job_unwritable` | Download decision and the 409, 200 (`Content-Disposition: attachment; filename="signed.pdf"`), 404 and 500 responses. |
| `Service/job_file(conf_text, id, suffix)`, `Service/key_path`, `Service/cert_path` | File paths as Bend `String`s (`Service/string` maps each byte to one character, which HVM writes back as that byte). |
| `Service/log(head, status)` | Log line `<method> <path> <status>`. |
| `Service/form()` | The HTML page (five literals, rule P-20). |

## Internal helpers

`Service/flag`, `Service/empty`, `Service/min`, `Service/split`,
`Service/member`, `Service/hosts.go`, `Service/format_limit`,
`Service/json_ctype`, `Service/error_body`, `Service/error`, `Service/reply`,
`Service/fail`, `Service/hex_id`, `Service/mode`, `Service/text`,
`Service/pems`, `Service/param`, `Service/with_newlines`,
`Service/status_member`, `Service/status_reply`, `Service/state_fields`,
`Service/next_line`, `Service/next_number`, `Service/conf_timeout`,
`Service/or_dash`, `Service/form1`, `Service/form2`, `Service/form3`,
`Service/form4`, `Service/form5`,
`Service/DEFAULT_MAX_PDF` (8 MiB), `Service/MAX_TEXT` (512).

## Tests

`conf`, `conf_errors`, `route_public`, `route_api`, `route_jobs`,
`post_errors`, `post_sign`, `job_status`, `job_stale` in `test.bend`, and
`tests/service.sh` end to end.
