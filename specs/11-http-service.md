# 11 — HTTP service (`server.bend`)

## Process model

Bend 0.2 has no sockets: a program can only use files, standard input and
output, a monotonic clock, sleep and C dynamic libraries. The service
therefore follows the inetd/CGI model. A socket manager accepts each TCP
connection and starts `build/server` with the connection as standard input
and output; the Bend program reads one HTTP/1.1 request, writes one
response with `Connection: close` and exits. All protocol handling, request
validation, JSON, base64, authentication and signing happen in Bend; the
socket manager only calls `accept()` and enforces process limits.

| Environment | Socket manager |
|---|---|
| Production | systemd socket activation: `deploy/sign-engine.socket` (`Accept=yes`, `MaxConnections`) and the template `deploy/sign-engine@.service` (`StandardInput=socket`, `RuntimeMaxSec`, `MemoryMax`, sandboxing). |
| Development | `scripts/serve.sh [address:port]`, which runs `systemd-socket-activate --inetd --accept` from the current directory. |

`server.bend` only performs input and output; all decisions are pure
functions of `lib/service.bend` ([modules/service.md](modules/service.md)),
called through wrappers defined in `server.bend` (rule P-22).

| Function of `server.bend` | Role |
|---|---|
| `main` | Reads `server.conf` and the head, matches the `Route`. |
| `Main/read_head(acc, state, n)` | Reads the head byte by byte; `Main/head_state` tracks line breaks (`2` = empty line seen); at most `Main/MAX_HEAD` (16 384) bytes. |
| `Main/read_exact(n, chunks)` | Reads exactly `n` body bytes in chunks of up to `Main/CHUNK`; `Main/min`, `Main/measure`, `Main/assemble`. |
| `Main/read_file`, `Main/read_chunks`, `Main/reverse` | Whole-file reads, as in `sign.bend`. |
| `Main/random(kind)` | 16 bytes from `/dev/urandom` for jobs (`Main/bytes`). |
| `Main/continue(expect)` | Sends `Main/continue_bytes` when the client asked for `100 Continue`. |
| `Main/handle_post` | Reads key, certificate, time sources and randomness, matches the `Outcome`. |
| `Main/job`, `Main/complete`, `Main/write_pdf` | Asynchronous job: record, `202`, close the connection, sign, results. |
| `Main/status`, `Main/download` | Job status and download. |
| `Main/send`, `Main/log`, `Main/reply` | Write and flush a response, log line on standard error. |
| `Main/route`, `Main/post`, `Main/sign`, `Main/signed`, `Main/outcome`, `Main/accepted`, `Main/job_file`, `Main/key_path`, `Main/cert_path`, `Main/state_running`, `Main/state_final`, `Main/job_status`, `Main/job_done`, `Main/job_conflict`, `Main/job_download`, `Main/job_missing`, `Main/job_unwritable`, `Main/log_line`, `Main/empty` | Wrappers of library functions (rule P-22). |

## Request handling

1. Read `server.conf` from the working directory.
2. Read the request head one byte at a time until the empty line (`\r\n\r\n`
   or `\n\n`), at most 16 KiB (`431` beyond). Reading a byte at a time is
   required: a read of more bytes than the client sent would block, because
   the client keeps the connection open while waiting for the response.
3. `Service/route` decides: answer immediately, read a body, or read a job.
4. For a body: send `100 Continue` if the client asked for it, read exactly
   `Content-Length` bytes (in chunks of up to 1 MiB), read the server key and
   certificate files, `/proc/stat` and `/proc/uptime` (current time) and, for
   jobs, 16 bytes from `/dev/urandom`; then `Service/post` validates the
   request.
5. Synchronous signing: run `Signer/sign_pdf`, write the response.
6. Asynchronous job: write the job record, send `202`, close standard output
   and input (the client sees the end of the response), then sign and write
   the result files. The signing is placed inside a `match` on the result of
   closing standard input: HVM evaluates every reducible expression as soon
   as its inputs are known, so a signature computed from values that are
   already available would otherwise be calculated before the `202` is sent
   (rule P-24).
7. Write a log line `<method> <path> <status>` to standard error (the
   journal under systemd).

## Endpoints

| Method and path | Auth | Description |
|---|---|---|
| `GET /` | no | HTML form that signs a local file through the asynchronous API. |
| `GET /health` | no | `{"status": "ok", "server_key": <key and cert configured>}` |
| `POST /api/v1/sign` | yes | Synchronous signing. Response `{"pdf": "<base64>"}`, or the raw PDF when the request has `Accept: application/pdf`. |
| `POST /api/v1/jobs` | yes | Asynchronous signing. Response `202 {"id": "<32 hex>", "status": "running"}`. |
| `GET /api/v1/jobs/<id>` | yes | `{"id", "status": "running" \| "done" \| "error", "created", "finished"?, "error"?}` (times in ISO 8601 UTC) |
| `GET /api/v1/jobs/<id>/pdf` | yes | Signed PDF (`application/pdf`, `Content-Disposition: attachment`) when `status` is `done`; `409` otherwise. |

## Request protection

Every request:

- **Host allow-list.** Exactly one `Host` header, equal (case-insensitive)
  to an entry of `allowed_hosts`; otherwise `403`. This defeats DNS
  rebinding.
- **Origin check.** When an `Origin` header is present, its `host:port` must
  equal the `Host` header; otherwise `403`.

Endpoints marked "auth":

- **Bearer token.** Exactly one `Authorization: Bearer <token>` header,
  compared without early exit. Every request fails with `500` while
  `server.conf` has no token, unless `anonymous=1` (local testing only).
- **JSON only.** `POST` bodies must be `Content-Type: application/json`
  (`415` otherwise); HTML forms cannot produce this type without a CORS
  preflight. `Transfer-Encoding` is not supported (`400`).

## Request body (`/sign`, `/jobs`)

```json
{
  "pdf": "<base64, required>",
  "reason": "", "location": "", "contact": "",
  "key": "<PEM>", "cert": "<PEM>", "name": ""
}
```

- `pdf` must be strict base64 (standard alphabet, correct `=` padding, no
  white-space), contain `%PDF-` in its first 1024 bytes and be at most
  `max_pdf` bytes (`413`).
- Text fields are optional strings (or null) of at most 512 characters; each
  run of line breaks becomes one space.
- `key` and `cert` are accepted only with `client_keys=1` (otherwise `403`).
  Without them the server key and certificate are used.
- `name` is honored only together with a client key, so clients cannot make
  a signature display another signer's name.
- The server adds `time` (current UTC time from `/proc`) and `sig_size`.

## Errors

All errors are JSON `{"error": "<message>"}`.

| Status | Cause |
|---|---|
| 400 | Malformed request, invalid JSON, missing or invalid `pdf`, invalid field types, bad or duplicate `Content-Length`, empty body, `Transfer-Encoding` |
| 401 | Missing or wrong bearer token |
| 403 | Host not allowed, cross-origin request, or `key`/`cert` sent while client keys are disabled |
| 404 | Unknown path or job |
| 405 | Method other than `GET` or `POST` |
| 409 | PDF requested for a job that is not `done` |
| 413 | Body or PDF too large |
| 415 | `POST` without `Content-Type: application/json` |
| 422 | The signer rejected the input |
| 431 | Request head above 16 KiB |
| 500 | Configuration error, no server key, unwritable jobs directory, no random source, or `runtime: out of memory` (written by the patched runtime, see [01-architecture.md](01-architecture.md#5-runtime-and-build)) |

A request killed by `RuntimeMaxSec` simply loses its connection.

## Configuration (`server.conf`)

`key=value` lines in the working directory (template in
`deploy/server.conf.example`). The file holds the token, so it must be
readable only by the service user.

| Key | Default | Meaning |
|---|---|---|
| `token` | — | Bearer token (required unless `anonymous=1`) |
| `key`, `cert` | — | Server private key and certificate chain (PEM or DER paths) |
| `allowed_hosts` | `localhost:8080,127.0.0.1:8080,[::1]:8080` | Accepted `Host` values (comma separated); add the public name behind a reverse proxy |
| `max_pdf` | `8388608` (8 MiB) | Largest accepted document, capped at the format limit |
| `sig_size` | `8192` | Bytes reserved for the CMS (`1024..262144`) |
| `client_keys` | `0` | `1` accepts `key`/`cert`/`name` in requests |
| `anonymous` | `0` | `1` disables authentication when no token is set |
| `jobs` | `jobs` | Directory for job records and results (must exist) |
| `job_timeout` | `3600` | Seconds after which a `running` job is reported as interrupted |

The file is read on every request, so changes apply to the next request.

## Jobs

- Ids are 32 lowercase hexadecimal characters from 16 bytes of
  `/dev/urandom`; they are unguessable and also used as file names.
- `<jobs>/<id>.status` holds the state record (see `Service/state_running`
  and `Service/state_final`); `<jobs>/<id>.pdf` the signed document.
- Bend cannot delete files, so finished jobs stay until removed outside the
  service: `deploy/sign-engine.tmpfiles` makes `systemd-tmpfiles` delete
  files older than one day.
- A job whose process dies (timeout, out of memory, restart) stays
  `running`; after `job_timeout` seconds it is reported as `error`.

## Limits and resources

- Concurrency is bounded by the socket unit's `MaxConnections` (a running
  job keeps its connection slot until it finishes); further connections are
  refused by systemd. There is no `429`.
- Each signing process can use up to about 4.5 GiB of memory with the
  default build (`MEM_L2=28`, `VARS_L2=29`); `MemoryMax=5G` bounds it. Quick
  requests (`/health`, job status) touch little memory.
- `RuntimeMaxSec=900` stops a request that runs longer than 15 minutes.
- The service has no TLS: run it behind a reverse proxy that terminates
  HTTPS, and add the proxy's host name to `allowed_hosts`.
- The service unit runs as a dedicated user with `ProtectSystem=strict`,
  `ProtectHome`, `PrivateTmp`, `PrivateDevices` (which keeps
  `/dev/urandom`) and write access only to the jobs directory.
