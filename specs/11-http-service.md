# 11 — HTTP service (`service/server.py`)

## Role

Bend 0.2 has no networking, so the service is a thin transport layer written
with the Python standard library only. It validates requests, prepares a
private working directory per request, runs `build/sign` there and returns
the result. It performs no PDF or cryptographic processing (NFR-1).

## Endpoints

| Method and path | Auth | Description |
|---|---|---|
| `GET /` | no | HTML form that signs a local file through the asynchronous API. |
| `GET /health` | no | `{"status": "ok", "signer": <binary exists>, "server_key": <key configured>}` |
| `POST /api/v1/sign` | yes | Synchronous signing. Response `{"pdf": "<base64>"}`, or the raw PDF when the request has `Accept: application/pdf`. |
| `POST /api/v1/jobs` | yes | Asynchronous signing. Response `202 {"id": "<32 hex>", "status": "running"}`. |
| `GET /api/v1/jobs/<id>` | yes | `{"id", "status": "running" \| "done" \| "error", "created", "finished"?, "error"?}` |
| `GET /api/v1/jobs/<id>/pdf` | yes | Signed PDF (`application/pdf`) when `status` is `done`; `409` otherwise. |

## Request protection

Every request, including `GET /` and `/health`:

- **Host allow-list.** The `Host` header must be one of `SIGN_ALLOWED_HOSTS`
  (default `localhost:<port>`, `127.0.0.1:<port>`, `[::1]:<port>`); otherwise
  `403`. This defeats DNS rebinding.
- **Origin check.** When an `Origin` header is present, its `host:port` must
  equal the `Host` header; otherwise `403`. Browsers send `Origin` on
  cross-site `POST`s, so another web page cannot use the service.

Endpoints marked "auth":

- **Bearer token.** `Authorization: Bearer <SIGN_API_TOKEN>`, compared in
  constant time. The server refuses to start without a token unless
  `SIGN_ALLOW_ANONYMOUS=1` (local testing only).
- **JSON only.** `POST` bodies must be `Content-Type: application/json`
  (`415` otherwise); HTML forms cannot produce this content type without a
  CORS preflight.

## Request body (`/sign`, `/jobs`)

```json
{
  "pdf": "<base64, required>",
  "reason": "", "location": "", "contact": "",
  "key": "<PEM>", "cert": "<PEM>", "name": ""
}
```

- `pdf` must be strict base64, contain `%PDF-` in its first 1024 bytes and be
  at most `SIGN_MAX_PDF` bytes, which is capped at the format limit
  `2^24 - 1 - 2·SIGN_SIG_SIZE - 65536` (positions are `u24`).
- Text fields are optional strings of at most 512 characters; line breaks are
  replaced by spaces (they would break `params.txt`).
- `key` and `cert` are accepted only when `SIGN_ALLOW_CLIENT_KEYS=1`
  (otherwise `403`). Without them the server key (`SIGN_KEY`, `SIGN_CERT`) is
  used.
- `name` is honored only together with a client key. With the server key the
  signature name is always the certificate's common name, so clients cannot
  make a signature display another signer's name.
- The server adds `time` (current UTC time) and `sig_size`.

## Errors

All errors are JSON `{"error": "<message>"}`.

| Status | Cause |
|---|---|
| 400 | Invalid JSON, missing or invalid `pdf`, invalid field types, bad `Content-Length`, empty body |
| 401 | Missing or wrong bearer token |
| 403 | Host not allowed, cross-origin request, or `key`/`cert` sent while client keys are disabled |
| 404 | Unknown path or job |
| 409 | PDF requested for a job that is not `done` |
| 413 | Body or PDF too large |
| 415 | `POST` without `Content-Type: application/json` |
| 422 | The signer rejected the input (message from `error.txt`), including `runtime: out of memory` when a document does not fit the runtime buffers |
| 429 | `SIGN_MAX_QUEUE` requests are already running or waiting |
| 500 | Server misconfiguration or unexpected failure |
| 504 | Signing exceeded `SIGN_TIMEOUT` |

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SIGN_HOST`, `SIGN_PORT` | `127.0.0.1`, `8080` | Listen address |
| `SIGN_ALLOWED_HOSTS` | `localhost:<port>,127.0.0.1:<port>,[::1]:<port>` | Accepted `Host` headers (comma separated); add the public name when behind a reverse proxy |
| `SIGN_BIN` | `build/sign` | Signer binary |
| `SIGN_KEY`, `SIGN_CERT` | — | Server-held private key and certificate chain (PEM) |
| `SIGN_API_TOKEN` | — | Bearer token (required unless `SIGN_ALLOW_ANONYMOUS=1`) |
| `SIGN_ALLOW_ANONYMOUS` | off | `1` disables authentication (local testing only) |
| `SIGN_ALLOW_CLIENT_KEYS` | off | `1` accepts `key`/`cert`/`name` in requests |
| `SIGN_MAX_JOBS` | `2` | Concurrent signer processes |
| `SIGN_MAX_QUEUE` | `8` | Running plus waiting requests before answering `429` |
| `SIGN_MAX_RESULTS` | `16` | Finished jobs kept in memory |
| `SIGN_TIMEOUT` | `900` | Seconds before a signer process is killed |
| `SIGN_SIG_SIZE` | `8192` | Bytes reserved for the CMS (`1024..262144`, checked at startup) |
| `SIGN_MAX_PDF` | `8388608` (8 MiB) | Largest accepted document, so that documents that do not fit the signer's memory (about 10 MB with the default build, see [13-performance.md](13-performance.md#memory)) are refused at once with `413` |
| `SIGN_JOB_TTL` | `3600` | Seconds a finished job is kept in memory |

## Behavior

- A request first takes a queue position (`429` when `SIGN_MAX_QUEUE` are
  taken), then waits for one of `SIGN_MAX_JOBS` signer slots. Only when it
  holds a slot does it create a fresh `tempfile.mkdtemp` directory with mode
  `0700`, write `input.pdf`, `key.pem`, `cert.pem` and `params.txt`, run the
  binary there and remove the directory in every case (NFR-4). Waiting
  requests therefore never leave keys or documents on disk.
- Each signer process can use up to about 4.5 GiB of memory with the default
  build (`MEM_L2=28`, `VARS_L2=29`, see
  [01-architecture.md](01-architecture.md#5-runtime-and-build)); size
  `SIGN_MAX_JOBS` to the available memory.
- Asynchronous jobs run in daemon threads; job records (including the signed
  PDF) live in memory. Finished jobs older than `SIGN_JOB_TTL` and all but the
  newest `SIGN_MAX_RESULTS` finished jobs are discarded.
- The access log contains method, path and status only, never bodies.
- Responses carry `Cache-Control: no-store` and `X-Content-Type-Options:
  nosniff`.
- The server has no TLS and is meant to run behind a reverse proxy that
  terminates HTTPS.
