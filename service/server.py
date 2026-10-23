import base64
import binascii
import collections
import datetime
import hmac
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HOST = os.environ.get("SIGN_HOST", "127.0.0.1")
PORT = int(os.environ.get("SIGN_PORT", "8080"))
SIGN_BIN = os.environ.get("SIGN_BIN", os.path.join(ROOT, "build", "sign"))
SERVER_KEY = os.environ.get("SIGN_KEY")
SERVER_CERT = os.environ.get("SIGN_CERT")
ALLOW_CLIENT_KEYS = os.environ.get("SIGN_ALLOW_CLIENT_KEYS") == "1"
ALLOW_ANONYMOUS = os.environ.get("SIGN_ALLOW_ANONYMOUS") == "1"
API_TOKEN = os.environ.get("SIGN_API_TOKEN")
ALLOWED_HOSTS = {
    h.strip().lower()
    for h in os.environ.get("SIGN_ALLOWED_HOSTS", f"localhost:{PORT},127.0.0.1:{PORT},[::1]:{PORT}").split(",")
    if h.strip()
}
MAX_JOBS = int(os.environ.get("SIGN_MAX_JOBS", "2"))
MAX_QUEUE = int(os.environ.get("SIGN_MAX_QUEUE", "8"))
MAX_RESULTS = int(os.environ.get("SIGN_MAX_RESULTS", "16"))
TIMEOUT = int(os.environ.get("SIGN_TIMEOUT", "900"))
SIG_SIZE = int(os.environ.get("SIGN_SIG_SIZE", "8192"))
JOB_TTL = int(os.environ.get("SIGN_JOB_TTL", "3600"))

FORMAT_LIMIT = (1 << 24) - 1 - SIG_SIZE * 2 - 65536
MAX_PDF = min(int(os.environ.get("SIGN_MAX_PDF", str(8 << 20))), FORMAT_LIMIT)
MAX_BODY = MAX_PDF * 4 // 3 + 1_000_000
MAX_TEXT = 512

_slots = threading.BoundedSemaphore(MAX_JOBS)
_pending = 0
_pending_lock = threading.Lock()
_jobs = collections.OrderedDict()
_jobs_lock = threading.Lock()


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def _text(value, field):
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ApiError(400, f"'{field}' must be a string")
    if len(value) > MAX_TEXT:
        raise ApiError(400, f"'{field}' exceeds {MAX_TEXT} characters")
    return re.sub(r"[\r\n]+", " ", value).strip()


def parse_request(body):
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise ApiError(400, "body must be valid JSON")
    if not isinstance(data, dict):
        raise ApiError(400, "body must be a JSON object")

    pdf_b64 = data.get("pdf")
    if not isinstance(pdf_b64, str) or not pdf_b64:
        raise ApiError(400, "missing 'pdf' (base64)")
    try:
        pdf = base64.b64decode(pdf_b64, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(400, "'pdf' is not valid base64")
    if b"%PDF-" not in pdf[:1024]:
        raise ApiError(400, "'pdf' does not look like a PDF document")
    if len(pdf) > MAX_PDF:
        raise ApiError(413, f"the PDF exceeds the maximum of {MAX_PDF} bytes")

    fields = {k: _text(data.get(k), k) for k in ("reason", "location", "contact")}
    if "key" in data or "cert" in data:
        if not ALLOW_CLIENT_KEYS:
            raise ApiError(403, "this server does not accept keys in requests")
        key = data.get("key")
        cert = data.get("cert")
        if not isinstance(key, str) or not isinstance(cert, str):
            raise ApiError(400, "'key' and 'cert' must be PEM strings")
        key, cert = key.encode(), cert.encode()
        fields["name"] = _text(data.get("name"), "name")
    else:
        if not (SERVER_KEY and SERVER_CERT):
            raise ApiError(500, "the server has no signing key configured (SIGN_KEY/SIGN_CERT)")
        with open(SERVER_KEY, "rb") as f:
            key = f.read()
        with open(SERVER_CERT, "rb") as f:
            cert = f.read()
    return pdf, key, cert, fields


def _enter_queue():
    global _pending
    with _pending_lock:
        if _pending >= MAX_QUEUE:
            raise ApiError(429, "too many pending signing requests")
        _pending += 1


def _leave_queue():
    global _pending
    with _pending_lock:
        _pending -= 1


def run_signer(pdf, key, cert, fields):
    params = [f"{k}={v}" for k, v in fields.items() if v]
    with _slots:
        now = datetime.datetime.now(datetime.timezone.utc)
        params.append("time=" + now.strftime("%Y%m%d%H%M%S"))
        params.append(f"sig_size={SIG_SIZE}")
        work = tempfile.mkdtemp(prefix="sign-")
        try:
            os.chmod(work, 0o700)
            for name, content in (("input.pdf", pdf), ("key.pem", key), ("cert.pem", cert),
                                  ("params.txt", ("\n".join(params) + "\n").encode("utf-8"))):
                with open(os.path.join(work, name), "wb") as f:
                    f.write(content)
            try:
                proc = subprocess.run([SIGN_BIN], cwd=work, capture_output=True, timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                raise ApiError(504, f"signing exceeded {TIMEOUT} s")
            out = os.path.join(work, "output.pdf")
            err = os.path.join(work, "error.txt")
            if os.path.exists(out):
                with open(out, "rb") as f:
                    return f.read()
            if os.path.exists(err):
                with open(err, "rb") as f:
                    raise ApiError(422, f.read().decode("utf-8", "replace"))
            raise ApiError(500, "the signer finished without a result: "
                           + proc.stdout.decode("utf-8", "replace")[-500:])
        finally:
            shutil.rmtree(work, ignore_errors=True)


def _purge_jobs():
    now = time.monotonic()
    with _jobs_lock:
        finished = [j for j, v in _jobs.items() if "_done_at" in v]
        for job_id in finished:
            if now - _jobs[job_id]["_done_at"] > JOB_TTL:
                del _jobs[job_id]
        finished = [j for j in finished if j in _jobs]
        for job_id in finished[:max(0, len(finished) - MAX_RESULTS)]:
            del _jobs[job_id]


def _run_job(job_id, args):
    try:
        result = run_signer(*args)
        update = {"status": "done", "pdf": result}
    except ApiError as e:
        update = {"status": "error", "error": e.message}
    except Exception as e:
        update = {"status": "error", "error": str(e)}
    finally:
        _leave_queue()
    with _jobs_lock:
        _jobs[job_id].update(update)
        _jobs[job_id]["finished"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        _jobs[job_id]["_done_at"] = time.monotonic()
    _purge_jobs()


FORM = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>sign_engine</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}
label{display:block;margin:.8rem 0 .2rem}input{width:100%;padding:.4rem}
button{margin-top:1rem;padding:.6rem 1.2rem}#out{margin-top:1rem;white-space:pre-wrap}</style>
</head><body>
<h1>PDF signing (Bend)</h1>
<form id="f">
<label>PDF</label><input type="file" id="pdf" accept="application/pdf" required>
<label>Reason</label><input id="reason">
<label>Location</label><input id="location">
<label>Contact</label><input id="contact">
<label>API token</label><input id="token" type="password">
<button>Sign</button></form>
<div id="out"></div>
<script>
const out = document.getElementById('out');
document.getElementById('f').onsubmit = async (ev) => {
  ev.preventDefault();
  const file = document.getElementById('pdf').files[0];
  const buf = new Uint8Array(await file.arrayBuffer());
  let bin = ''; for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode(...buf.subarray(i, i + 0x8000));
  const body = {pdf: btoa(bin)};
  for (const k of ['reason', 'location', 'contact']) { const v = document.getElementById(k).value; if (v) body[k] = v; }
  const headers = {'Content-Type': 'application/json'};
  const token = document.getElementById('token').value; if (token) headers['Authorization'] = 'Bearer ' + token;
  out.textContent = 'Sending...';
  const r = await fetch('/api/v1/jobs', {method: 'POST', headers, body: JSON.stringify(body)});
  const j = await r.json(); if (!r.ok) { out.textContent = 'Error: ' + j.error; return; }
  while (true) {
    await new Promise(res => setTimeout(res, 2000));
    const s = await (await fetch('/api/v1/jobs/' + j.id, {headers})).json();
    out.textContent = 'Status: ' + s.status + (s.error ? ' - ' + s.error : '');
    if (s.status === 'done') {
      const pdf = await (await fetch('/api/v1/jobs/' + j.id + '/pdf', {headers})).blob();
      const a = document.createElement('a'); a.href = URL.createObjectURL(pdf);
      a.download = file.name.replace(/\\.pdf$/i, '') + '-signed.pdf'; a.textContent = 'Download signed PDF';
      out.textContent = ''; out.appendChild(a); break;
    }
    if (s.status === 'error') break;
  }
};
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "sign_engine/0.1"

    def _send(self, status, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _check_origin(self):
        host = (self.headers.get("Host") or "").strip().lower()
        if host not in ALLOWED_HOSTS:
            raise ApiError(403, "host not allowed")
        origin = self.headers.get("Origin")
        if origin is not None and urllib.parse.urlsplit(origin).netloc.lower() != host:
            raise ApiError(403, "cross-origin requests are not allowed")

    def _check_auth(self):
        if ALLOW_ANONYMOUS and not API_TOKEN:
            return
        header = self.headers.get("Authorization", "")
        if not API_TOKEN or not hmac.compare_digest(header, "Bearer " + API_TOKEN):
            raise ApiError(401, "unauthorized")

    def _body(self):
        ctype = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            raise ApiError(415, "Content-Type must be application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ApiError(400, "invalid Content-Length")
        if length <= 0:
            raise ApiError(400, "empty body")
        if length > MAX_BODY:
            raise ApiError(413, "body too large")
        return self.rfile.read(length)

    def _handle(self, fn):
        try:
            self._check_origin()
            fn()
        except ApiError as e:
            self._send(e.status, {"error": e.message})
        except Exception as e:
            self._send(500, {"error": f"internal error: {e}"})

    def do_GET(self):
        self._handle(self._get)

    def do_POST(self):
        self._handle(self._post)

    def _get(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            return self._send(200, FORM, "text/html; charset=utf-8")
        if path == "/health":
            return self._send(200, {"status": "ok", "signer": os.path.exists(SIGN_BIN),
                                    "server_key": bool(SERVER_KEY and SERVER_CERT)})
        self._check_auth()
        m = re.fullmatch(r"/api/v1/jobs/([0-9a-f]{32})(/pdf)?", path)
        if not m:
            raise ApiError(404, "not found")
        with _jobs_lock:
            job = dict(_jobs.get(m.group(1)) or {})
        if not job:
            raise ApiError(404, "job not found")
        if m.group(2):
            if job["status"] != "done":
                raise ApiError(409, f"the job is in state '{job['status']}'")
            return self._send(200, job["pdf"], "application/pdf",
                              {"Content-Disposition": 'attachment; filename="signed.pdf"'})
        return self._send(200, {k: v for k, v in job.items() if k != "pdf" and not k.startswith("_")})

    def _post(self):
        path = self.path.split("?", 1)[0]
        if path not in ("/api/v1/sign", "/api/v1/jobs"):
            raise ApiError(404, "not found")
        self._check_auth()
        args = parse_request(self._body())
        _enter_queue()
        if path == "/api/v1/sign":
            try:
                signed = run_signer(*args)
            finally:
                _leave_queue()
            if "application/pdf" in self.headers.get("Accept", ""):
                return self._send(200, signed, "application/pdf")
            return self._send(200, {"pdf": base64.b64encode(signed).decode("ascii")})
        job_id = uuid.uuid4().hex
        with _jobs_lock:
            _jobs[job_id] = {"id": job_id, "status": "running",
                             "created": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        threading.Thread(target=_run_job, args=(job_id, args), daemon=True).start()
        return self._send(202, {"id": job_id, "status": "running"})

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")


def main():
    if not 1024 <= SIG_SIZE <= 262144:
        raise SystemExit("SIGN_SIG_SIZE must be between 1024 and 262144")
    if MAX_PDF < 1024:
        raise SystemExit("SIGN_MAX_PDF must be at least 1024")
    if not API_TOKEN and not ALLOW_ANONYMOUS:
        raise SystemExit("set SIGN_API_TOKEN (or SIGN_ALLOW_ANONYMOUS=1 for local testing only)")
    if not os.path.exists(SIGN_BIN):
        print(f"warning: {SIGN_BIN} does not exist; run scripts/build.sh")
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"sign_engine listening on http://{HOST}:{PORT}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
