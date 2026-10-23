"""Servicio HTTP de firma de PDFs.

Bend 0.2 no tiene sockets, así que este servicio (sólo biblioteca estándar
de Python) es una capa delgada de transporte: valida la entrada, prepara
un directorio de trabajo y ejecuta el binario compilado desde sign.bend,
donde ocurre todo el procesamiento (PDF, SHA-256, RSA, CMS).

Endpoints
  GET  /                       formulario web para probar la API
  GET  /health                 estado del servicio
  POST /api/v1/sign            firma síncrona (espera el resultado)
  POST /api/v1/jobs            firma asíncrona: retorna {"id": ...}
  GET  /api/v1/jobs/<id>       estado del trabajo
  GET  /api/v1/jobs/<id>/pdf   PDF firmado (cuando status == "done")

Cuerpo JSON de /sign y /jobs:
  {
    "pdf": "<base64>",                 obligatorio
    "reason": "...", "location": "...", "contact": "...", "name": "...",
    "key": "<PEM>", "cert": "<PEM>"    sólo si SIGN_ALLOW_CLIENT_KEYS=1
  }

Configuración (variables de entorno)
  SIGN_HOST / SIGN_PORT        dirección de escucha (127.0.0.1:8080)
  SIGN_BIN                     binario de firma (build/sign)
  SIGN_KEY / SIGN_CERT         llave privada y certificado(s) del servidor (PEM)
  SIGN_ALLOW_CLIENT_KEYS       "1" para aceptar llave/certificado en la petición
  SIGN_API_TOKEN               si se define, exige "Authorization: Bearer <token>"
  SIGN_MAX_JOBS                firmas simultáneas (2)
  SIGN_TIMEOUT                 segundos máximos por firma (900)
  SIGN_SIG_SIZE                bytes reservados para el CMS (8192)
  SIGN_JOB_TTL                 segundos que se conservan los trabajos terminados (3600)
"""

import base64
import binascii
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
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HOST = os.environ.get("SIGN_HOST", "127.0.0.1")
PORT = int(os.environ.get("SIGN_PORT", "8080"))
SIGN_BIN = os.environ.get("SIGN_BIN", os.path.join(ROOT, "build", "sign"))
SERVER_KEY = os.environ.get("SIGN_KEY")
SERVER_CERT = os.environ.get("SIGN_CERT")
ALLOW_CLIENT_KEYS = os.environ.get("SIGN_ALLOW_CLIENT_KEYS") == "1"
API_TOKEN = os.environ.get("SIGN_API_TOKEN")
MAX_JOBS = int(os.environ.get("SIGN_MAX_JOBS", "2"))
TIMEOUT = int(os.environ.get("SIGN_TIMEOUT", "900"))
SIG_SIZE = int(os.environ.get("SIGN_SIG_SIZE", "8192"))
JOB_TTL = int(os.environ.get("SIGN_JOB_TTL", "3600"))

# Bend usa enteros de 24 bits para posiciones: el PDF debe ser < 16 MiB.
MAX_PDF = (1 << 24) - 1 - SIG_SIZE * 2 - 65536
MAX_BODY = MAX_PDF * 4 // 3 + 1_000_000
MAX_TEXT = 512

_slots = threading.BoundedSemaphore(MAX_JOBS)
_jobs = {}
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
        raise ApiError(400, f"'{field}' debe ser texto")
    if len(value) > MAX_TEXT:
        raise ApiError(400, f"'{field}' excede {MAX_TEXT} caracteres")
    # params.txt es "clave=valor" por línea: no se permiten saltos de línea.
    return re.sub(r"[\r\n]+", " ", value).strip()


def parse_request(body):
    """Valida el JSON de entrada y retorna los datos normalizados."""
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise ApiError(400, "el cuerpo debe ser JSON válido")
    if not isinstance(data, dict):
        raise ApiError(400, "el cuerpo debe ser un objeto JSON")

    pdf_b64 = data.get("pdf")
    if not isinstance(pdf_b64, str) or not pdf_b64:
        raise ApiError(400, "falta 'pdf' (base64)")
    try:
        pdf = base64.b64decode(pdf_b64, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(400, "'pdf' no es base64 válido")
    if b"%PDF-" not in pdf[:1024]:
        raise ApiError(400, "'pdf' no parece un documento PDF")
    if len(pdf) > MAX_PDF:
        raise ApiError(413, f"el PDF excede el máximo de {MAX_PDF} bytes")

    if "key" in data or "cert" in data:
        if not ALLOW_CLIENT_KEYS:
            raise ApiError(403, "este servidor no acepta llaves en la petición")
        key = data.get("key")
        cert = data.get("cert")
        if not isinstance(key, str) or not isinstance(cert, str):
            raise ApiError(400, "'key' y 'cert' deben ser PEM en texto")
        key, cert = key.encode(), cert.encode()
    else:
        if not (SERVER_KEY and SERVER_CERT):
            raise ApiError(500, "el servidor no tiene llave configurada (SIGN_KEY/SIGN_CERT)")
        with open(SERVER_KEY, "rb") as f:
            key = f.read()
        with open(SERVER_CERT, "rb") as f:
            cert = f.read()

    fields = {k: _text(data.get(k), k) for k in ("name", "reason", "location", "contact")}
    return pdf, key, cert, fields


def run_signer(pdf, key, cert, fields):
    """Ejecuta el binario Bend en un directorio temporal. Retorna el PDF firmado."""
    now = datetime.datetime.now(datetime.timezone.utc)
    params = [f"{k}={v}" for k, v in fields.items() if v]
    params.append("time=" + now.strftime("%Y%m%d%H%M%S"))
    params.append(f"sig_size={SIG_SIZE}")

    work = tempfile.mkdtemp(prefix="sign-")
    try:
        os.chmod(work, 0o700)
        for name, content in (("input.pdf", pdf), ("key.pem", key), ("cert.pem", cert),
                              ("params.txt", ("\n".join(params) + "\n").encode("utf-8"))):
            with open(os.path.join(work, name), "wb") as f:
                f.write(content)
        with _slots:
            try:
                proc = subprocess.run([SIGN_BIN], cwd=work, capture_output=True, timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                raise ApiError(504, f"la firma excedió {TIMEOUT} s")
        out = os.path.join(work, "output.pdf")
        err = os.path.join(work, "error.txt")
        if os.path.exists(out):
            with open(out, "rb") as f:
                return f.read()
        if os.path.exists(err):
            with open(err, "rb") as f:
                raise ApiError(422, f.read().decode("utf-8", "replace"))
        raise ApiError(500, "el firmador terminó sin resultado: "
                       + proc.stdout.decode("utf-8", "replace")[-500:])
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _purge_jobs():
    """Elimina los trabajos terminados hace más de JOB_TTL segundos."""
    now = time.monotonic()
    with _jobs_lock:
        for job_id in [j for j, v in _jobs.items() if now - v.get("_done_at", now) > JOB_TTL]:
            del _jobs[job_id]


def _run_job(job_id, args):
    try:
        result = run_signer(*args)
        update = {"status": "done", "pdf": result}
    except ApiError as e:
        update = {"status": "error", "error": e.message}
    except Exception as e:  # noqa: BLE001 - se informa al cliente
        update = {"status": "error", "error": str(e)}
    with _jobs_lock:
        _jobs[job_id].update(update)
        _jobs[job_id]["finished"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        _jobs[job_id]["_done_at"] = time.monotonic()


FORM = """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>sign_engine</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}
label{display:block;margin:.8rem 0 .2rem}input{width:100%;padding:.4rem}
button{margin-top:1rem;padding:.6rem 1.2rem}#out{margin-top:1rem;white-space:pre-wrap}</style>
</head><body>
<h1>Firma de PDF (Bend)</h1>
<form id="f">
<label>PDF</label><input type="file" id="pdf" accept="application/pdf" required>
<label>Motivo</label><input id="reason">
<label>Lugar</label><input id="location">
<label>Contacto</label><input id="contact">
<label>Token de API (si aplica)</label><input id="token" type="password">
<button>Firmar</button></form>
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
  out.textContent = 'Enviando...';
  const r = await fetch('/api/v1/jobs', {method: 'POST', headers, body: JSON.stringify(body)});
  const j = await r.json(); if (!r.ok) { out.textContent = 'Error: ' + j.error; return; }
  while (true) {
    await new Promise(res => setTimeout(res, 2000));
    const s = await (await fetch('/api/v1/jobs/' + j.id, {headers})).json();
    out.textContent = 'Estado: ' + s.status + (s.error ? ' - ' + s.error : '');
    if (s.status === 'done') {
      const pdf = await (await fetch('/api/v1/jobs/' + j.id + '/pdf', {headers})).blob();
      const a = document.createElement('a'); a.href = URL.createObjectURL(pdf);
      a.download = file.name.replace(/\\.pdf$/i, '') + '-firmado.pdf'; a.textContent = 'Descargar PDF firmado';
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
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        if not API_TOKEN:
            return True
        header = self.headers.get("Authorization", "")
        return hmac.compare_digest(header, "Bearer " + API_TOKEN)

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ApiError(400, "Content-Length inválido")
        if length <= 0:
            raise ApiError(400, "cuerpo vacío")
        if length > MAX_BODY:
            raise ApiError(413, "cuerpo demasiado grande")
        return self.rfile.read(length)

    def _handle(self, fn):
        try:
            fn()
        except ApiError as e:
            self._send(e.status, {"error": e.message})
        except Exception as e:  # noqa: BLE001
            self._send(500, {"error": f"error interno: {e}"})

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
        if not self._authorized():
            raise ApiError(401, "no autorizado")
        m = re.fullmatch(r"/api/v1/jobs/([0-9a-f]{32})(/pdf)?", path)
        if not m:
            raise ApiError(404, "no encontrado")
        with _jobs_lock:
            job = dict(_jobs.get(m.group(1)) or {})
        if not job:
            raise ApiError(404, "trabajo no encontrado")
        if m.group(2):
            if job["status"] != "done":
                raise ApiError(409, f"el trabajo está en estado '{job['status']}'")
            return self._send(200, job["pdf"], "application/pdf",
                              {"Content-Disposition": 'attachment; filename="firmado.pdf"'})
        return self._send(200, {k: v for k, v in job.items() if k != "pdf" and not k.startswith("_")})

    def _post(self):
        path = self.path.split("?", 1)[0]
        if path not in ("/api/v1/sign", "/api/v1/jobs"):
            raise ApiError(404, "no encontrado")
        if not self._authorized():
            raise ApiError(401, "no autorizado")
        args = parse_request(self._body())
        if path == "/api/v1/sign":
            signed = run_signer(*args)
            if "application/pdf" in self.headers.get("Accept", ""):
                return self._send(200, signed, "application/pdf")
            return self._send(200, {"pdf": base64.b64encode(signed).decode("ascii")})
        _purge_jobs()
        job_id = uuid.uuid4().hex
        with _jobs_lock:
            _jobs[job_id] = {"id": job_id, "status": "running",
                             "created": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        threading.Thread(target=_run_job, args=(job_id, args), daemon=True).start()
        return self._send(202, {"id": job_id, "status": "running"})

    def log_message(self, fmt, *args):
        # Nunca registrar cuerpos: pueden contener documentos o llaves.
        print(f"{self.address_string()} - {fmt % args}")


def main():
    if not os.path.exists(SIGN_BIN):
        print(f"advertencia: no existe {SIGN_BIN}; ejecute scripts/build.sh")
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"sign_engine escuchando en http://{HOST}:{PORT}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
