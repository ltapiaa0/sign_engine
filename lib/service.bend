from lib/bytes import *
from lib/text import *
from lib/json import *
from lib/http import *
from lib/clock import *
from lib/signer import *

type Conf:
  New { token, key, cert, hosts, max_pdf, sig_size, client_keys, anonymous, jobs, job_timeout, error }

type Route:
  Reply { status, response }
  Body { kind, length, expect, accept_pdf }
  Status { id }
  Download { id }

type Outcome:
  Reply { status, response }
  Sign { mode, id, pdf, key, cert, params }

def Service/DEFAULT_MAX_PDF() -> u24:
  return 8388608

def Service/MAX_TEXT() -> u24:
  return 512

def Service/conf(text: List(u24)) -> Conf:
  ps = Signer/parse_params(text)
  token = Signer/param(ps, "token")
  sig_size = Service/number(Signer/param(ps, "sig_size"), Signer/DEFAULT_SIG_SIZE)
  anonymous = Service/flag(Signer/param(ps, "anonymous"))
  valid = (sig_size >= 1024) & (sig_size <= Signer/MAX_SIG_SIZE)
  error = Service/conf_error(valid, Service/empty(token) & (anonymous == 0))
  max_pdf = Service/min(Service/number(Signer/param(ps, "max_pdf"), Service/DEFAULT_MAX_PDF), Service/format_limit(valid, sig_size))
  return Conf/New(token, Signer/param(ps, "key"), Signer/param(ps, "cert"), Service/hosts(Signer/param(ps, "allowed_hosts")), max_pdf, sig_size, Service/flag(Signer/param(ps, "client_keys")), anonymous, Signer/or_default(Signer/param(ps, "jobs"), Bytes/from_string("jobs")), Service/number(Signer/param(ps, "job_timeout"), 3600), error)

def Service/conf_error(valid: u24, no_token: u24) -> List(u24):
  if valid == 0:
    return Bytes/from_string("server.conf: sig_size must be between 1024 and 262144")
  elif no_token:
    return Bytes/from_string("server.conf: set token (or anonymous=1 for local testing only)")
  else:
    return []

def Service/format_limit(valid: u24, sig_size: u24) -> u24:
  if valid:
    return 0xFFFFFF - 0x10000 - 2 * sig_size
  else:
    return 0

def Service/number(xs: List(u24), default: u24) -> u24:
  (st, v) = Http/content_length(xs)
  if st == 0:
    return v
  elif st == 2:
    return 0xFFFFFF
  else:
    return default

def Service/flag(xs: List(u24)) -> u24:
  return Bytes/equal(xs, [49])

def Service/empty(xs: List(u24)) -> u24:
  match xs:
    case List/Nil:
      return 1
    case List/Cons:
      return 0

def Service/min(a: u24, b: u24) -> u24:
  if a < b:
    return a
  else:
    return b

def Service/hosts(value: List(u24)) -> List(List(u24)):
  match value:
    case List/Nil:
      return [Bytes/from_string("localhost:8080"), Bytes/from_string("127.0.0.1:8080"), Bytes/from_string("[::1]:8080")]
    case List/Cons:
      return Service/hosts.go(Service/split(List/Cons(value.head, value.tail), 44, []))

def Service/hosts.go(items: List(List(u24))) -> List(List(u24)):
  match items:
    case List/Nil:
      return []
    case List/Cons:
      match h = Http/lower(Bytes/trim(items.head)):
        case List/Nil:
          return Service/hosts.go(items.tail)
        case List/Cons:
          return List/Cons(List/Cons(h.head, h.tail), Service/hosts.go(items.tail))

def Service/split(xs: List(u24), sep: u24, cur: List(u24)) -> List(List(u24)):
  match xs:
    case List/Nil:
      return [Bytes/reverse(cur)]
    case List/Cons:
      if xs.head == sep:
        return List/Cons(Bytes/reverse(cur), Service/split(xs.tail, sep, []))
      else:
        return Service/split(xs.tail, sep, List/Cons(xs.head, cur))

def Service/member(x: List(u24), xs: List(List(u24))) -> u24:
  match xs:
    case List/Nil:
      return 0
    case List/Cons:
      if Bytes/equal(x, xs.head):
        return 1
      else:
        return Service/member(x, xs.tail)

def Service/json_ctype() -> List(u24):
  return Bytes/from_string("application/json; charset=utf-8")

def Service/error_body(msg: List(u24)) -> List(u24):
  return Json/object_text([Json/member("error", Json/quote(msg))])

def Service/error(status: u24, msg: List(u24)) -> List(u24):
  return Http/response(status, Service/json_ctype, [], Service/error_body(msg))

def Service/reply(status: u24, msg: String) -> Route:
  return Route/Reply(status, Service/error(status, Bytes/from_string(msg)))

def Service/fail(status: u24, msg: List(u24)) -> Outcome:
  return Outcome/Reply(status, Service/error(status, msg))

def Service/route(text: List(u24), head: List(u24), complete: u24) -> Route:
  conf = Service/conf(text)
  open Conf: conf
  if complete == 2:
    return Service/reply(431, "request header too large")
  elif complete == 0:
    return Service/reply(400, "incomplete request")
  elif Service/empty(conf.error) == 0:
    return Route/Reply(500, Service/error(500, conf.error))
  else:
    (ok, req) = Http/parse(head)
    open Request: req
    (nhost, host) = Http/header(req.headers, Bytes/from_string("host"))
    (norigin, origin) = Http/header(req.headers, Bytes/from_string("origin"))
    lhost = Http/lower(host)
    if ok == 0:
      return Service/reply(400, "malformed request")
    elif (nhost != 1) | (Service/member(lhost, conf.hosts) == 0):
      return Service/reply(403, "host not allowed")
    elif (norigin > 1) | ((norigin == 1) & (Bytes/equal(Http/origin_host(origin), lhost) == 0)):
      return Service/reply(403, "cross-origin requests are not allowed")
    elif Bytes/equal(req.method, Bytes/from_string("GET")):
      return Service/get(conf.token, conf.anonymous, conf.key, conf.cert, req.path, req.headers)
    elif Bytes/equal(req.method, Bytes/from_string("POST")):
      return Service/post_head(conf.token, conf.anonymous, conf.max_pdf, req.path, req.headers)
    else:
      return Service/reply(405, "method not allowed")

def Service/auth(token: List(u24), anonymous: u24, headers) -> u24:
  (n, value) = Http/header(headers, Bytes/from_string("authorization"))
  if anonymous & Service/empty(token):
    return 1
  elif Service/empty(token):
    return 0
  else:
    return (n == 1) & Http/same(value, Bytes/concat(Bytes/from_string("Bearer "), token))

def Service/get(token: List(u24), anonymous: u24, key: List(u24), cert: List(u24), path: List(u24), headers) -> Route:
  if Bytes/equal(path, [47]):
    return Route/Reply(200, Http/response(200, Bytes/from_string("text/html; charset=utf-8"), [], Service/form))
  elif Bytes/equal(path, Bytes/from_string("/health")):
    has_key = (Service/empty(key) == 0) & (Service/empty(cert) == 0)
    return Route/Reply(200, Http/response(200, Service/json_ctype, [], Json/object_text([Json/member("status", Json/quote(Bytes/from_string("ok"))), Json/member("server_key", Json/bool_text(has_key))])))
  elif Service/auth(token, anonymous, headers) == 0:
    return Service/reply(401, "unauthorized")
  else:
    (kind, id) = Service/job_path(path)
    if kind == 1:
      return Route/Status(id)
    elif kind == 2:
      return Route/Download(id)
    else:
      return Service/reply(404, "not found")

def Service/job_path(path: List(u24)) -> (u24, List(u24)):
  (ok, rest) = Bytes/strip_prefix(path, Bytes/from_string("/api/v1/jobs/"))
  (id, tail) = Bytes/split(rest, 32)
  if ok & Service/hex_id(id, 0):
    match tail:
      case List/Nil:
        return (1, id)
      case List/Cons:
        if Bytes/equal(List/Cons(tail.head, tail.tail), Bytes/from_string("/pdf")):
          return (2, id)
        else:
          return (0, [])
  else:
    return (0, [])

def Service/hex_id(xs: List(u24), n: u24) -> u24:
  match xs:
    case List/Nil:
      return n == 32
    case List/Cons:
      c = xs.head
      if ((c >= 48) & (c <= 57)) | ((c >= 97) & (c <= 102)):
        return Service/hex_id(xs.tail, n + 1)
      else:
        return 0

def Service/post_head(token: List(u24), anonymous: u24, max_pdf: u24, path: List(u24), headers) -> Route:
  sign = Bytes/equal(path, Bytes/from_string("/api/v1/sign"))
  jobs = Bytes/equal(path, Bytes/from_string("/api/v1/jobs"))
  (nctype, ctype) = Http/header(headers, Bytes/from_string("content-type"))
  (nte, *) = Http/header(headers, Bytes/from_string("transfer-encoding"))
  (nlen, length) = Http/header(headers, Bytes/from_string("content-length"))
  (*, expect) = Http/header(headers, Bytes/from_string("expect"))
  (*, accept) = Http/header(headers, Bytes/from_string("accept"))
  (lst, n) = Http/content_length(length)
  max_body = Service/max_body(max_pdf)
  if (sign | jobs) == 0:
    return Service/reply(404, "not found")
  elif Service/auth(token, anonymous, headers) == 0:
    return Service/reply(401, "unauthorized")
  elif Bytes/equal(Http/media_type(ctype), Bytes/from_string("application/json")) == 0:
    return Service/reply(415, "Content-Type must be application/json")
  elif nte > 0:
    return Service/reply(400, "Transfer-Encoding is not supported")
  elif nlen == 0:
    return Service/reply(400, "empty body")
  elif (nlen > 1) | (lst == 1):
    return Service/reply(400, "invalid Content-Length")
  elif (lst == 2) | (n > max_body):
    return Service/reply(413, "body too large")
  elif n == 0:
    return Service/reply(400, "empty body")
  else:
    return Route/Body(jobs, n, Bytes/equal(Http/lower(expect), Bytes/from_string("100-continue")), Bytes/find(accept, Bytes/from_string("application/pdf")) != Bytes/NONE)

def Service/max_body(max_pdf: u24) -> u24:
  b = max_pdf / 3 * 4 + 4 + 1000000
  if b > 0xFFFFFF:
    return 0xFFFFFF
  else:
    return b

def Service/post(text: List(u24), kind: u24, accept_pdf: u24, body: List(u24), key_file: List(u24), cert_file: List(u24), stat: List(u24), uptime: List(u24), rand: List(u24)) -> Outcome:
  conf = Service/conf(text)
  open Conf: conf
  (ok, json) = Json/parse(body)
  if ok:
    match json:
      case Json/Obj:
        (pdf_json, others) = Service/split_pdf(json.entries, Json/Null, [])
        (st, msg, pdf) = Service/pdf_field(pdf_json, conf.max_pdf)
        if st:
          return Service/fail(st, msg)
        else:
          return Service/fields(others, pdf, conf.client_keys, key_file, cert_file, Service/time_param(stat, uptime), conf.sig_size, Service/mode(kind, accept_pdf), rand)
      case _:
        return Service/fail(400, Bytes/from_string("body must be a JSON object"))
  else:
    return Service/fail(400, Bytes/from_string("body must be valid JSON"))

def Service/mode(kind: u24, accept_pdf: u24) -> u24:
  if kind:
    return 2
  elif accept_pdf:
    return 1
  else:
    return 0

def Service/split_pdf(entries, pdf: Json, others) -> (Json, List((List(u24), Json))):
  match entries:
    case List/Nil:
      return (pdf, others)
    case List/Cons:
      (k, v) = entries.head
      if Bytes/equal(k, [112, 100, 102]):
        return Service/split_pdf(entries.tail, v, others)
      else:
        return Service/split_pdf(entries.tail, pdf, List/Cons((k, v), others))

def Service/lookup(entries, key: List(u24)) -> (u24, Json):
  match entries:
    case List/Nil:
      return (0, Json/Null)
    case List/Cons:
      (k, v) = entries.head
      if Bytes/equal(k, key):
        return (1, v)
      else:
        return Service/lookup(entries.tail, key)

def Service/pdf_field(json: Json, max_pdf: u24) -> (u24, List(u24), List(u24)):
  match json:
    case Json/Str:
      match s = json.bytes:
        case List/Nil:
          return (400, Bytes/from_string("missing 'pdf' (base64)"), [])
        case List/Cons:
          (ok, n, bytes) = Bytes/from_base64_strict(List/Cons(s.head, s.tail))
          (found, pdf) = Service/pdf_header(bytes)
          if ok == 0:
            return (400, Bytes/from_string("'pdf' is not valid base64"), [])
          elif found == 0:
            return (400, Bytes/from_string("'pdf' does not look like a PDF document"), [])
          elif n > max_pdf:
            return (413, Bytes/join([Bytes/from_string("the PDF exceeds the maximum of "), Bytes/from_u24(max_pdf), Bytes/from_string(" bytes")]), [])
          else:
            return (0, [], pdf)
    case _:
      return (400, Bytes/from_string("missing 'pdf' (base64)"), [])

def Service/pdf_header(bytes: List(u24)) -> (u24, List(u24)):
  (front, back) = Bytes/split(bytes, 1024)
  found = Bytes/find(front, Bytes/from_string("%PDF-")) != Bytes/NONE
  return (found, Bytes/concat(front, back))

def Service/text(field: (u24, Json), name: String) -> (u24, List(u24), List(u24)):
  (present, json) = field
  match json:
    case Json/Str:
      (n, s) = Service/chars(json.bytes)
      if n > Service/MAX_TEXT:
        return (400, Bytes/join([[39], Bytes/from_string(name), Bytes/from_string("' exceeds 512 characters")]), [])
      else:
        return (0, [], Bytes/trim(Service/one_line(s, 0)))
    case Json/Null:
      return (0, [], [])
    case _:
      return (400, Bytes/join([[39], Bytes/from_string(name), Bytes/from_string("' must be a string")]), [])

def Service/chars(xs: List(u24)) -> (u24, List(u24)):
  match xs:
    case List/Nil:
      return (0, [])
    case List/Cons:
      c = xs.head
      (n, rest) = Service/chars(xs.tail)
      if (c & 0xC0) == 0x80:
        return (n, List/Cons(c, rest))
      else:
        return (n + 1, List/Cons(c, rest))

def Service/one_line(xs: List(u24), in_break: u24) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      c = xs.head
      if (c == 10) | (c == 13):
        if in_break:
          return Service/one_line(xs.tail, 1)
        else:
          return List/Cons(32, Service/one_line(xs.tail, 1))
      else:
        return List/Cons(c, Service/one_line(xs.tail, 0))

def Service/fields(others, pdf: List(u24), client_keys: u24, key_file: List(u24), cert_file: List(u24), time: List(u24), sig_size: u24, mode: u24, rand: List(u24)) -> Outcome:
  (s1, m1, reason) = Service/text(Service/lookup(others, Bytes/from_string("reason")), "reason")
  (s2, m2, location) = Service/text(Service/lookup(others, Bytes/from_string("location")), "location")
  (s3, m3, contact) = Service/text(Service/lookup(others, Bytes/from_string("contact")), "contact")
  (has_key, key_json) = Service/lookup(others, Bytes/from_string("key"))
  (has_cert, cert_json) = Service/lookup(others, Bytes/from_string("cert"))
  (s4, m4, name) = Service/text(Service/lookup(others, Bytes/from_string("name")), "name")
  (pem_ok, key, cert) = Service/pems(key_json, cert_json)
  client = has_key | has_cert
  id = Bytes/to_hex(rand)
  base = Bytes/join([Service/param("reason", reason), Service/param("location", location), Service/param("contact", contact)])
  tail = Bytes/join([time, Bytes/from_string("sig_size="), Bytes/from_u24(sig_size), [10]])
  if s1:
    return Service/fail(s1, m1)
  elif s2:
    return Service/fail(s2, m2)
  elif s3:
    return Service/fail(s3, m3)
  elif client:
    if client_keys == 0:
      return Service/fail(403, Bytes/from_string("this server does not accept keys in requests"))
    elif pem_ok == 0:
      return Service/fail(400, Bytes/from_string("'key' and 'cert' must be PEM strings"))
    elif s4:
      return Service/fail(s4, m4)
    else:
      return Service/sign(mode, id, pdf, key, cert, Bytes/join([base, Service/param("name", name), tail]))
  elif Service/empty(key_file) | Service/empty(cert_file):
    return Service/fail(500, Bytes/from_string("the server has no signing key configured (key and cert in server.conf)"))
  else:
    return Service/sign(mode, id, pdf, key_file, cert_file, Bytes/concat(base, tail))

def Service/sign(mode: u24, id: List(u24), pdf: List(u24), key: List(u24), cert: List(u24), params: List(u24)) -> Outcome:
  (n, hex) = Bytes/measure(id)
  if (mode == 2) & (n != 32):
    return Service/fail(500, Bytes/from_string("no random source available for job ids"))
  else:
    return Outcome/Sign(mode, hex, pdf, key, cert, params)

def Service/pems(key: Json, cert: Json) -> (u24, List(u24), List(u24)):
  match key:
    case Json/Str:
      match cert:
        case Json/Str:
          return (1, key.bytes, cert.bytes)
        case _:
          return (0, [], [])
    case _:
      return (0, [], [])

def Service/param(name: String, value: List(u24)) -> List(u24):
  match value:
    case List/Nil:
      return []
    case List/Cons:
      return Bytes/join([Bytes/from_string(name), [61], List/Cons(value.head, value.tail), [10]])

def Service/time_param(stat: List(u24), uptime: List(u24)) -> List(u24):
  (ok, days, secs) = Clock/now(stat, uptime)
  if ok:
    return Bytes/join([Bytes/from_string("time="), Clock/stamp(days, secs), [10]])
  else:
    return []

def Service/signed(mode: u24, res) -> (u24, List(u24)):
  match res:
    case Result/Ok:
      if mode == 1:
        return (200, Http/response(200, Bytes/from_string("application/pdf"), [], res.val))
      else:
        return (200, Http/response(200, Service/json_ctype, [], Json/object_text([Json/member("pdf", Json/quote(Bytes/to_base64(res.val)))])))
    case Result/Err:
      return (422, Service/error(422, String/encode_utf8(res.val)))

def Service/accepted(id: List(u24)) -> List(u24):
  return Http/response(202, Service/json_ctype, [], Json/object_text([Json/member("id", Json/quote(id)), Json/member("status", Json/quote(Bytes/from_string("running")))]))

def Service/job_file(text: List(u24), id: List(u24), suffix: String) -> String:
  conf = Service/conf(text)
  open Conf: conf
  return Service/string(Bytes/join([conf.jobs, [47], id, Bytes/from_string(suffix)]))

def Service/key_path(text: List(u24)) -> String:
  conf = Service/conf(text)
  open Conf: conf
  return Service/string(conf.key)

def Service/cert_path(text: List(u24)) -> String:
  conf = Service/conf(text)
  open Conf: conf
  return Service/string(conf.cert)

def Service/string(xs: List(u24)) -> String:
  match xs:
    case List/Nil:
      return String/Nil
    case List/Cons:
      return String/Cons(xs.head, Service/string(xs.tail))

def Service/state_running(stat: List(u24), uptime: List(u24)) -> List(u24):
  (*, days, secs) = Clock/now(stat, uptime)
  return Bytes/join([Bytes/from_string("running\n"), Bytes/from_u24(days), [10], Bytes/from_u24(secs), [10]])

def Service/outcome(res) -> (u24, List(u24), List(u24)):
  match res:
    case Result/Ok:
      return (1, res.val, [])
    case Result/Err:
      return (0, [], Service/one_line(String/encode_utf8(res.val), 0))

def Service/state_final(running: List(u24), stat: List(u24), uptime: List(u24), ok: u24, msg: List(u24)) -> List(u24):
  (*, days, secs) = Clock/now(stat, uptime)
  match lines = Bytes/lines(running):
    case List/Nil:
      created = []
    case List/Cons:
      created = Bytes/join(Service/with_newlines(lines.tail))
  if ok:
    return Bytes/join([Bytes/from_string("done\n"), created, Bytes/from_u24(days), [10], Bytes/from_u24(secs), [10]])
  else:
    return Bytes/join([Bytes/from_string("error\n"), created, Bytes/from_u24(days), [10], Bytes/from_u24(secs), [10], msg, [10]])

def Service/with_newlines(lines: List(List(u24))) -> List(List(u24)):
  match lines:
    case List/Nil:
      return []
    case List/Cons:
      return List/Cons(Bytes/concat(lines.head, [10]), Service/with_newlines(lines.tail))

def Service/job_status(id: List(u24), text: List(u24), stat: List(u24), uptime: List(u24), timeout: List(u24)) -> List(u24):
  (ok, nd, ns) = Clock/now(stat, uptime)
  (state, cd, cs, fd, fs, msg) = Service/state_fields(Bytes/lines(text))
  limit = Service/number(timeout, 3600)
  created = Json/member("created", Json/quote(Clock/iso(cd, cs)))
  finished = Json/member("finished", Json/quote(Clock/iso(fd, fs)))
  head = Json/member("id", Json/quote(id))
  if Bytes/equal(state, Bytes/from_string("running")):
    if ok & (Clock/elapsed(cd, cs, nd, ns) > limit):
      return Service/status_reply([head, Service/status_member("error"), created, Json/member("error", Json/quote(Bytes/from_string("the signer stopped before finishing")))])
    else:
      return Service/status_reply([head, Service/status_member("running"), created])
  elif Bytes/equal(state, Bytes/from_string("done")):
    return Service/status_reply([head, Service/status_member("done"), created, finished])
  elif Bytes/equal(state, Bytes/from_string("error")):
    return Service/status_reply([head, Service/status_member("error"), created, finished, Json/member("error", Json/quote(msg))])
  else:
    return Service/error(500, Bytes/from_string("corrupt job record"))

def Service/status_member(state: String) -> List(u24):
  return Json/member("status", Json/quote(Bytes/from_string(state)))

def Service/status_reply(members: List(List(u24))) -> List(u24):
  return Http/response(200, Service/json_ctype, [], Json/object_text(members))

def Service/state_fields(lines: List(List(u24))) -> (List(u24), u24, u24, u24, u24, List(u24)):
  (state, r1) = Service/next_line(lines)
  (cd, r2) = Service/next_number(r1)
  (cs, r3) = Service/next_number(r2)
  (fd, r4) = Service/next_number(r3)
  (fs, r5) = Service/next_number(r4)
  (msg, *) = Service/next_line(r5)
  return (state, cd, cs, fd, fs, msg)

def Service/next_line(lines: List(List(u24))) -> (List(u24), List(List(u24))):
  match lines:
    case List/Nil:
      return ([], [])
    case List/Cons:
      return (lines.head, lines.tail)

def Service/next_number(lines: List(List(u24))) -> (u24, List(List(u24))):
  (line, rest) = Service/next_line(lines)
  (v, *, *) = Bytes/parse_u24(line)
  return (v, rest)

def Service/job_done(text: List(u24)) -> u24:
  (state, *) = Service/next_line(Bytes/lines(text))
  return Bytes/equal(state, Bytes/from_string("done"))

def Service/job_conflict(text: List(u24)) -> List(u24):
  (state, *) = Service/next_line(Bytes/lines(text))
  return Service/error(409, Bytes/join([Bytes/from_string("the job is in state '"), state, [39]]))

def Service/job_download(pdf: List(u24)) -> List(u24):
  return Http/response(200, Bytes/from_string("application/pdf"), Bytes/from_string("Content-Disposition: attachment; filename=\"signed.pdf\"\r\n"), pdf)

def Service/job_missing() -> List(u24):
  return Service/error(404, Bytes/from_string("job not found"))

def Service/job_unwritable() -> List(u24):
  return Service/error(500, Bytes/from_string("the jobs directory is not writable"))

def Service/conf_timeout(text: List(u24)) -> List(u24):
  return Signer/param(Signer/parse_params(text), "job_timeout")

def Service/log(head: List(u24), status: u24) -> List(u24):
  (*, req) = Http/parse(head)
  open Request: req
  return Bytes/join([Service/or_dash(req.method), [32], Service/or_dash(req.path), [32], Bytes/from_u24(status), [10]])

def Service/or_dash(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return [45]
    case List/Cons:
      return List/Cons(xs.head, xs.tail)

def Service/form() -> List(u24):
  return Bytes/join([Service/form1, Service/form2, Service/form3, Service/form4, Service/form5])

def Service/form1() -> List(u24):
  return Bytes/from_string("<!doctype html>\n<html lang='en'><head><meta charset='utf-8'><title>sign_engine</title>\n<meta name='viewport' content='width=device-width, initial-scale=1'>\n<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}\nlabel{display:block;margin:.8rem 0 .2rem}input{width:100%;padding:.4rem}\nbutton{margin-top:1rem;padding:.6rem 1.2rem}#out{margin-top:1rem;white-space:pre-wrap}</style>\n</head><body>\n")

def Service/form2() -> List(u24):
  return Bytes/from_string("<h1>PDF signing (Bend)</h1>\n<form id='f'>\n<label>PDF</label><input type='file' id='pdf' accept='application/pdf' required>\n<label>Reason</label><input id='reason'>\n<label>Location</label><input id='location'>\n<label>Contact</label><input id='contact'>\n<label>API token</label><input id='token' type='password'>\n<button>Sign</button></form>\n<div id='out'></div>\n")

def Service/form3() -> List(u24):
  return Bytes/from_string("<script>\nconst out = document.getElementById('out');\ndocument.getElementById('f').onsubmit = async (ev) => {\n  ev.preventDefault();\n  const file = document.getElementById('pdf').files[0];\n  const buf = new Uint8Array(await file.arrayBuffer());\n  let bin = ''; for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode(...buf.subarray(i, i + 0x8000));\n  const body = {pdf: btoa(bin)};\n")

def Service/form4() -> List(u24):
  return Bytes/from_string("  for (const k of ['reason', 'location', 'contact']) { const v = document.getElementById(k).value; if (v) body[k] = v; }\n  const headers = {'Content-Type': 'application/json'};\n  const token = document.getElementById('token').value; if (token) headers['Authorization'] = 'Bearer ' + token;\n  out.textContent = 'Sending...';\n  const r = await fetch('/api/v1/jobs', {method: 'POST', headers, body: JSON.stringify(body)});\n  const j = await r.json(); if (!r.ok) { out.textContent = 'Error: ' + j.error; return; }\n")

def Service/form5() -> List(u24):
  return Bytes/from_string("  while (true) {\n    await new Promise(res => setTimeout(res, 2000));\n    const s = await (await fetch('/api/v1/jobs/' + j.id, {headers})).json();\n    out.textContent = 'Status: ' + s.status + (s.error ? ' - ' + s.error : '');\n    if (s.status === 'done') {\n      const pdf = await (await fetch('/api/v1/jobs/' + j.id + '/pdf', {headers})).blob();\n      const a = document.createElement('a'); a.href = URL.createObjectURL(pdf);\n      a.download = file.name.replace(/[.]pdf$/i, '') + '-signed.pdf'; a.textContent = 'Download signed PDF';\n      out.textContent = ''; out.appendChild(a); break;\n    }\n    if (s.status === 'error') break;\n  }\n};\n</script></body></html>\n")
