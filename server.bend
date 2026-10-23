from lib/bytes import *
from lib/http import *
from lib/service import *
from lib/signer import *

def Main/CHUNK() -> u24:
  return 1048576

def Main/MAX_HEAD() -> u24:
  return 16384

def Main/reverse(xs, acc):
  match xs:
    case List/Nil:
      return acc
    case List/Cons:
      return Main/reverse(xs.tail, List/Cons(xs.head, acc))

def Main/min(a: u24, b: u24) -> u24:
  if a < b:
    return a
  else:
    return b

def Main/empty(xs: List(u24)) -> u24:
  match xs:
    case List/Nil:
      return 1
    case List/Cons:
      return 0

def Main/assemble(chunks) -> List(u24):
  return Bytes/from_io(Bytes/join(Main/reverse(chunks, [])))

def Main/measure(xs: List(u24)) -> (u24, List(u24)):
  return Bytes/measure(xs)

def Main/bytes(xs: List(u24)) -> List(u24):
  return Bytes/from_io(xs)

def Main/head_state(st: u24, b: u24) -> u24:
  if b == 10:
    if st == 1:
      return 2
    else:
      return 1
  elif b == 13:
    return st
  else:
    return 0

def Main/route(conf: List(u24), head: List(u24), complete: u24) -> Route:
  return Service/route(conf, head, complete)

def Main/post(conf: List(u24), kind: u24, accept_pdf: u24, body: List(u24), key: List(u24), cert: List(u24), stat: List(u24), uptime: List(u24), rand: List(u24)) -> Outcome:
  return Service/post(conf, kind, accept_pdf, body, key, cert, stat, uptime, rand)

def Main/sign(pdf: List(u24), key: List(u24), cert: List(u24), params: List(u24)):
  return Signer/sign_pdf(pdf, key, cert, params)

def Main/signed(mode: u24, res) -> (u24, List(u24)):
  return Service/signed(mode, res)

def Main/outcome(res) -> (u24, List(u24), List(u24)):
  return Service/outcome(res)

def Main/continue_bytes() -> List(u24):
  return Http/continue

def Main/accepted(id: List(u24)) -> List(u24):
  return Service/accepted(id)

def Main/job_file(conf: List(u24), id: List(u24), suffix: String) -> String:
  return Service/job_file(conf, id, suffix)

def Main/key_path(conf: List(u24)) -> String:
  return Service/key_path(conf)

def Main/cert_path(conf: List(u24)) -> String:
  return Service/cert_path(conf)

def Main/state_running(stat: List(u24), uptime: List(u24)) -> List(u24):
  return Service/state_running(stat, uptime)

def Main/state_final(running: List(u24), stat: List(u24), uptime: List(u24), ok: u24, msg: List(u24)) -> List(u24):
  return Service/state_final(running, stat, uptime, ok, msg)

def Main/job_status(id: List(u24), text: List(u24), stat: List(u24), uptime: List(u24), conf: List(u24)) -> List(u24):
  return Service/job_status(id, text, stat, uptime, Service/conf_timeout(conf))

def Main/job_done(text: List(u24)) -> u24:
  return Service/job_done(text)

def Main/job_conflict(text: List(u24)) -> List(u24):
  return Service/job_conflict(text)

def Main/job_download(pdf: List(u24)) -> List(u24):
  return Service/job_download(pdf)

def Main/job_missing() -> List(u24):
  return Service/job_missing

def Main/job_unwritable() -> List(u24):
  return Service/job_unwritable

def Main/log_line(head: List(u24), status: u24) -> List(u24):
  return Service/log(head, status)

def Main/read_chunks(fd: u24, chunks):
  with IO:
    res <- IO/FS/read(fd, Main/CHUNK)
    match res:
      case Result/Ok:
        match chunk = res.val:
          case List/Nil:
            return wrap(Main/assemble(chunks))
          case List/Cons:
            return Main/read_chunks(fd, List/Cons(chunk, chunks))
      case Result/Err:
        return wrap([])

def Main/read_file(path: String):
  with IO:
    opened <- IO/FS/open(path, "r")
    match opened:
      case Result/Ok:
        data <- Main/read_chunks(opened.val, [])
        * <- IO/FS/close(opened.val)
        return wrap(data)
      case Result/Err:
        return wrap([])

def Main/read_head(acc, st: u24, n: u24):
  with IO:
    res <- IO/FS/read(0, 1)
    match res:
      case Result/Ok:
        match bs = res.val:
          case List/Nil:
            return wrap((0, Main/reverse(acc, [])))
          case List/Cons:
            b = bs.head & 0xFF
            st2 = Main/head_state(st, b)
            if st2 == 2:
              return wrap((1, Main/reverse(List/Cons(b, acc), [])))
            elif n >= Main/MAX_HEAD:
              return wrap((2, []))
            else:
              return Main/read_head(List/Cons(b, acc), st2, n + 1)
      case Result/Err:
        return wrap((0, Main/reverse(acc, [])))

def Main/read_exact(n: u24, chunks):
  with IO:
    res <- IO/FS/read(0, Main/min(n, Main/CHUNK))
    match res:
      case Result/Ok:
        (got, chunk) = Main/measure(res.val)
        if (got == 0) | (got >= n):
          return wrap(Main/assemble(List/Cons(chunk, chunks)))
        else:
          return Main/read_exact(n - got, List/Cons(chunk, chunks))
      case Result/Err:
        return wrap([])

def Main/random(kind: u24):
  with IO:
    if kind:
      opened <- IO/FS/open("/dev/urandom", "r")
      match opened:
        case Result/Ok:
          res <- IO/FS/read(opened.val, 16)
          * <- IO/FS/close(opened.val)
          match res:
            case Result/Ok:
              return wrap(Main/bytes(res.val))
            case Result/Err:
              return wrap([])
        case Result/Err:
          return wrap([])
    else:
      return wrap([])

def Main/send(bytes: List(u24)):
  with IO:
    * <- IO/FS/write(1, bytes)
    * <- IO/FS/flush(1)
    return wrap(0)

def Main/log(head: List(u24), status: u24):
  with IO:
    * <- IO/FS/write(2, Main/log_line(head, status))
    * <- IO/FS/flush(2)
    return wrap(0)

def Main/reply(head: List(u24), status: u24, response: List(u24)):
  with IO:
    * <- Main/send(response)
    * <- Main/log(head, status)
    return wrap(0)

def Main/continue(expect: u24):
  with IO:
    if expect:
      * <- Main/send(Main/continue_bytes)
      return wrap(0)
    else:
      return wrap(0)

def Main/write_pdf(conf: List(u24), id: List(u24), ok: u24, pdf: List(u24)):
  with IO:
    if ok:
      * <- IO/FS/write_file(Main/job_file(conf, id, ".pdf"), pdf)
      return wrap(0)
    else:
      return wrap(0)

def Main/complete(conf: List(u24), id: List(u24), running: List(u24), pdf: List(u24), key: List(u24), cert: List(u24), params: List(u24)):
  with IO:
    (ok, signed, msg) = Main/outcome(Main/sign(pdf, key, cert, params))
    * <- Main/write_pdf(conf, id, ok, signed)
    stat <- Main/read_file("/proc/stat")
    uptime <- Main/read_file("/proc/uptime")
    * <- IO/FS/write_file(Main/job_file(conf, id, ".status"), Main/state_final(running, stat, uptime, ok, msg))
    return wrap(0)

def Main/job(conf: List(u24), head: List(u24), id: List(u24), pdf: List(u24), key: List(u24), cert: List(u24), params: List(u24), stat: List(u24), uptime: List(u24)):
  with IO:
    running = Main/state_running(stat, uptime)
    written <- IO/FS/write_file(Main/job_file(conf, id, ".status"), running)
    match written:
      case Result/Ok:
        * <- Main/reply(head, 202, Main/accepted(id))
        * <- IO/FS/close(1)
        closed <- IO/FS/close(0)
        match closed:
          case Result/Ok:
            * <- Main/complete(conf, id, running, pdf, key, cert, params)
            return wrap(0)
          case Result/Err:
            * <- Main/complete(conf, id, running, pdf, key, cert, params)
            return wrap(0)
      case Result/Err:
        * <- Main/reply(head, 500, Main/job_unwritable)
        return wrap(0)

def Main/handle_post(conf: List(u24), head: List(u24), kind: u24, accept_pdf: u24, body: List(u24)):
  with IO:
    key <- Main/read_file(Main/key_path(conf))
    cert <- Main/read_file(Main/cert_path(conf))
    stat <- Main/read_file("/proc/stat")
    uptime <- Main/read_file("/proc/uptime")
    rand <- Main/random(kind)
    match out = Main/post(conf, kind, accept_pdf, body, key, cert, stat, uptime, rand):
      case Outcome/Reply:
        * <- Main/reply(head, out.status, out.response)
        return wrap(0)
      case Outcome/Sign:
        if out.mode == 2:
          * <- Main/job(conf, head, out.id, out.pdf, out.key, out.cert, out.params, stat, uptime)
          return wrap(0)
        else:
          (status, response) = Main/signed(out.mode, Main/sign(out.pdf, out.key, out.cert, out.params))
          * <- Main/reply(head, status, response)
          return wrap(0)

def Main/status(conf: List(u24), head: List(u24), id: List(u24)):
  with IO:
    text <- Main/read_file(Main/job_file(conf, id, ".status"))
    stat <- Main/read_file("/proc/stat")
    uptime <- Main/read_file("/proc/uptime")
    if Main/empty(text):
      * <- Main/reply(head, 404, Main/job_missing)
      return wrap(0)
    else:
      * <- Main/reply(head, 200, Main/job_status(id, text, stat, uptime, conf))
      return wrap(0)

def Main/download(conf: List(u24), head: List(u24), id: List(u24)):
  with IO:
    text <- Main/read_file(Main/job_file(conf, id, ".status"))
    if Main/empty(text):
      * <- Main/reply(head, 404, Main/job_missing)
      return wrap(0)
    elif Main/job_done(text):
      pdf <- Main/read_file(Main/job_file(conf, id, ".pdf"))
      * <- Main/reply(head, 200, Main/job_download(pdf))
      return wrap(0)
    else:
      * <- Main/reply(head, 409, Main/job_conflict(text))
      return wrap(0)

def main():
  with IO:
    conf <- Main/read_file("server.conf")
    request <- Main/read_head([], 0, 0)
    (complete, head) = request
    match route = Main/route(conf, head, complete):
      case Route/Reply:
        * <- Main/reply(head, route.status, route.response)
        return wrap(0)
      case Route/Body:
        * <- Main/continue(route.expect)
        body <- Main/read_exact(route.length, [])
        * <- Main/handle_post(conf, head, route.kind, route.accept_pdf, body)
        return wrap(0)
      case Route/Status:
        * <- Main/status(conf, head, route.id)
        return wrap(0)
      case Route/Download:
        * <- Main/download(conf, head, route.id)
        return wrap(0)
