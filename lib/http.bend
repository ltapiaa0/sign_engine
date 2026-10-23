from lib/bytes import *

type Request:
  New { method, path, headers }

def Http/lower(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      c = xs.head
      if (c >= 65) & (c <= 90):
        return List/Cons(c + 32, Http/lower(xs.tail))
      else:
        return List/Cons(c, Http/lower(xs.tail))

def Http/words(xs: List(u24), cur: List(u24)) -> List(List(u24)):
  match xs:
    case List/Nil:
      match cur:
        case List/Nil:
          return []
        case List/Cons:
          return [Bytes/reverse(List/Cons(cur.head, cur.tail))]
    case List/Cons:
      if xs.head == 32:
        match cur:
          case List/Nil:
            return Http/words(xs.tail, [])
          case List/Cons:
            return List/Cons(Bytes/reverse(List/Cons(cur.head, cur.tail)), Http/words(xs.tail, []))
      else:
        return Http/words(xs.tail, List/Cons(xs.head, cur))

def Http/parse(head: List(u24)) -> (u24, Request):
  match lines = Bytes/lines(head):
    case List/Nil:
      return (0, Request/New([], [], []))
    case List/Cons:
      (ok1, method, target) = Http/request_line(Http/words(lines.head, []))
      (ok2, headers) = Http/headers(lines.tail, [])
      return (ok1 & ok2, Request/New(method, Http/path(target), headers))

def Http/request_line(words: List(List(u24))) -> (u24, List(u24), List(u24)):
  match words:
    case List/Nil:
      return (0, [], [])
    case List/Cons:
      match w2 = words.tail:
        case List/Nil:
          return (0, [], [])
        case List/Cons:
          match w3 = w2.tail:
            case List/Nil:
              return (0, [], [])
            case List/Cons:
              (version_ok, *) = Bytes/strip_prefix(w3.head, Bytes/from_string("HTTP/1."))
              (slash, target) = Bytes/pop(w2.head)
              match w3.tail:
                case List/Nil:
                  return (version_ok & (slash == 47), words.head, List/Cons(slash, target))
                case List/Cons:
                  return (0, [], [])

def Http/path(target: List(u24)) -> List(u24):
  match target:
    case List/Nil:
      return []
    case List/Cons:
      c = target.head
      if (c == 63) | (c == 35):
        return []
      else:
        return List/Cons(c, Http/path(target.tail))

def Http/headers(lines: List(List(u24)), acc) -> (u24, List((List(u24), List(u24)))):
  match lines:
    case List/Nil:
      return (1, acc)
    case List/Cons:
      match line = lines.head:
        case List/Nil:
          return (1, acc)
        case List/Cons:
          c = line.head
          colon = Bytes/find(List/Cons(c, line.tail), [58])
          if (c == 32) | (c == 9) | (colon == Bytes/NONE) | (colon == 0):
            return (0, [])
          else:
            (name, rest) = Bytes/split(List/Cons(c, line.tail), colon)
            if Http/token(name):
              return Http/headers(lines.tail, List/Cons((Http/lower(name), Bytes/trim(Bytes/drop(rest, 1))), acc))
            else:
              return (0, [])

def Http/token(xs: List(u24)) -> u24:
  match xs:
    case List/Nil:
      return 1
    case List/Cons:
      c = xs.head
      if (c <= 32) | (c >= 127) | (c == 58):
        return 0
      else:
        return Http/token(xs.tail)

def Http/header(headers: List((List(u24), List(u24))), name: List(u24)) -> (u24, List(u24)):
  match headers:
    case List/Nil:
      return (0, [])
    case List/Cons:
      (k, v) = headers.head
      (n, value) = Http/header(headers.tail, name)
      if Bytes/equal(k, name):
        return (n + 1, v)
      else:
        return (n, value)

def Http/same(a: List(u24), b: List(u24)) -> u24:
  return Http/same.go(a, b, 0)

def Http/same.go(a: List(u24), b: List(u24), diff: u24) -> u24:
  match a:
    case List/Nil:
      match b:
        case List/Nil:
          return diff == 0
        case List/Cons:
          return 0
    case List/Cons:
      match b:
        case List/Nil:
          return 0
        case List/Cons:
          return Http/same.go(a.tail, b.tail, diff | (a.head ^ b.head))

def Http/media_type(value: List(u24)) -> List(u24):
  return Http/lower(Bytes/trim(Bytes/take(value, Bytes/find(value, [59]))))

def Http/origin_host(origin: List(u24)) -> List(u24):
  p = Bytes/find(origin, [58, 47, 47])
  if p == Bytes/NONE:
    return []
  else:
    return Http/lower(Http/until_slash(Bytes/drop(origin, p + 3)))

def Http/until_slash(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      c = xs.head
      if (c == 47) | (c == 63) | (c == 35):
        return []
      else:
        return List/Cons(c, Http/until_slash(xs.tail))

def Http/content_length(value: List(u24)) -> (u24, u24):
  return Http/content_length.go(value, 0, 0, 0)

def Http/content_length.go(xs: List(u24), v: u24, digits: u24, over: u24) -> (u24, u24):
  match xs:
    case List/Nil:
      if digits == 0:
        return (1, 0)
      elif over:
        return (2, 0)
      else:
        return (0, v)
    case List/Cons:
      c = xs.head
      if Bytes/is_digit(c):
        d = c - 48
        if over | (v > 1677721) | ((v == 1677721) & (d > 5)):
          return Http/content_length.go(xs.tail, 0, digits + 1, 1)
        else:
          return Http/content_length.go(xs.tail, v * 10 + d, digits + 1, 0)
      else:
        return (1, 0)

def Http/reason(status: u24) -> String:
  if status == 100:
    return "Continue"
  elif status == 200:
    return "OK"
  elif status == 202:
    return "Accepted"
  elif status == 400:
    return "Bad Request"
  elif status == 401:
    return "Unauthorized"
  elif status == 403:
    return "Forbidden"
  elif status == 404:
    return "Not Found"
  elif status == 405:
    return "Method Not Allowed"
  elif status == 409:
    return "Conflict"
  elif status == 413:
    return "Payload Too Large"
  elif status == 415:
    return "Unsupported Media Type"
  elif status == 422:
    return "Unprocessable Content"
  elif status == 431:
    return "Request Header Fields Too Large"
  elif status == 500:
    return "Internal Server Error"
  else:
    return "Error"

def Http/response(status: u24, ctype: List(u24), extra: List(u24), body: List(u24)) -> List(u24):
  (n, content) = Bytes/measure(body)
  return Bytes/join([Bytes/from_string("HTTP/1.1 "), Bytes/from_u24(status), [32], Bytes/from_string(Http/reason(status)), [13, 10], Bytes/from_string("Content-Type: "), ctype, [13, 10], Bytes/from_string("Content-Length: "), Bytes/from_u24(n), [13, 10], Bytes/from_string("X-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nConnection: close\r\n"), extra, [13, 10], content])

def Http/continue() -> List(u24):
  return [72, 84, 84, 80, 47, 49, 46, 49, 32, 49, 48, 48, 32, 67, 111, 110, 116, 105, 110, 117, 101, 13, 10, 13, 10]
