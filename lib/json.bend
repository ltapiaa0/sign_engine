from lib/bytes import *
from lib/text import *

type Json:
  Str { bytes }
  Num { raw }
  Bool { val }
  Null
  Arr { items }
  Obj { entries }

def Json/MAX_DEPTH() -> u24:
  return 64

def Json/parse(xs: List(u24)) -> (u24, Json):
  (ok, v, rest) = Json/value(Json/ws(xs), 0)
  match r = Json/ws(rest):
    case List/Nil:
      return (ok, v)
    case List/Cons:
      return (0, Json/Null)

def Json/ws(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      c = xs.head
      if (c == 32) | (c == 9) | (c == 10) | (c == 13):
        return Json/ws(xs.tail)
      else:
        return List/Cons(c, xs.tail)

def Json/value(xs: List(u24), depth: u24) -> (u24, Json, List(u24)):
  match xs:
    case List/Nil:
      return (0, Json/Null, [])
    case List/Cons:
      c = xs.head
      if depth > Json/MAX_DEPTH:
        return (0, Json/Null, [])
      elif c == 34:
        (ok, s, rest) = Json/string(xs.tail)
        return (ok, Json/Str(s), rest)
      elif c == 123:
        return Json/object(Json/ws(xs.tail), depth + 1)
      elif c == 91:
        return Json/array(Json/ws(xs.tail), depth + 1)
      elif c == 116:
        (ok, rest) = Bytes/strip_prefix(xs.tail, [114, 117, 101])
        return (ok, Json/Bool(1), rest)
      elif c == 102:
        (ok, rest) = Bytes/strip_prefix(xs.tail, [97, 108, 115, 101])
        return (ok, Json/Bool(0), rest)
      elif c == 110:
        (ok, rest) = Bytes/strip_prefix(xs.tail, [117, 108, 108])
        return (ok, Json/Null, rest)
      else:
        (ok, raw, rest) = Json/number(List/Cons(c, xs.tail), 0)
        return (ok, Json/Num(raw), rest)

def Json/number(xs: List(u24), st: u24) -> (u24, List(u24), List(u24)):
  match xs:
    case List/Nil:
      return (Json/accepting(st), [], [])
    case List/Cons:
      c = xs.head
      n = Json/num_next(st, c)
      if n == 0xFF:
        return (Json/accepting(st), [], List/Cons(c, xs.tail))
      else:
        (ok, raw, rest) = Json/number(xs.tail, n)
        return (ok, List/Cons(c, raw), rest)

def Json/accepting(st: u24) -> u24:
  return (st == 2) | (st == 3) | (st == 5) | (st == 8)

def Json/num_next(st: u24, c: u24) -> u24:
  digit = Bytes/is_digit(c)
  exp = (c == 101) | (c == 69)
  if st == 0:
    if c == 45:
      return 1
    elif c == 48:
      return 2
    elif digit:
      return 3
    else:
      return 0xFF
  elif st == 1:
    if c == 48:
      return 2
    elif digit:
      return 3
    else:
      return 0xFF
  elif (st == 2) | (st == 3):
    if (st == 3) & digit:
      return 3
    elif c == 46:
      return 4
    elif exp:
      return 6
    else:
      return 0xFF
  elif (st == 4) | (st == 5):
    if digit:
      return 5
    elif (st == 5) & exp:
      return 6
    else:
      return 0xFF
  elif st == 6:
    if (c == 43) | (c == 45):
      return 7
    elif digit:
      return 8
    else:
      return 0xFF
  elif digit:
    return 8
  else:
    return 0xFF

def Json/string(xs: List(u24)) -> (u24, List(u24), List(u24)):
  match xs:
    case List/Nil:
      return (0, [], [])
    case List/Cons:
      c = xs.head
      if c == 34:
        return (1, [], xs.tail)
      elif c == 92:
        return Json/escape(xs.tail)
      elif c < 32:
        return (0, [], [])
      else:
        (ok, s, rest) = Json/string(xs.tail)
        return (ok, List/Cons(c, s), rest)

def Json/escape(xs: List(u24)) -> (u24, List(u24), List(u24)):
  match xs:
    case List/Nil:
      return (0, [], [])
    case List/Cons:
      e = xs.head
      if e == 117:
        (cp, n, rest, *) = Json/hex4(xs.tail, 0, 0, [])
        if n < 4:
          return (0, [], [])
        elif (cp >= 0xD800) & (cp < 0xDC00):
          (found, lo, rest2) = Json/low(rest)
          if found:
            (ok, s, r) = Json/string(rest2)
            return (ok, Bytes/concat(Text/utf8_encode([0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)]), s), r)
          else:
            (ok, s, r) = Json/string(rest2)
            return (ok, Bytes/concat(Text/utf8_encode([Text/REPLACEMENT]), s), r)
        else:
          (ok, s, r) = Json/string(rest)
          return (ok, Bytes/concat(Text/utf8_encode([cp]), s), r)
      else:
        b = Json/unescape(e)
        if b == 0xFF:
          return (0, [], [])
        else:
          (ok, s, rest) = Json/string(xs.tail)
          return (ok, List/Cons(b, s), rest)

def Json/unescape(e: u24) -> u24:
  if (e == 34) | (e == 92) | (e == 47):
    return e
  elif e == 98:
    return 8
  elif e == 102:
    return 12
  elif e == 110:
    return 10
  elif e == 114:
    return 13
  elif e == 116:
    return 9
  else:
    return 0xFF

def Json/hex4(xs: List(u24), v: u24, n: u24, used: List(u24)) -> (u24, u24, List(u24), List(u24)):
  if n == 4:
    return (v, n, xs, Bytes/reverse(used))
  else:
    match xs:
      case List/Nil:
        return (v, n, [], Bytes/reverse(used))
      case List/Cons:
        h = Bytes/hex_value(xs.head)
        if h == 0xFF:
          return (v, n, List/Cons(xs.head, xs.tail), Bytes/reverse(used))
        else:
          return Json/hex4(xs.tail, (v << 4) | h, n + 1, List/Cons(xs.head, used))

def Json/low(xs: List(u24)) -> (u24, u24, List(u24)):
  (ok, r1) = Bytes/strip_prefix(xs, [92, 117])
  if ok:
    (v, n, r2, used) = Json/hex4(r1, 0, 0, [])
    if (n == 4) & (v >= 0xDC00) & (v < 0xE000):
      return (1, v, r2)
    else:
      return (0, 0, List/Cons(92, List/Cons(117, Bytes/concat(used, r2))))
  else:
    return (0, 0, r1)

def Json/object(xs: List(u24), depth: u24) -> (u24, Json, List(u24)):
  match xs:
    case List/Nil:
      return (0, Json/Null, [])
    case List/Cons:
      if xs.head == 125:
        return (1, Json/Obj([]), xs.tail)
      else:
        return Json/members(List/Cons(xs.head, xs.tail), depth, [])

def Json/members(xs: List(u24), depth: u24, acc) -> (u24, Json, List(u24)):
  match xs:
    case List/Nil:
      return (0, Json/Null, [])
    case List/Cons:
      if xs.head == 34:
        (ok, key, r1) = Json/string(xs.tail)
        (colon, r2) = Bytes/strip_prefix(Json/ws(r1), [58])
        if ok & colon:
          (ok2, v, r3) = Json/value(Json/ws(r2), depth)
          match r4 = Json/ws(r3):
            case List/Nil:
              return (0, Json/Null, [])
            case List/Cons:
              if ok2 & (r4.head == 44):
                return Json/members(Json/ws(r4.tail), depth, List/Cons((key, v), acc))
              elif ok2 & (r4.head == 125):
                return (1, Json/Obj(Json/reverse(List/Cons((key, v), acc), [])), r4.tail)
              else:
                return (0, Json/Null, [])
        else:
          return (0, Json/Null, [])
      else:
        return (0, Json/Null, [])

def Json/array(xs: List(u24), depth: u24) -> (u24, Json, List(u24)):
  match xs:
    case List/Nil:
      return (0, Json/Null, [])
    case List/Cons:
      if xs.head == 93:
        return (1, Json/Arr([]), xs.tail)
      else:
        return Json/items(List/Cons(xs.head, xs.tail), depth, [])

def Json/items(xs: List(u24), depth: u24, acc) -> (u24, Json, List(u24)):
  (ok, v, r1) = Json/value(xs, depth)
  match r2 = Json/ws(r1):
    case List/Nil:
      return (0, Json/Null, [])
    case List/Cons:
      if ok & (r2.head == 44):
        return Json/items(Json/ws(r2.tail), depth, List/Cons(v, acc))
      elif ok & (r2.head == 93):
        return (1, Json/Arr(Json/reverse(List/Cons(v, acc), [])), r2.tail)
      else:
        return (0, Json/Null, [])

def Json/reverse(xs, acc):
  match xs:
    case List/Nil:
      return acc
    case List/Cons:
      return Json/reverse(xs.tail, List/Cons(xs.head, acc))

def Json/quote(s: List(u24)) -> List(u24):
  return List/Cons(34, Json/quote.go(s))

def Json/quote.go(s: List(u24)) -> List(u24):
  match s:
    case List/Nil:
      return [34]
    case List/Cons:
      c = s.head
      rest = Json/quote.go(s.tail)
      if (c == 34) | (c == 92):
        return List/Cons(92, List/Cons(c, rest))
      elif c == 10:
        return List/Cons(92, List/Cons(110, rest))
      elif c == 13:
        return List/Cons(92, List/Cons(114, rest))
      elif c == 9:
        return List/Cons(92, List/Cons(116, rest))
      elif c < 32:
        return Bytes/concat([92, 117, 48, 48, Bytes/hex_digit(c >> 4), Bytes/hex_digit(c & 15)], rest)
      else:
        return List/Cons(c, rest)

def Json/member(key: String, value: List(u24)) -> List(u24):
  return Bytes/join([Json/quote(Bytes/from_string(key)), [58, 32], value])

def Json/object_text(members: List(List(u24))) -> List(u24):
  return List/Cons(123, Json/members_text(members))

def Json/members_text(members: List(List(u24))) -> List(u24):
  match members:
    case List/Nil:
      return [125]
    case List/Cons:
      match rest = members.tail:
        case List/Nil:
          return Bytes/concat(members.head, [125])
        case List/Cons:
          return Bytes/concat(members.head, List/Cons(44, List/Cons(32, Json/members_text(List/Cons(rest.head, rest.tail)))))

def Json/bool_text(b: u24) -> List(u24):
  if b:
    return [116, 114, 117, 101]
  else:
    return [102, 97, 108, 115, 101]
