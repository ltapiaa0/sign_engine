from lib/bytes import *

def Clock/DAY() -> u24:
  return 86400

def Clock/parse(xs: List(u24)) -> (u24, u24, u24):
  return Clock/parse.go(xs, 0, 0, 0)

def Clock/parse.go(xs: List(u24), days: u24, secs: u24, digits: u24) -> (u24, u24, u24):
  match xs:
    case List/Nil:
      return (days, secs, digits)
    case List/Cons:
      c = xs.head
      if Bytes/is_digit(c) & (digits < 12):
        t = secs * 10 + (c - 48)
        return Clock/parse.go(xs.tail, days * 10 + t / Clock/DAY, t % Clock/DAY, digits + 1)
      else:
        return (days, secs, digits)

def Clock/now(stat: List(u24), uptime: List(u24)) -> (u24, u24, u24):
  (found, rest) = Clock/after(stat, Bytes/from_string("btime "))
  (bd, bs, bn) = Clock/parse(rest)
  (ud, us, un) = Clock/parse(uptime)
  t = bs + us
  if found & (bn > 0) & (un > 0):
    return (1, bd + ud + t / Clock/DAY, t % Clock/DAY)
  else:
    return (0, 0, 0)

def Clock/after(xs: List(u24), needle: List(u24)) -> (u24, List(u24)):
  match xs:
    case List/Nil:
      return (0, [])
    case List/Cons:
      (ok, rest) = Bytes/strip_prefix(List/Cons(xs.head, xs.tail), needle)
      if ok:
        return (1, rest)
      else:
        match rest:
          case List/Nil:
            return (0, [])
          case List/Cons:
            return Clock/after(rest.tail, needle)

def Clock/civil(days: u24) -> (u24, u24, u24):
  z = days + 719468
  era = z / 146097
  doe = z - era * 146097
  yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
  doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
  mp = (5 * doy + 2) / 153
  d = doy - (153 * mp + 2) / 5 + 1
  if mp < 10:
    return (yoe + era * 400, mp + 3, d)
  else:
    return (yoe + era * 400 + 1, mp - 9, d)

def Clock/stamp(days: u24, secs: u24) -> List(u24):
  (y, m, d) = Clock/civil(days)
  return Bytes/join([Bytes/from_u24_padded(y, 4), Bytes/from_u24_padded(m, 2), Bytes/from_u24_padded(d, 2), Bytes/from_u24_padded(secs / 3600, 2), Bytes/from_u24_padded((secs / 60) % 60, 2), Bytes/from_u24_padded(secs % 60, 2)])

def Clock/iso(days: u24, secs: u24) -> List(u24):
  (y, m, d) = Clock/civil(days)
  return Bytes/join([Bytes/from_u24_padded(y, 4), [45], Bytes/from_u24_padded(m, 2), [45], Bytes/from_u24_padded(d, 2), [84], Bytes/from_u24_padded(secs / 3600, 2), [58], Bytes/from_u24_padded((secs / 60) % 60, 2), [58], Bytes/from_u24_padded(secs % 60, 2), [90]])

def Clock/elapsed(d1: u24, s1: u24, d2: u24, s2: u24) -> u24:
  if d2 < d1:
    return 0
  elif d2 - d1 >= 100:
    return 0xFFFFFF
  else:
    t = (d2 - d1) * Clock/DAY + s2
    if t < s1:
      return 0
    else:
      return t - s1
