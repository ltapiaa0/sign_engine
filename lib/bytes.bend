def Bytes/NONE() -> u24:
  return 0xFFFFFF

def Bytes/from_io(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      return List/Cons(xs.head & 0xFF, Bytes/from_io(xs.tail))

def Bytes/len(xs: List(u24)) -> u24:
  fold xs:
    case List/Nil:
      return 0
    case List/Cons:
      return 1 + xs.tail

def Bytes/concat(xs: List(u24), ys: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return ys
    case List/Cons:
      return List/Cons(xs.head, Bytes/concat(xs.tail, ys))

def Bytes/join(xss: List(List(u24))) -> List(u24):
  match xss:
    case List/Nil:
      return []
    case List/Cons:
      return Bytes/concat(xss.head, Bytes/join(xss.tail))

def Bytes/take(xs: List(u24), n: u24) -> List(u24):
  if n == 0:
    return []
  else:
    match xs:
      case List/Nil:
        return []
      case List/Cons:
        return List/Cons(xs.head, Bytes/take(xs.tail, n - 1))

def Bytes/drop(xs: List(u24), n: u24) -> List(u24):
  if n == 0:
    return xs
  else:
    match xs:
      case List/Nil:
        return []
      case List/Cons:
        return Bytes/drop(xs.tail, n - 1)

def Bytes/at(xs: List(u24), i: u24) -> u24:
  match xs:
    case List/Nil:
      return 0
    case List/Cons:
      if i == 0:
        return xs.head
      else:
        return Bytes/at(xs.tail, i - 1)

def Bytes/reverse(xs: List(u24)) -> List(u24):
  return Bytes/reverse.go(xs, [])

def Bytes/reverse.go(xs: List(u24), acc: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return acc
    case List/Cons:
      return Bytes/reverse.go(xs.tail, List/Cons(xs.head, acc))

def Bytes/repeat(b: u24, n: u24) -> List(u24):
  if n == 0:
    return []
  else:
    return List/Cons(b, Bytes/repeat(b, n - 1))

def Bytes/pad_left(xs: List(u24), n: u24, b: u24) -> List(u24):
  len = Bytes/len(xs)
  if len >= n:
    return xs
  else:
    return Bytes/concat(Bytes/repeat(b, n - len), xs)

def Bytes/pad_right(xs: List(u24), n: u24, b: u24) -> List(u24):
  len = Bytes/len(xs)
  if len >= n:
    return xs
  else:
    return Bytes/concat(xs, Bytes/repeat(b, n - len))

def Bytes/equal(xs: List(u24), ys: List(u24)) -> u24:
  match xs:
    case List/Nil:
      match ys:
        case List/Nil:
          return 1
        case List/Cons:
          return 0
    case List/Cons:
      match ys:
        case List/Nil:
          return 0
        case List/Cons:
          if xs.head == ys.head:
            return Bytes/equal(xs.tail, ys.tail)
          else:
            return 0

def Bytes/starts_with(xs: List(u24), prefix: List(u24)) -> u24:
  match prefix:
    case List/Nil:
      return 1
    case List/Cons:
      match xs:
        case List/Nil:
          return 0
        case List/Cons:
          if xs.head == prefix.head:
            return Bytes/starts_with(xs.tail, prefix.tail)
          else:
            return 0

def Bytes/compare(a: List(u24), b: List(u24)) -> u24:
  match a:
    case List/Nil:
      match b:
        case List/Nil:
          return 1
        case List/Cons:
          return 0
    case List/Cons:
      match b:
        case List/Nil:
          return 2
        case List/Cons:
          if a.head < b.head:
            return 0
          elif a.head > b.head:
            return 2
          else:
            return Bytes/compare(a.tail, b.tail)

def Bytes/sort(xss: List(List(u24))) -> List(List(u24)):
  match xss:
    case List/Nil:
      return []
    case List/Cons:
      return Bytes/sort.insert(xss.head, Bytes/sort(xss.tail))

def Bytes/sort.insert(x: List(u24), sorted: List(List(u24))) -> List(List(u24)):
  match sorted:
    case List/Nil:
      return [x]
    case List/Cons:
      if Bytes/compare(x, sorted.head) == 2:
        return List/Cons(sorted.head, Bytes/sort.insert(x, sorted.tail))
      else:
        return List/Cons(x, sorted)

def Bytes/find(xs: List(u24), needle: List(u24)) -> u24:
  match needle:
    case List/Nil:
      return 0
    case List/Cons:
      return Bytes/find.go(xs, List/Cons(needle.head, needle.tail), needle.head, Bytes/len(needle), 0)

def Bytes/find.go(xs: List(u24), needle: List(u24), first: u24, m: u24, i: u24) -> u24:
  match xs:
    case List/Nil:
      return Bytes/NONE
    case List/Cons:
      if xs.head == first:
        (front, rest) = Bytes/split(List/Cons(xs.head, xs.tail), m)
        if Bytes/equal(front, needle):
          return i
        else:
          return Bytes/find.go(Bytes/concat(Bytes/drop(front, 1), rest), needle, first, m, i + 1)
      else:
        return Bytes/find.go(xs.tail, needle, first, m, i + 1)

def Bytes/rfind(xs: List(u24), needle: List(u24)) -> u24:
  (rev, n) = Bytes/reverse_len(xs, [], 0)
  m = Bytes/len(needle)
  p = Bytes/find(rev, Bytes/reverse(needle))
  if p == Bytes/NONE:
    return Bytes/NONE
  else:
    return n - p - m

def Bytes/reverse_len(xs: List(u24), acc: List(u24), n: u24) -> (List(u24), u24):
  match xs:
    case List/Nil:
      return (acc, n)
    case List/Cons:
      return Bytes/reverse_len(xs.tail, List/Cons(xs.head, acc), n + 1)

def Bytes/split(xs: List(u24), n: u24) -> (List(u24), List(u24)):
  if n == 0:
    return ([], xs)
  else:
    match xs:
      case List/Nil:
        return ([], [])
      case List/Cons:
        (front, back) = Bytes/split(xs.tail, n - 1)
        return (List/Cons(xs.head, front), back)

def Bytes/pop(xs: List(u24)) -> (u24, List(u24)):
  match xs:
    case List/Nil:
      return (0, [])
    case List/Cons:
      return (xs.head, xs.tail)

def Bytes/strip_prefix(xs: List(u24), prefix: List(u24)) -> (u24, List(u24)):
  match prefix:
    case List/Nil:
      return (1, xs)
    case List/Cons:
      match xs:
        case List/Nil:
          return (0, [])
        case List/Cons:
          if xs.head == prefix.head:
            (ok, rest) = Bytes/strip_prefix(xs.tail, prefix.tail)
            if ok:
              return (1, rest)
            else:
              return (0, List/Cons(xs.head, rest))
          else:
            return (0, List/Cons(xs.head, xs.tail))

def Bytes/from_string(s: String) -> List(u24):
  return String/encode_ascii(s)

def Bytes/is_space(c: u24) -> u24:
  return (c == 32) | (c == 10) | (c == 13) | (c == 9) | (c == 12) | (c == 0)

def Bytes/is_digit(c: u24) -> u24:
  return (c >= 48) & (c <= 57)

def Bytes/skip_spaces(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      if Bytes/is_space(xs.head):
        return Bytes/skip_spaces(xs.tail)
      else:
        return xs

def Bytes/trim(xs: List(u24)) -> List(u24):
  return Bytes/reverse(Bytes/skip_spaces(Bytes/reverse(Bytes/skip_spaces(xs))))

def Bytes/from_u24(n: u24) -> List(u24):
  if n < 10:
    return [48 + n]
  else:
    return Bytes/concat(Bytes/from_u24(n / 10), [48 + (n % 10)])

def Bytes/from_u24_padded(n: u24, width: u24) -> List(u24):
  return Bytes/pad_left(Bytes/from_u24(n), width, 48)

def Bytes/parse_u24(xs: List(u24)) -> (u24, u24, List(u24)):
  return Bytes/parse_u24.go(xs, 0, 0)

def Bytes/parse_u24.go(xs: List(u24), acc: u24, n: u24) -> (u24, u24, List(u24)):
  match xs:
    case List/Nil:
      return (acc, n, [])
    case List/Cons:
      if Bytes/is_digit(xs.head):
        return Bytes/parse_u24.go(xs.tail, acc * 10 + (xs.head - 48), n + 1)
      else:
        return (acc, n, xs)

def Bytes/lines(xs: List(u24)) -> List(List(u24)):
  return Bytes/lines.go(xs, [])

def Bytes/lines.go(xs: List(u24), cur: List(u24)) -> List(List(u24)):
  match xs:
    case List/Nil:
      match cur:
        case List/Nil:
          return []
        case List/Cons:
          return [Bytes/reverse(cur)]
    case List/Cons:
      if xs.head == 10:
        return List/Cons(Bytes/reverse(cur), Bytes/lines.go(xs.tail, []))
      elif xs.head == 13:
        return Bytes/lines.go(xs.tail, cur)
      else:
        return Bytes/lines.go(xs.tail, List/Cons(xs.head, cur))

def Bytes/from_uint_be(n: u24, width: u24) -> List(u24):
  return Bytes/from_uint_be.go(n, width, [])

def Bytes/from_uint_be.go(n: u24, width: u24, acc: List(u24)) -> List(u24):
  if width == 0:
    return acc
  else:
    return Bytes/from_uint_be.go(n >> 8, width - 1, List/Cons(n & 0xFF, acc))

def Bytes/to_uint_be(xs: List(u24)) -> u24:
  return Bytes/to_uint_be.go(xs, 0)

def Bytes/to_uint_be.go(xs: List(u24), acc: u24) -> u24:
  match xs:
    case List/Nil:
      return acc
    case List/Cons:
      return Bytes/to_uint_be.go(xs.tail, (acc << 8) | xs.head)

def Bytes/strip_zeros(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      if xs.head == 0:
        return Bytes/strip_zeros(xs.tail)
      else:
        return xs

def Bytes/hex_digit(n: u24) -> u24:
  if n < 10:
    return 48 + n
  else:
    return 87 + n

def Bytes/hex_digit_upper(n: u24) -> u24:
  if n < 10:
    return 48 + n
  else:
    return 55 + n

def Bytes/hex_value(c: u24) -> u24:
  if (c >= 48) & (c <= 57):
    return c - 48
  elif (c >= 97) & (c <= 102):
    return c - 87
  elif (c >= 65) & (c <= 70):
    return c - 55
  else:
    return 0xFF

def Bytes/to_hex(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      return List/Cons(Bytes/hex_digit(xs.head >> 4), List/Cons(Bytes/hex_digit(xs.head & 15), Bytes/to_hex(xs.tail)))

def Bytes/to_hex_upper(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      return List/Cons(Bytes/hex_digit_upper(xs.head >> 4), List/Cons(Bytes/hex_digit_upper(xs.head & 15), Bytes/to_hex_upper(xs.tail)))

def Bytes/from_hex(xs: List(u24)) -> List(u24):
  return Bytes/from_hex.go(xs, 0xFF)

def Bytes/from_hex.go(xs: List(u24), hi: u24) -> List(u24):
  match xs:
    case List/Nil:
      if hi == 0xFF:
        return []
      else:
        return [hi << 4]
    case List/Cons:
      v = Bytes/hex_value(xs.head)
      if v == 0xFF:
        return Bytes/from_hex.go(xs.tail, hi)
      elif hi == 0xFF:
        return Bytes/from_hex.go(xs.tail, v)
      else:
        return List/Cons((hi << 4) | v, Bytes/from_hex.go(xs.tail, 0xFF))

def Bytes/b64_char(n: u24) -> u24:
  if n < 26:
    return 65 + n
  elif n < 52:
    return 71 + n
  elif n < 62:
    return n - 4
  elif n == 62:
    return 43
  else:
    return 47

def Bytes/b64_value(c: u24) -> u24:
  if (c >= 65) & (c <= 90):
    return c - 65
  elif (c >= 97) & (c <= 122):
    return c - 71
  elif (c >= 48) & (c <= 57):
    return c + 4
  elif c == 43:
    return 62
  elif c == 47:
    return 63
  elif c == 45:
    return 62
  elif c == 95:
    return 63
  elif c == 61:
    return 0xFE
  else:
    return 0xFF

def Bytes/to_base64(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      a = xs.head
      match t1 = xs.tail:
        case List/Nil:
          return [Bytes/b64_char(a >> 2), Bytes/b64_char((a & 3) << 4), 61, 61]
        case List/Cons:
          b = t1.head
          match t2 = t1.tail:
            case List/Nil:
              return [Bytes/b64_char(a >> 2), Bytes/b64_char(((a & 3) << 4) | (b >> 4)), Bytes/b64_char((b & 15) << 2), 61]
            case List/Cons:
              c = t2.head
              n = (a << 16) | (b << 8) | c
              return List/Cons(Bytes/b64_char(n >> 18), List/Cons(Bytes/b64_char((n >> 12) & 63), List/Cons(Bytes/b64_char((n >> 6) & 63), List/Cons(Bytes/b64_char(n & 63), Bytes/to_base64(t2.tail)))))

def Bytes/from_base64(xs: List(u24)) -> List(u24):
  return Bytes/from_base64.go(xs, 0, 0)

def Bytes/from_base64.go(xs: List(u24), acc: u24, n: u24) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      v = Bytes/b64_value(xs.head)
      if v == 0xFE:
        return []
      elif v == 0xFF:
        return Bytes/from_base64.go(xs.tail, acc, n)
      else:
        acc2 = ((acc << 6) | v) & 0xFFFF
        if n + 6 >= 8:
          return List/Cons((acc2 >> (n - 2)) & 0xFF, Bytes/from_base64.go(xs.tail, acc2 & ((1 << (n - 2)) - 1), n - 2))
        else:
          return Bytes/from_base64.go(xs.tail, acc2, n + 6)
