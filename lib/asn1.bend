from lib/bytes import *

def Der/read_len(xs: List(u24)) -> (u24, List(u24), List(u24)):
  match xs:
    case List/Nil:
      return (0, [], [])
    case List/Cons:
      if xs.head < 0x80:
        return (xs.head, [xs.head], xs.tail)
      else:
        (octets, rest) = Bytes/split(xs.tail, xs.head & 0x7F)
        return (Bytes/to_uint_be(octets), List/Cons(xs.head, octets), rest)

def Der/read(xs: List(u24)) -> (u24, List(u24), List(u24), List(u24)):
  match xs:
    case List/Nil:
      return (0, [], [], [])
    case List/Cons:
      (len, header, after) = Der/read_len(xs.tail)
      (content, rest) = Bytes/split(after, len)
      return (xs.head, content, List/Cons(xs.head, Bytes/concat(header, content)), rest)

def Der/children(content: List(u24)) -> List((u24, List(u24), List(u24))):
  match content:
    case List/Nil:
      return []
    case List/Cons:
      (tag, body, raw, rest) = Der/read(content)
      return List/Cons((tag, body, raw), Der/children(rest))

def Der/child(content: List(u24), i: u24) -> (u24, List(u24), List(u24)):
  return Der/nth(Der/children(content), i)

def Der/nth(xs: List((u24, List(u24), List(u24))), i: u24) -> (u24, List(u24), List(u24)):
  match xs:
    case List/Nil:
      return (0, [], [])
    case List/Cons:
      if i == 0:
        return xs.head
      else:
        return Der/nth(xs.tail, i - 1)

def Der/int_value(content: List(u24)) -> List(u24):
  return Bytes/strip_zeros(content)

def Der/len_bytes(n: u24) -> List(u24):
  if n < 0x80:
    return [n]
  elif n < 0x100:
    return [0x81, n]
  elif n < 0x10000:
    return [0x82, n >> 8, n & 0xFF]
  else:
    return [0x83, n >> 16, (n >> 8) & 0xFF, n & 0xFF]

def Der/tlv(tag: u24, content: List(u24)) -> List(u24):
  return List/Cons(tag, Bytes/concat(Der/len_bytes(Bytes/len(content)), content))

def Der/seq(items: List(List(u24))) -> List(u24):
  return Der/tlv(0x30, Bytes/join(items))

def Der/set(items: List(List(u24))) -> List(u24):
  return Der/tlv(0x31, Bytes/join(Bytes/sort(items)))

def Der/int(bs: List(u24)) -> List(u24):
  match v = Bytes/strip_zeros(bs):
    case List/Nil:
      return [0x02, 0x01, 0x00]
    case List/Cons:
      if v.head >= 0x80:
        return Der/tlv(0x02, List/Cons(0, v))
      else:
        return Der/tlv(0x02, v)

def Der/octet_string(bs: List(u24)) -> List(u24):
  return Der/tlv(0x04, bs)

def Der/null() -> List(u24):
  return [0x05, 0x00]

def Der/oid(content: List(u24)) -> List(u24):
  return Der/tlv(0x06, content)

def Der/ctx(n: u24, content: List(u24)) -> List(u24):
  return Der/tlv(0xA0 | n, content)

def Pem/decode_all(xs: List(u24)) -> List((List(u24), List(u24))):
  if Bytes/find(xs, Bytes/from_string("-----BEGIN")) == Bytes/NONE:
    return [([], xs)]
  else:
    return Pem/blocks(Bytes/lines(xs), [], 0, [])

def Pem/blocks(lines: List(List(u24)), label: List(u24), inside: u24, acc: List(List(u24))) -> List((List(u24), List(u24))):
  match lines:
    case List/Nil:
      return []
    case List/Cons:
      (is_begin, line) = Bytes/strip_prefix(Bytes/trim(lines.head), Bytes/from_string("-----BEGIN "))
      if is_begin:
        return Pem/blocks(lines.tail, Pem/label(line), 1, [])
      else:
        (is_end, body) = Bytes/strip_prefix(line, Bytes/from_string("-----END"))
        if is_end:
          return List/Cons((label, Bytes/from_base64(Bytes/join(Pem/reverse(acc)))), Pem/blocks(lines.tail, [], 0, []))
        elif inside & (Bytes/find(body, [58]) == Bytes/NONE):
          return Pem/blocks(lines.tail, label, 1, List/Cons(body, acc))
        else:
          return Pem/blocks(lines.tail, label, inside, acc)

def Pem/label(rest: List(u24)) -> List(u24):
  return Bytes/take(rest, Bytes/find(rest, Bytes/from_string("-----")))

def Pem/reverse(xs: List(List(u24))) -> List(List(u24)):
  return Pem/reverse.go(xs, [])

def Pem/reverse.go(xs: List(List(u24)), acc: List(List(u24))) -> List(List(u24)):
  match xs:
    case List/Nil:
      return acc
    case List/Cons:
      return Pem/reverse.go(xs.tail, List/Cons(xs.head, acc))

def Pem/is_label(label: List(u24), name: String) -> u24:
  return Bytes/equal(label, Bytes/from_string(name))
