from lib/bytes import *

def Text/REPLACEMENT() -> u24:
  return 0xFFFD

def Text/utf8_decode(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      c = xs.head
      if c < 0xC0:
        return List/Cons(c, Text/utf8_decode(xs.tail))
      elif c < 0xE0:
        (b1, r1) = Bytes/pop(xs.tail)
        return List/Cons(((c & 0x1F) << 6) | (b1 & 0x3F), Text/utf8_decode(r1))
      elif c < 0xF0:
        (b1, r1) = Bytes/pop(xs.tail)
        (b2, r2) = Bytes/pop(r1)
        return List/Cons(((c & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F), Text/utf8_decode(r2))
      else:
        (b1, r1) = Bytes/pop(xs.tail)
        (b2, r2) = Bytes/pop(r1)
        (b3, r3) = Bytes/pop(r2)
        return List/Cons(Text/valid(((c & 0x07) << 18) | ((b1 & 0x3F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F)), Text/utf8_decode(r3))

def Text/valid(c: u24) -> u24:
  if c > 0x10FFFF:
    return Text/REPLACEMENT
  else:
    return c

def Text/utf8_encode(cps: List(u24)) -> List(u24):
  match cps:
    case List/Nil:
      return []
    case List/Cons:
      c = Text/valid(cps.head)
      rest = Text/utf8_encode(cps.tail)
      if c < 0x80:
        return List/Cons(c, rest)
      elif c < 0x800:
        return List/Cons(0xC0 | (c >> 6), List/Cons(0x80 | (c & 0x3F), rest))
      elif c < 0x10000:
        return List/Cons(0xE0 | (c >> 12), List/Cons(0x80 | ((c >> 6) & 0x3F), List/Cons(0x80 | (c & 0x3F), rest)))
      else:
        return List/Cons(0xF0 | (c >> 18), List/Cons(0x80 | ((c >> 12) & 0x3F), List/Cons(0x80 | ((c >> 6) & 0x3F), List/Cons(0x80 | (c & 0x3F), rest))))

def Text/utf16be_encode(cps: List(u24)) -> List(u24):
  match cps:
    case List/Nil:
      return []
    case List/Cons:
      c = Text/valid(cps.head)
      if c < 0x10000:
        return List/Cons(c >> 8, List/Cons(c & 0xFF, Text/utf16be_encode(cps.tail)))
      else:
        v = c - 0x10000
        hi = 0xD800 | (v >> 10)
        lo = 0xDC00 | (v & 0x3FF)
        return List/Cons(hi >> 8, List/Cons(hi & 0xFF, List/Cons(lo >> 8, List/Cons(lo & 0xFF, Text/utf16be_encode(cps.tail)))))

def Text/utf16be_decode(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      (lo, r1) = Bytes/pop(xs.tail)
      u = (xs.head << 8) | lo
      if (u >= 0xD800) & (u < 0xDC00):
        match r1:
          case List/Nil:
            return [Text/REPLACEMENT]
          case List/Cons:
            (w2, r3) = Bytes/pop(r1.tail)
            w = (r1.head << 8) | w2
            if (w >= 0xDC00) & (w < 0xE000):
              return List/Cons(0x10000 + ((u - 0xD800) << 10) + (w - 0xDC00), Text/utf16be_decode(r3))
            else:
              return List/Cons(Text/REPLACEMENT, Text/utf16be_decode(List/Cons(r1.head, List/Cons(w2, r3))))
      else:
        return List/Cons(u, Text/utf16be_decode(r1))

def Text/utf32be_decode(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      (b1, r1) = Bytes/pop(xs.tail)
      (b2, r2) = Bytes/pop(r1)
      (b3, r3) = Bytes/pop(r2)
      if xs.head == 0:
        return List/Cons(Text/valid((b1 << 16) | (b2 << 8) | b3), Text/utf32be_decode(r3))
      else:
        return List/Cons(Text/REPLACEMENT, Text/utf32be_decode(r3))
