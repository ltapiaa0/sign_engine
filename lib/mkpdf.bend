from lib/bytes import *

def Mk/LINES() -> u24:
  return 70

def Mk/WORDS() -> u24:
  return 14

def Mk/word(i: u24) -> List(u24):
  if i == 0:
    return Bytes/from_string("contract")
  elif i == 1:
    return Bytes/from_string("party")
  elif i == 2:
    return Bytes/from_string("clause")
  elif i == 3:
    return Bytes/from_string("signature")
  elif i == 4:
    return Bytes/from_string("agreement")
  elif i == 5:
    return Bytes/from_string("payment")
  elif i == 6:
    return Bytes/from_string("term")
  elif i == 7:
    return Bytes/from_string("obligation")
  elif i == 8:
    return Bytes/from_string("liability")
  else:
    return Bytes/from_string("notice")

def Mk/next(seed: u24) -> u24:
  return (seed * 1103 + 12345) & 0xFFFFFF

def Mk/line(seed: u24, n: u24) -> (List(u24), u24):
  if n == 0:
    return ([], seed)
  else:
    s = Mk/next(seed)
    (rest, s2) = Mk/line(s, n - 1)
    if n == 1:
      return (Bytes/concat(Mk/word((s >> 8) % 10), rest), s2)
    else:
      return (Bytes/concat(Mk/word((s >> 8) % 10), List/Cons(32, rest)), s2)

def Mk/text(seed: u24, n: u24) -> (List(u24), u24):
  if n == 0:
    return ([], seed)
  else:
    (line, s) = Mk/line(seed, Mk/WORDS)
    (rest, s2) = Mk/text(s, n - 1)
    return (Bytes/join([[40], line, Bytes/from_string(") Tj T*\n"), rest]), s2)

def Mk/object(num: u24, body: List(u24)) -> List(u24):
  return Bytes/join([Bytes/from_u24(num), Bytes/from_string(" 0 obj\n"), body, Bytes/from_string("\nendobj\n")])

def Mk/ref(num: u24) -> List(u24):
  return Bytes/concat(Bytes/from_u24(num), Bytes/from_string(" 0 R"))

def Mk/kids(i: u24, n: u24) -> List(u24):
  if i == n:
    return []
  else:
    return Bytes/join([Mk/ref(4 + 2 * i), [32], Mk/kids(i + 1, n)])

def Mk/pages(i: u24, n: u24, seed: u24) -> List(List(u24)):
  if i == n:
    return []
  else:
    (text, s) = Mk/text(seed, Mk/LINES)
    (len, stream) = Bytes/measure(Bytes/join([Bytes/from_string("BT /F1 9 Tf 40 800 Td 11 TL\n"), text, Bytes/from_string("ET")]))
    page = Mk/object(4 + 2 * i, Bytes/join([Bytes/from_string("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents "), Mk/ref(5 + 2 * i), Bytes/from_string(" >>")]))
    content = Mk/object(5 + 2 * i, Bytes/join([Bytes/from_string("<< /Length "), Bytes/from_u24(len), Bytes/from_string(" >>\nstream\n"), stream, Bytes/from_string("\nendstream")]))
    return List/Cons(page, List/Cons(content, Mk/pages(i + 1, n, s)))

def Mk/document(n: u24) -> List(u24):
  header = Bytes/concat(Bytes/from_string("%PDF-1.4\n%"), [0xE2, 0xE3, 0xCF, 0xD3, 10])
  objects = List/Cons(Mk/object(1, Bytes/from_string("<< /Type /Catalog /Pages 2 0 R >>")), List/Cons(Mk/object(2, Bytes/join([Bytes/from_string("<< /Type /Pages /Kids [ "), Mk/kids(0, n), Bytes/from_string("] /Count "), Bytes/from_u24(n), Bytes/from_string(" >>")])), List/Cons(Mk/object(3, Bytes/from_string("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")), Mk/pages(0, n, 7))))
  (hlen, head) = Bytes/measure(header)
  (body, offsets, end) = Mk/layout(objects, hlen)
  size = 4 + 2 * n
  xref = Bytes/join([Bytes/from_string("xref\n0 "), Bytes/from_u24(size), Bytes/from_string("\n0000000000 65535 f\r\n"), Mk/entries(offsets)])
  trailer = Bytes/join([Bytes/from_string("trailer\n<< /Size "), Bytes/from_u24(size), Bytes/from_string(" /Root 1 0 R >>\nstartxref\n"), Bytes/from_u24(end), Bytes/from_string("\n%%EOF\n")])
  return Bytes/join([head, body, xref, trailer])

def Mk/layout(objects: List(List(u24)), at: u24) -> (List(u24), List(u24), u24):
  match objects:
    case List/Nil:
      return ([], [], at)
    case List/Cons:
      (len, obj) = Bytes/measure(objects.head)
      (rest, offsets, end) = Mk/layout(objects.tail, at + len)
      return (Bytes/concat(obj, rest), List/Cons(at, offsets), end)

def Mk/entries(offsets: List(u24)) -> List(u24):
  match offsets:
    case List/Nil:
      return []
    case List/Cons:
      return Bytes/join([Bytes/from_u24_padded(offsets.head, 10), Bytes/from_string(" 00000 n\r\n"), Mk/entries(offsets.tail)])

def Mk/pages_from(text: List(u24)) -> u24:
  (n, digits, *) = Bytes/parse_u24(Bytes/trim(text))
  if (digits == 0) | (n == 0) | (n > 2000):
    return 60
  else:
    return n
