# lib/asn1.bend
# Codificación y decodificación ASN.1 DER (X.690) y contenedores PEM.

from lib/bytes import *

# ---------------------------------------------------------------------------
# Decodificación
# ---------------------------------------------------------------------------

# Lee la longitud DER. Retorna (longitud, bytes_de_longitud, resto).
def Der/read_len(xs: List(u24)) -> (u24, u24, List(u24)):
  match xs:
    case List/Nil:
      return (0, 0, [])
    case List/Cons:
      if xs.head < 0x80:
        return (xs.head, 1, xs.tail)
      else:
        n = xs.head & 0x7F
        return (Bytes/to_uint_be(Bytes/take(xs.tail, n)), 1 + n, Bytes/drop(xs.tail, n))

# Lee un elemento TLV. Retorna (tag, contenido, codificación_completa, resto).
# Ante una entrada vacía retorna tag 0.
def Der/read(xs: List(u24)) -> (u24, List(u24), List(u24), List(u24)):
  match xs:
    case List/Nil:
      return (0, [], [], [])
    case List/Cons:
      (len, lb, after) = Der/read_len(xs.tail)
      return (xs.head, Bytes/take(after, len), Bytes/take(xs, 1 + lb + len), Bytes/drop(after, len))

# Elementos hijos de un contenido construido: lista de (tag, contenido, raw).
def Der/children(content: List(u24)) -> List((u24, List(u24), List(u24))):
  match content:
    case List/Nil:
      return []
    case List/Cons:
      (tag, body, raw, rest) = Der/read(content)
      return List/Cons((tag, body, raw), Der/children(rest))

# i-ésimo hijo (tag 0 si no existe).
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

# Contenido de un elemento DER completo (descarta tag y longitud).
def Der/content(xs: List(u24)) -> List(u24):
  (*, body, *, *) = Der/read(xs)
  return body

# Entero DER -> bytes big-endian sin ceros iniciales.
def Der/int_value(content: List(u24)) -> List(u24):
  return Bytes/strip_zeros(content)

# ---------------------------------------------------------------------------
# Codificación
# ---------------------------------------------------------------------------

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

# SET OF: DER exige ordenar las codificaciones de los elementos.
def Der/set(items: List(List(u24))) -> List(u24):
  return Der/tlv(0x31, Bytes/join(Bytes/sort(items)))

# INTEGER a partir de bytes big-endian sin signo.
def Der/int(bs: List(u24)) -> List(u24):
  match v = Bytes/strip_zeros(bs):
    case List/Nil:
      return [0x02, 0x01, 0x00]
    case List/Cons:
      if v.head >= 0x80:
        return Der/tlv(0x02, List/Cons(0, v))
      else:
        return Der/tlv(0x02, v)

def Der/int_small(n: u24) -> List(u24):
  return Der/int(Bytes/from_uint_be(n, 3))

def Der/octet_string(bs: List(u24)) -> List(u24):
  return Der/tlv(0x04, bs)

def Der/null() -> List(u24):
  return [0x05, 0x00]

# OID a partir de su contenido ya codificado (p.ej. [0x2a, 0x86, 0x48, ...]).
def Der/oid(content: List(u24)) -> List(u24):
  return Der/tlv(0x06, content)

# Etiqueta de contexto construida [n] (0xA0 | n).
def Der/ctx(n: u24, content: List(u24)) -> List(u24):
  return Der/tlv(0xA0 | n, content)

def Der/utf8_string(bs: List(u24)) -> List(u24):
  return Der/tlv(0x0C, bs)

# GeneralizedTime / UTCTime a partir de texto ASCII ya formateado.
def Der/utc_time(text: List(u24)) -> List(u24):
  return Der/tlv(0x17, text)

# ---------------------------------------------------------------------------
# PEM (RFC 7468)
# ---------------------------------------------------------------------------

# Extrae todos los bloques PEM como DER. Si la entrada no es PEM, se asume
# que ya es DER y se devuelve como único elemento.
def Pem/decode_all(xs: List(u24)) -> List(List(u24)):
  if Bytes/find(xs, Bytes/from_string("-----BEGIN")) == Bytes/NONE:
    return [xs]
  else:
    return Pem/blocks(Bytes/lines(xs), 0, [])

def Pem/blocks(lines: List(List(u24)), inside: u24, acc: List(List(u24))) -> List(List(u24)):
  match lines:
    case List/Nil:
      return []
    case List/Cons:
      line = Bytes/trim(lines.head)
      if Bytes/starts_with(line, Bytes/from_string("-----BEGIN")):
        return Pem/blocks(lines.tail, 1, [])
      elif Bytes/starts_with(line, Bytes/from_string("-----END")):
        der = Bytes/from_base64(Bytes/join(Pem/reverse(acc)))
        return List/Cons(der, Pem/blocks(lines.tail, 0, []))
      elif inside:
        if Bytes/find(line, [58]) == Bytes/NONE:
          return Pem/blocks(lines.tail, 1, List/Cons(line, acc))
        else:
          # Encabezados tipo "Proc-Type:" (PEM cifrado antiguo): se ignoran.
          return Pem/blocks(lines.tail, 1, acc)
      else:
        return Pem/blocks(lines.tail, 0, acc)

def Pem/reverse(xs: List(List(u24))) -> List(List(u24)):
  return Pem/reverse.go(xs, [])

def Pem/reverse.go(xs: List(List(u24)), acc: List(List(u24))) -> List(List(u24)):
  match xs:
    case List/Nil:
      return acc
    case List/Cons:
      return Pem/reverse.go(xs.tail, List/Cons(xs.head, acc))

# Primer bloque PEM (o la entrada si ya es DER).
def Pem/decode(xs: List(u24)) -> List(u24):
  match blocks = Pem/decode_all(xs):
    case List/Nil:
      return []
    case List/Cons:
      return blocks.head
