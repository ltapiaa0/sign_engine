# lib/bytes.bend
# Utilidades para secuencias de bytes.
#
# Un "Bytes" es una List(u24) donde cada elemento es un valor 0..255.
# Las posiciones y longitudes son u24, por lo que el tamaño máximo
# soportado es 16 MiB (2^24 - 1 bytes).

# Valor centinela para "no encontrado".
def Bytes/NONE() -> u24:
  return 0xFFFFFF

# ---------------------------------------------------------------------------
# Construcción y acceso
# ---------------------------------------------------------------------------

# Normaliza datos leídos con IO/FS: el runtime C de HVM 2.0 extiende el
# signo de los bytes >= 0x80 (0x93 llega como 0xFFFF93), así que todo lo
# que venga de un archivo debe pasar por aquí.
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

# Concatena una lista de Bytes.
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

def Bytes/slice(xs: List(u24), start: u24, len: u24) -> List(u24):
  return Bytes/take(Bytes/drop(xs, start), len)

# Elemento en la posición i (0 si está fuera de rango).
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

# Rellena por la izquierda con `b` hasta longitud `n`.
def Bytes/pad_left(xs: List(u24), n: u24, b: u24) -> List(u24):
  len = Bytes/len(xs)
  if len >= n:
    return xs
  else:
    return Bytes/concat(Bytes/repeat(b, n - len), xs)

# Rellena por la derecha con `b` hasta longitud `n`.
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

# 1 si `prefix` es prefijo de `xs`.
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

# Comparación lexicográfica: 0 si a < b, 1 si a == b, 2 si a > b.
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

# Ordena una lista de Bytes (inserción, para listas pequeñas como SET OF DER).
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

# ---------------------------------------------------------------------------
# Búsqueda
# ---------------------------------------------------------------------------

# Posición de la primera aparición de `needle` en `xs`, o Bytes/NONE.
def Bytes/find(xs: List(u24), needle: List(u24)) -> u24:
  return Bytes/find.go(xs, needle, 0)

def Bytes/find.go(xs: List(u24), needle: List(u24), i: u24) -> u24:
  if Bytes/starts_with(xs, needle):
    return i
  else:
    match xs:
      case List/Nil:
        return Bytes/NONE
      case List/Cons:
        return Bytes/find.go(xs.tail, needle, i + 1)

# Posición de la primera aparición de `needle` a partir de `from`.
def Bytes/find_from(xs: List(u24), needle: List(u24), from: u24) -> u24:
  return Bytes/find.go(Bytes/drop(xs, from), needle, from)

# Posición de la última aparición de `needle` en `xs`, o Bytes/NONE.
def Bytes/rfind(xs: List(u24), needle: List(u24)) -> u24:
  return Bytes/rfind.go(xs, needle, 0, Bytes/NONE)

def Bytes/rfind.go(xs: List(u24), needle: List(u24), i: u24, last: u24) -> u24:
  match xs:
    case List/Nil:
      return last
    case List/Cons:
      if Bytes/starts_with(xs, needle):
        return Bytes/rfind.go(xs.tail, needle, i + 1, i)
      else:
        return Bytes/rfind.go(xs.tail, needle, i + 1, last)

# ---------------------------------------------------------------------------
# Texto ASCII
# ---------------------------------------------------------------------------

def Bytes/from_string(s: String) -> List(u24):
  return String/encode_ascii(s)

def Bytes/to_string(xs: List(u24)) -> String:
  return String/decode_ascii(xs)

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

# Elimina espacios en ambos extremos.
def Bytes/trim(xs: List(u24)) -> List(u24):
  return Bytes/reverse(Bytes/skip_spaces(Bytes/reverse(Bytes/skip_spaces(xs))))

# Representación decimal ASCII de un u24.
def Bytes/from_u24(n: u24) -> List(u24):
  if n < 10:
    return [48 + n]
  else:
    return Bytes/concat(Bytes/from_u24(n / 10), [48 + (n % 10)])

# Decimal con ancho fijo, relleno de ceros a la izquierda.
def Bytes/from_u24_padded(n: u24, width: u24) -> List(u24):
  return Bytes/pad_left(Bytes/from_u24(n), width, 48)

# Lee un entero decimal al inicio de `xs`: retorna (valor, dígitos_leídos, resto).
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

# Divide en líneas por '\n' (descarta '\r' final de cada línea).
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

# ---------------------------------------------------------------------------
# Enteros <-> bytes (big-endian)
# ---------------------------------------------------------------------------

# Codifica `n` en `width` bytes big-endian (width <= 3 para u24 completo).
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

# Elimina ceros iniciales.
def Bytes/strip_zeros(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      if xs.head == 0:
        return Bytes/strip_zeros(xs.tail)
      else:
        return xs

# ---------------------------------------------------------------------------
# Hexadecimal
# ---------------------------------------------------------------------------

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

# Valor de un dígito hexadecimal ASCII, o 0xFF si no es hexadecimal.
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

# Decodifica hexadecimal ignorando caracteres no hexadecimales (espacios, saltos).
# Un dígito final impar se completa con 0 (como en las cadenas hex de PDF).
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

# ---------------------------------------------------------------------------
# Base64 (RFC 4648)
# ---------------------------------------------------------------------------

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

# Valor de un carácter base64, 0xFE para '=', 0xFF para cualquier otro.
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

# Decodifica base64 ignorando espacios/saltos de línea; se detiene en '='.
def Bytes/from_base64(xs: List(u24)) -> List(u24):
  return Bytes/from_base64.go(xs, 0, 0)

# acc: bits acumulados, n: cantidad de bits en acc
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
