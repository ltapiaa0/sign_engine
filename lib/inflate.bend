# lib/inflate.bend
# Descompresión DEFLATE (RFC 1951) y envoltorio zlib (RFC 1950), más los
# predictores PNG (RFC 2083) que usan los xref streams de PDF.
#
# Implementación basada en el decodificador canónico de "puff" (zlib):
# las tablas de Huffman se representan como una lista, por longitud de
# código 1..15, de pares (cantidad, símbolos). La ventana de 32 KiB para
# las referencias hacia atrás es un Map indexado por posición mod 2^15.

from lib/bytes import *

# ---------------------------------------------------------------------------
# Lector de bits. Estado: (bytes_restantes, buffer, bits_en_buffer)
# ---------------------------------------------------------------------------

def Inflate/bits(s, need: u24):
  (xs, buf, cnt) = s
  if cnt >= need:
    return (buf & ((1 << need) - 1), (xs, buf >> need, cnt - need))
  else:
    match xs:
      case List/Nil:
        return Inflate/bits(([], buf, cnt + 8), need)
      case List/Cons:
        return Inflate/bits((xs.tail, buf | (xs.head << cnt), cnt + 8), need)

# Descarta los bits hasta el siguiente límite de byte.
def Inflate/align(s):
  (xs, buf, cnt) = s
  r = cnt & 7
  return (xs, buf >> r, cnt - r)

def Inflate/at(xs: List(u24), i: u24) -> u24:
  match xs:
    case List/Nil:
      return 0
    case List/Cons:
      if i == 0:
        return xs.head
      else:
        return Inflate/at(xs.tail, i - 1)

def Inflate/count(xs: List(u24)) -> u24:
  match xs:
    case List/Nil:
      return 0
    case List/Cons:
      return 1 + Inflate/count(xs.tail)

# ---------------------------------------------------------------------------
# Tablas de Huffman canónicas
# ---------------------------------------------------------------------------

# Construye la tabla a partir de las longitudes de código (en orden de símbolo).
def Inflate/build(lengths: List(u24)):
  return Inflate/build.go(lengths, 1)

def Inflate/build.go(lengths: List(u24), len: u24):
  if len > 15:
    return []
  else:
    syms = Inflate/syms_with_len(lengths, len, 0)
    return List/Cons((Inflate/count(syms), syms), Inflate/build.go(lengths, len + 1))

def Inflate/syms_with_len(lengths: List(u24), len: u24, sym: u24) -> List(u24):
  match lengths:
    case List/Nil:
      return []
    case List/Cons:
      if lengths.head == len:
        return List/Cons(sym, Inflate/syms_with_len(lengths.tail, len, sym + 1))
      else:
        return Inflate/syms_with_len(lengths.tail, len, sym + 1)

# Decodifica un símbolo. Retorna (símbolo, estado); 0xFFFF si el código es inválido.
def Inflate/decode(s, table):
  return Inflate/decode.go(s, table, 0, 0)

def Inflate/decode.go(s, table, code: u24, first: u24):
  match table:
    case List/Nil:
      return (0xFFFF, s)
    case List/Cons:
      (bit, s2) = Inflate/bits(s, 1)
      c = code | bit
      (count, syms) = table.head
      if c < first + count:
        return (Inflate/at(syms, c - first), s2)
      else:
        return Inflate/decode.go(s2, table.tail, c << 1, (first + count) << 1)

# Tablas fijas. `z` debe ser 0 calculado en tiempo de ejecución: si la
# expresión fuera cerrada, Bend la extraería como definición global y HVM no
# permite duplicar referencias globales no afines.
def Inflate/fixed_lit(z: u24):
  return Inflate/build(Bytes/concat(Bytes/repeat(8 + z, 144), Bytes/concat(Bytes/repeat(9 + z, 112), Bytes/concat(Bytes/repeat(7 + z, 24), Bytes/repeat(8 + z, 8)))))

def Inflate/fixed_dist(z: u24):
  return Inflate/build(Bytes/repeat(5 + z, 30))

def Inflate/LEN_BASE() -> List(u24):
  return [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258]

def Inflate/LEN_EXTRA() -> List(u24):
  return [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]

def Inflate/DIST_BASE() -> List(u24):
  return [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577]

def Inflate/DIST_EXTRA() -> List(u24):
  return [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]

# Posición de cada símbolo 0..18 en el orden de transmisión de HCLEN.
def Inflate/CLEN_POS() -> List(u24):
  return [3, 17, 15, 13, 11, 9, 7, 5, 4, 6, 8, 10, 12, 14, 16, 18, 0, 1, 2]

# ---------------------------------------------------------------------------
# Bloques
# ---------------------------------------------------------------------------

# Estado de salida: (ventana, posición, salida_invertida)
def Inflate/emit(o, b: u24):
  (win, pos, out) = o
  return (Map/set(win, pos & 0x7FFF, b), pos + 1, List/Cons(b, out))

def Inflate/copy(o, len: u24, dist: u24):
  if len == 0:
    return o
  else:
    (win, pos, out) = o
    (b, win2) = Map/get(win, (pos - dist) & 0x7FFF)
    return Inflate/copy(Inflate/emit((win2, pos, out), b), len - 1, dist)

# Decodifica símbolos hasta el fin de bloque (256). Retorna (estado, salida).
def Inflate/codes(s, o, lit, dist):
  (sym, s1) = Inflate/decode(s, lit)
  if sym < 256:
    return Inflate/codes(s1, Inflate/emit(o, sym), lit, dist)
  elif sym == 256:
    return (s1, o)
  elif sym > 285:
    return (s1, o)
  else:
    li = sym - 257
    (le, s2) = Inflate/bits(s1, Inflate/at(Inflate/LEN_EXTRA, li))
    len = Inflate/at(Inflate/LEN_BASE, li) + le
    (dsym, s3) = Inflate/decode(s2, dist)
    (de, s4) = Inflate/bits(s3, Inflate/at(Inflate/DIST_EXTRA, dsym))
    d = Inflate/at(Inflate/DIST_BASE, dsym) + de
    return Inflate/codes(s4, Inflate/copy(o, len, d), lit, dist)

def Inflate/stored(s, o):
  (len, s1) = Inflate/bits(Inflate/align(s), 16)
  (*, s2) = Inflate/bits(s1, 16)
  return Inflate/stored.go(s2, o, len)

def Inflate/stored.go(s, o, n: u24):
  if n == 0:
    return (s, o)
  else:
    (b, s2) = Inflate/bits(s, 8)
    return Inflate/stored.go(s2, Inflate/emit(o, b), n - 1)

# Lee `n` valores de 3 bits.
def Inflate/read3(s, n: u24):
  if n == 0:
    return ([], s)
  else:
    (v, s2) = Inflate/bits(s, 3)
    (vs, s3) = Inflate/read3(s2, n - 1)
    return (List/Cons(v, vs), s3)

# Longitudes del código de longitudes, en orden de símbolo 0..18.
def Inflate/clen_lengths(vals: List(u24), hclen: u24, pos: List(u24)) -> List(u24):
  match pos:
    case List/Nil:
      return []
    case List/Cons:
      if pos.head < hclen:
        return List/Cons(Inflate/at(vals, pos.head), Inflate/clen_lengths(vals, hclen, pos.tail))
      else:
        return List/Cons(0, Inflate/clen_lengths(vals, hclen, pos.tail))

# Lee `n` longitudes de código usando la tabla `clen`. acc está invertida.
def Inflate/read_lengths(s, clen, n: u24, prev: u24, acc: List(u24)):
  if n == 0:
    return (Bytes/reverse(acc), s)
  else:
    (sym, s1) = Inflate/decode(s, clen)
    if sym < 16:
      return Inflate/read_lengths(s1, clen, n - 1, sym, List/Cons(sym, acc))
    elif sym == 16:
      (r, s2) = Inflate/bits(s1, 2)
      return Inflate/repeat_len(s2, clen, n, prev, acc, 3 + r, prev)
    elif sym == 17:
      (r, s2) = Inflate/bits(s1, 3)
      return Inflate/repeat_len(s2, clen, n, 0, acc, 3 + r, 0)
    else:
      (r, s2) = Inflate/bits(s1, 7)
      return Inflate/repeat_len(s2, clen, n, 0, acc, 11 + r, 0)

def Inflate/repeat_len(s, clen, n: u24, prev: u24, acc: List(u24), times: u24, v: u24):
  if (times == 0) | (n == 0):
    return Inflate/read_lengths(s, clen, n, prev, acc)
  else:
    return Inflate/repeat_len(s, clen, n - 1, prev, List/Cons(v, acc), times - 1, v)

def Inflate/dynamic(s, o):
  (hlit, s1) = Inflate/bits(s, 5)
  (hdist, s2) = Inflate/bits(s1, 5)
  (hclen, s3) = Inflate/bits(s2, 4)
  nlit = hlit + 257
  ndist = hdist + 1
  (vals, s4) = Inflate/read3(s3, hclen + 4)
  clen = Inflate/build(Inflate/clen_lengths(vals, hclen + 4, Inflate/CLEN_POS))
  (lens, s5) = Inflate/read_lengths(s4, clen, nlit + ndist, 0, [])
  lit = Inflate/build(Bytes/take(lens, nlit))
  dist = Inflate/build(Bytes/drop(lens, nlit))
  return Inflate/codes(s5, o, lit, dist)

def Inflate/blocks(s, o):
  (last, s1) = Inflate/bits(s, 1)
  (type, s2) = Inflate/bits(s1, 2)
  if type == 0:
    (s3, o2) = Inflate/stored(s2, o)
  elif type == 1:
    (s3, o2) = Inflate/codes(s2, o, Inflate/fixed_lit(type - 1), Inflate/fixed_dist(type - 1))
  elif type == 2:
    (s3, o2) = Inflate/dynamic(s2, o)
  else:
    (s3, o2) = (([], 0, 0), o)
  (xs, *, *) = s3
  if last:
    return o2
  else:
    match xs:
      case List/Nil:
        return o2
      case List/Cons:
        return Inflate/blocks(s3, o2)

# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

# Descomprime datos DEFLATE "crudos".
def Inflate/raw(xs: List(u24)) -> List(u24):
  (*, *, out) = Inflate/blocks((xs, 0, 0), (Map/empty, 0, []))
  return Bytes/reverse(out)

# Descomprime un flujo zlib (encabezado de 2 bytes + DEFLATE + Adler-32).
def Inflate/zlib(xs: List(u24)) -> List(u24):
  return Inflate/raw(Bytes/drop(xs, 2))

# ---------------------------------------------------------------------------
# Predictores PNG (/Predictor >= 10 en /DecodeParms)
# ---------------------------------------------------------------------------

# Revierte el filtrado PNG por filas. `columns` = bytes por fila (sin el byte
# de tipo de filtro), `bpp` = bytes por píxel (1 para xref streams).
def Png/unfilter(data: List(u24), columns: u24, bpp: u24) -> List(u24):
  return Png/rows(data, columns, bpp, Bytes/repeat(0, columns))

def Png/rows(data: List(u24), columns: u24, bpp: u24, prev: List(u24)) -> List(u24):
  match data:
    case List/Nil:
      return []
    case List/Cons:
      ftype = data.head
      row = Bytes/take(data.tail, columns)
      out = Png/row(ftype, row, prev, Bytes/repeat(0, bpp), Bytes/repeat(0, bpp))
      return Bytes/concat(out, Png/rows(Bytes/drop(data.tail, columns), columns, bpp, out))

# left/upleft: colas con los últimos `bpp` bytes decodificados (izquierda y
# diagonal superior izquierda), la más antigua primero.
def Png/row(ftype: u24, row: List(u24), up: List(u24), left: List(u24), upleft: List(u24)) -> List(u24):
  match row:
    case List/Nil:
      return []
    case List/Cons:
      a = Inflate/at(left, 0)
      b = Inflate/at(up, 0)
      c = Inflate/at(upleft, 0)
      x = row.head
      if ftype == 0:
        v = x
      elif ftype == 1:
        v = (x + a) & 0xFF
      elif ftype == 2:
        v = (x + b) & 0xFF
      elif ftype == 3:
        v = (x + ((a + b) >> 1)) & 0xFF
      else:
        v = (x + Png/paeth(a, b, c)) & 0xFF
      left2 = List/concat(Bytes/drop(left, 1), [v])
      upleft2 = List/concat(Bytes/drop(upleft, 1), [b])
      return List/Cons(v, Png/row(ftype, row.tail, Bytes/drop(up, 1), left2, upleft2))

def Png/abs_diff(x: u24, y: u24) -> u24:
  if x > y:
    return x - y
  else:
    return y - x

def Png/paeth(a: u24, b: u24, c: u24) -> u24:
  # p = a + b - c; pa = |p - a| = |b - c|; pb = |a - c|; pc = |a + b - 2c|
  pa = Png/abs_diff(b, c)
  pb = Png/abs_diff(a, c)
  pc = Png/abs_diff(a + b, c + c)
  if (pa <= pb) & (pa <= pc):
    return a
  elif pb <= pc:
    return b
  else:
    return c
