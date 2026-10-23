# lib/bigint.bend
# Enteros sin signo de precisión arbitraria.
#
# Representación: lista little-endian de "limbs" de 12 bits.
# Se eligen 12 bits porque el producto de dos limbs más dos acarreos cabe
# exactamente en un u24:  (2^12-1)^2 + 2*(2^12-1) = 2^24 - 1.
#
# La exponenciación modular usa multiplicación de Montgomery (CIOS) con
# ventana fija de 4 bits.

from lib/bytes import *

# ---------------------------------------------------------------------------
# Utilidades de listas genéricas
# ---------------------------------------------------------------------------

def BigInt/at(xs, i: u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      if i == 0:
        return xs.head
      else:
        return BigInt/at(xs.tail, i - 1)

def BigInt/head(xs: List(u24)) -> u24:
  match xs:
    case List/Nil:
      return 0
    case List/Cons:
      return xs.head

def BigInt/tail(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      return xs.tail

# ---------------------------------------------------------------------------
# Conversión
# ---------------------------------------------------------------------------

def BigInt/from_u24(n: u24) -> List(u24):
  return BigInt/normalize([n & 0xFFF, n >> 12])

# Bytes big-endian -> BigInt.
def BigInt/from_bytes(bs: List(u24)) -> List(u24):
  return BigInt/normalize(BigInt/from_le3(Bytes/reverse(bs)))

def BigInt/from_le3(bs: List(u24)) -> List(u24):
  match bs:
    case List/Nil:
      return []
    case List/Cons:
      b0 = bs.head
      match t1 = bs.tail:
        case List/Nil:
          return [b0]
        case List/Cons:
          b1 = t1.head
          match t2 = t1.tail:
            case List/Nil:
              v = b0 | (b1 << 8)
              return [v & 0xFFF, v >> 12]
            case List/Cons:
              v = b0 | (b1 << 8) | (t2.head << 16)
              return List/Cons(v & 0xFFF, List/Cons(v >> 12, BigInt/from_le3(t2.tail)))

# BigInt -> bytes big-endian con longitud exacta `len` (rellena con ceros).
def BigInt/to_bytes(n: List(u24), len: u24) -> List(u24):
  return Bytes/pad_left(Bytes/strip_zeros(Bytes/reverse(BigInt/to_le3(n))), len, 0)

# BigInt -> bytes big-endian mínimos (al menos un byte).
def BigInt/to_bytes_min(n: List(u24)) -> List(u24):
  return Bytes/pad_left(Bytes/strip_zeros(Bytes/reverse(BigInt/to_le3(n))), 1, 0)

def BigInt/to_le3(n: List(u24)) -> List(u24):
  match n:
    case List/Nil:
      return []
    case List/Cons:
      match t = n.tail:
        case List/Nil:
          return [n.head & 0xFF, n.head >> 8]
        case List/Cons:
          v = n.head | (t.head << 12)
          return List/Cons(v & 0xFF, List/Cons((v >> 8) & 0xFF, List/Cons(v >> 16, BigInt/to_le3(t.tail))))

# Elimina limbs cero de la parte alta.
def BigInt/normalize(n: List(u24)) -> List(u24):
  return Bytes/reverse(Bytes/strip_zeros(Bytes/reverse(n)))

def BigInt/is_zero(n: List(u24)) -> u24:
  match n:
    case List/Nil:
      return 1
    case List/Cons:
      if n.head == 0:
        return BigInt/is_zero(n.tail)
      else:
        return 0

# Ajusta a exactamente k limbs (rellena con ceros o trunca).
def BigInt/fit(n: List(u24), k: u24) -> List(u24):
  if k == 0:
    return []
  else:
    match n:
      case List/Nil:
        return List/Cons(0, BigInt/fit([], k - 1))
      case List/Cons:
        return List/Cons(n.head, BigInt/fit(n.tail, k - 1))

# Bits del número, del más significativo al menos significativo.
def BigInt/bits_msb(n: List(u24)) -> List(u24):
  return BigInt/bits_msb.go(Bytes/reverse(BigInt/normalize(n)))

def BigInt/bits_msb.go(limbs: List(u24)) -> List(u24):
  match limbs:
    case List/Nil:
      return []
    case List/Cons:
      x = limbs.head
      return List/Cons((x >> 11) & 1, List/Cons((x >> 10) & 1, List/Cons((x >> 9) & 1, List/Cons((x >> 8) & 1, List/Cons((x >> 7) & 1, List/Cons((x >> 6) & 1, List/Cons((x >> 5) & 1, List/Cons((x >> 4) & 1, List/Cons((x >> 3) & 1, List/Cons((x >> 2) & 1, List/Cons((x >> 1) & 1, List/Cons(x & 1, BigInt/bits_msb.go(limbs.tail)))))))))))))

# ---------------------------------------------------------------------------
# Comparación y aritmética básica
# ---------------------------------------------------------------------------

# 0 si a < b, 1 si a == b, 2 si a > b.
def BigInt/cmp(a: List(u24), b: List(u24)) -> u24:
  an = BigInt/normalize(a)
  bn = BigInt/normalize(b)
  la = Bytes/len(an)
  lb = Bytes/len(bn)
  if la < lb:
    return 0
  elif la > lb:
    return 2
  else:
    return Bytes/compare(Bytes/reverse(an), Bytes/reverse(bn))

def BigInt/add(a: List(u24), b: List(u24)) -> List(u24):
  return BigInt/add.go(a, b, 0)

def BigInt/add.go(a: List(u24), b: List(u24), c: u24) -> List(u24):
  match a:
    case List/Nil:
      match b:
        case List/Nil:
          if c == 0:
            return []
          else:
            return [c]
        case List/Cons:
          t = b.head + c
          return List/Cons(t & 0xFFF, BigInt/add.go([], b.tail, t >> 12))
    case List/Cons:
      match b:
        case List/Nil:
          t = a.head + c
          return List/Cons(t & 0xFFF, BigInt/add.go(a.tail, [], t >> 12))
        case List/Cons:
          t = a.head + b.head + c
          return List/Cons(t & 0xFFF, BigInt/add.go(a.tail, b.tail, t >> 12))

# a - b, requiere a >= b. Resultado normalizado.
def BigInt/sub(a: List(u24), b: List(u24)) -> List(u24):
  return BigInt/normalize(BigInt/sub.go(a, b, 0))

def BigInt/sub.go(a: List(u24), b: List(u24), borrow: u24) -> List(u24):
  match a:
    case List/Nil:
      return []
    case List/Cons:
      t = (a.head + 0x1000) - BigInt/head(b) - borrow
      return List/Cons(t & 0xFFF, BigInt/sub.go(a.tail, BigInt/tail(b), 1 - (t >> 12)))

# r + a*d + c (un limb d), en una sola pasada.
def BigInt/muladd(a: List(u24), d: u24, r: List(u24), c: u24) -> List(u24):
  match a:
    case List/Nil:
      return BigInt/add.go(r, [], c)
    case List/Cons:
      match r:
        case List/Nil:
          t = a.head * d + c
          return List/Cons(t & 0xFFF, BigInt/muladd(a.tail, d, [], t >> 12))
        case List/Cons:
          t = a.head * d + r.head + c
          return List/Cons(t & 0xFFF, BigInt/muladd(a.tail, d, r.tail, t >> 12))

def BigInt/mul(a: List(u24), b: List(u24)) -> List(u24):
  return BigInt/normalize(BigInt/mul.go(a, b))

def BigInt/mul.go(a: List(u24), b: List(u24)) -> List(u24):
  match b:
    case List/Nil:
      return []
    case List/Cons:
      return BigInt/muladd(a, b.head, List/Cons(0, BigInt/mul.go(a, b.tail)), 0)

# 2*r + bit
def BigInt/shl1(r: List(u24), bit: u24) -> List(u24):
  match r:
    case List/Nil:
      if bit == 0:
        return []
      else:
        return [bit]
    case List/Cons:
      t = (r.head << 1) | bit
      return List/Cons(t & 0xFFF, BigInt/shl1(r.tail, t >> 12))

# a mod m (división binaria; adecuada para reducciones puntuales).
def BigInt/mod(a: List(u24), m: List(u24)) -> List(u24):
  return BigInt/mod.go(BigInt/bits_msb(a), BigInt/normalize(m), [])

def BigInt/mod.go(bits: List(u24), m: List(u24), r: List(u24)) -> List(u24):
  match bits:
    case List/Nil:
      return r
    case List/Cons:
      r2 = BigInt/shl1(r, bits.head)
      if BigInt/cmp(r2, m) == 0:
        return BigInt/mod.go(bits.tail, m, r2)
      else:
        return BigInt/mod.go(bits.tail, m, BigInt/sub(r2, m))

# ---------------------------------------------------------------------------
# Montgomery (CIOS), R = 2^(12k)
# ---------------------------------------------------------------------------

# -n0^-1 mod 2^12 (n0 impar), por iteración de Newton.
def BigInt/mont_ninv(n0: u24) -> u24:
  x1 = BigInt/inv_step(n0, n0)
  x2 = BigInt/inv_step(n0, x1)
  x3 = BigInt/inv_step(n0, x2)
  x4 = BigInt/inv_step(n0, x3)
  return (0x1000 - x4) & 0xFFF

def BigInt/inv_step(n0: u24, x: u24) -> u24:
  nx = (n0 * x) & 0xFFF
  return (x * ((0x1002 - nx) & 0xFFF)) & 0xFFF

# Estado de una multiplicación de Montgomery: lista de k+1 pares
# (t_j, b_j | n_j << 12), donde t es el acumulador y b_j, n_j los limbs del
# multiplicando y del módulo (el último par lleva b = n = 0 y guarda el limb
# alto de t). Recorrer una sola lista con pares es bastante más barato en HVM
# que recorrer t, b y n por separado.
def BigInt/pack(b: List(u24), n: List(u24)):
  match b:
    case List/Nil:
      return [(0, 0)]
    case List/Cons:
      return List/Cons((0, b.head | (BigInt/head(n) << 12)), BigInt/pack(b.tail, BigInt/tail(n)))

# Primer paso de una fila de CIOS: calcula m y descarta el limb 0 (que es 0).
def BigInt/mont_row0(ai: u24, ninv: u24, st):
  match st:
    case List/Nil:
      return []
    case List/Cons:
      (t, v) = st.head
      x = t + ai * (v & 0xFFF)
      lo = x & 0xFFF
      m = (lo * ninv) & 0xFFF
      y = lo + m * (v >> 12)
      return BigInt/mont_row(ai, m, st.tail, v, x >> 12, y >> 12)

# Resto de la fila: (t + ai*b + m*n) / 2^12, con dos cadenas de acarreo
# independientes para no desbordar 24 bits:
#   (2^12-1) + (2^12-1)^2 + (2^12-1) = 2^24 - 1.
# Emite (u_j, bn_{j-1}): el resultado queda desplazado un limb.
def BigInt/mont_row(ai: u24, m: u24, st, prev: u24, c1: u24, c2: u24):
  match st:
    case List/Nil:
      return [(c1 + c2, prev)]
    case List/Cons:
      (t, v) = st.head
      x = t + ai * (v & 0xFFF) + c1
      y = (x & 0xFFF) + m * (v >> 12) + c2
      return List/Cons((y & 0xFFF, prev), BigInt/mont_row(ai, m, st.tail, v, x >> 12, y >> 12))

def BigInt/mont_loop(a: List(u24), ninv: u24, st):
  match a:
    case List/Nil:
      return st
    case List/Cons:
      return BigInt/mont_loop(a.tail, ninv, BigInt/mont_row0(a.head, ninv, st))

def BigInt/unpack(st, k: u24) -> List(u24):
  if k == 0:
    return []
  else:
    match st:
      case List/Nil:
        return List/Cons(0, BigInt/unpack([], k - 1))
      case List/Cons:
        (t, *) = st.head
        return List/Cons(t, BigInt/unpack(st.tail, k - 1))

# a*b*R^-1 mod n, con a, b < 2n, n < R/4. Resultado < 2n con exactamente k limbs.
def BigInt/mont_mul(a: List(u24), b: List(u24), n: List(u24), ninv: u24, k: u24) -> List(u24):
  st = BigInt/pack(BigInt/fit(b, k), n)
  return BigInt/unpack(BigInt/mont_loop(BigInt/fit(a, k), ninv, st), k)

# Número de bits de n (normalizado).
def BigInt/bit_len(n: List(u24)) -> u24:
  nn = BigInt/normalize(n)
  len = Bytes/len(nn)
  if len == 0:
    return 0
  else:
    return 12 * (len - 1) + BigInt/bit_len.u12(BigInt/head(Bytes/reverse(nn)))

def BigInt/bit_len.u12(x: u24) -> u24:
  if x == 0:
    return 0
  else:
    return 1 + BigInt/bit_len.u12(x >> 1)

# 2^e como BigInt.
def BigInt/pow2(e: u24) -> List(u24):
  return Bytes/concat(Bytes/repeat(0, e / 12), [1 << (e % 12)])

# 2^e mod m partiendo de 2^s mod m = r (s < e), duplicando e - s veces.
def BigInt/double_mod(r: List(u24), times: u24, m: List(u24)) -> List(u24):
  if times == 0:
    return r
  else:
    r2 = BigInt/shl1(r, 0)
    if BigInt/cmp(r2, m) == 0:
      return BigInt/double_mod(r2, times - 1, m)
    else:
      return BigInt/double_mod(BigInt/sub(r2, m), times - 1, m)

# Contexto de Montgomery para un módulo n impar:
#   (n con k limbs, k, ninv, R^2 mod n, R^3 mod n, n normalizado)
# con R = 2^(12k) y k elegido para que n < R/4.
#
# R^2 se calcula sin división larga: 2^(bits-1) < n ya está reducido, se
# duplica hasta 2^(15k) mod n y dos cuadrados de Montgomery dan
# 2^(2*15k - 12k) = 2^(18k) y luego 2^(36k - 12k) = 2^(24k) = R^2.
def BigInt/mont_ctx(n: List(u24)):
  nn = BigInt/normalize(n)
  top = BigInt/head(Bytes/reverse(nn))
  if top < 0x400:
    k = Bytes/len(nn)
  else:
    k = Bytes/len(nn) + 1
  nk = BigInt/fit(nn, k)
  ninv = BigInt/mont_ninv(BigInt/head(nn))
  bits = BigInt/bit_len(nn)
  c = BigInt/double_mod(BigInt/pow2(bits - 1), 15 * k - (bits - 1), nn)
  s1 = BigInt/mont_mul(c, c, nk, ninv, k)
  r2 = BigInt/reduce_once(BigInt/mont_mul(s1, s1, nk, ninv, k), nn)
  r3 = BigInt/mont_mul(r2, r2, nk, ninv, k)
  return (nk, k, ninv, r2, r3, nn)

# Reduce x < 2n a x mod n.
def BigInt/reduce_once(x: List(u24), n: List(u24)) -> List(u24):
  if BigInt/cmp(x, n) == 0:
    return BigInt/normalize(x)
  else:
    return BigInt/sub(x, n)

# Reduce x a x mod n restando n mientras x >= n (para x pequeño respecto de n).
def BigInt/reduce_small(x: List(u24), n: List(u24)) -> List(u24):
  if BigInt/cmp(x, n) == 0:
    return BigInt/normalize(x)
  else:
    return BigInt/reduce_small(BigInt/sub(x, n), n)

# x*R mod n (forma de Montgomery) para x < R^2, sin división larga:
# x = lo + hi*R  =>  x*R = mont(lo, R^2) + mont(hi, R^3)  (mod n).
# Para x >= R^2 se usa la división binaria.
def BigInt/to_mont(x: List(u24), ctx) -> List(u24):
  (nk, k, ninv, r2, r3, nn) = ctx
  xn = BigInt/normalize(x)
  if Bytes/len(xn) > 2 * k:
    return BigInt/mont_mul(BigInt/mod(xn, nn), r2, nk, ninv, k)
  else:
    a = BigInt/mont_mul(Bytes/take(xn, k), r2, nk, ninv, k)
    b = BigInt/mont_mul(Bytes/drop(xn, k), r3, nk, ninv, k)
    return BigInt/reduce_small(BigInt/add(a, b), nn)

# y*R^-1 mod n (sale de la forma de Montgomery), resultado < n.
def BigInt/from_mont(y: List(u24), ctx) -> List(u24):
  (nk, k, ninv, *, *, nn) = ctx
  return BigInt/reduce_once(BigInt/mont_mul(y, [1], nk, ninv, k), nn)

# x mod n usando el contexto.
def BigInt/mod_ctx(x: List(u24), ctx) -> List(u24):
  return BigInt/from_mont(BigInt/to_mont(x, ctx), ctx)

# a*b mod n usando el contexto (a, b < R^2).
def BigInt/mulmod_ctx(a: List(u24), b: List(u24), ctx) -> List(u24):
  (nk, k, ninv, *, *, nn) = ctx
  am = BigInt/to_mont(a, ctx)
  bm = BigInt/to_mont(b, ctx)
  return BigInt/from_mont(BigInt/mont_mul(am, bm, nk, ninv, k), ctx)

# Nibbles (4 bits) de un exponente dado en bytes big-endian.
def BigInt/nibbles(bs: List(u24)) -> List(u24):
  match bs:
    case List/Nil:
      return []
    case List/Cons:
      return List/Cons(bs.head >> 4, List/Cons(bs.head & 15, BigInt/nibbles(bs.tail)))

def BigInt/mont_table(x: List(u24), base: List(u24), n: List(u24), ninv: u24, k: u24, count: u24):
  if count == 0:
    return []
  else:
    return List/Cons(x, BigInt/mont_table(BigInt/mont_mul(x, base, n, ninv, k), base, n, ninv, k, count - 1))

def BigInt/mont_sq4(x: List(u24), n: List(u24), ninv: u24, k: u24) -> List(u24):
  x1 = BigInt/mont_mul(x, x, n, ninv, k)
  x2 = BigInt/mont_mul(x1, x1, n, ninv, k)
  x3 = BigInt/mont_mul(x2, x2, n, ninv, k)
  return BigInt/mont_mul(x3, x3, n, ninv, k)

def BigInt/modexp.go(acc: List(u24), nibs: List(u24), table, n: List(u24), ninv: u24, k: u24) -> List(u24):
  match nibs:
    case List/Nil:
      return acc
    case List/Cons:
      acc2 = BigInt/mont_mul(BigInt/mont_sq4(acc, n, ninv, k), BigInt/at(table, nibs.head), n, ninv, k)
      return BigInt/modexp.go(acc2, nibs.tail, table, n, ninv, k)

# base^exp mod n con un contexto ya calculado; `exp` en bytes big-endian.
# Ventana fija de 4 bits: siempre multiplica (también por 1), de modo que la
# secuencia de operaciones no depende de los bits del exponente.
def BigInt/modexp_ctx(base: List(u24), exp: List(u24), ctx) -> List(u24):
  (nk, k, ninv, r2, *, *) = ctx
  bm = BigInt/to_mont(base, ctx)
  one = BigInt/mont_mul([1], r2, nk, ninv, k)
  table = BigInt/mont_table(one, bm, nk, ninv, k, 16)
  acc = BigInt/modexp.go(one, BigInt/nibbles(Bytes/strip_zeros(exp)), table, nk, ninv, k)
  return BigInt/from_mont(acc, ctx)

# base^exp mod n. `exp` en bytes big-endian; n impar; base cualquiera.
def BigInt/modexp(base: List(u24), exp: List(u24), n: List(u24)) -> List(u24):
  return BigInt/modexp_ctx(base, exp, BigInt/mont_ctx(n))
