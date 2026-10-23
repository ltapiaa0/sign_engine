# lib/sha256.bend
# SHA-256 (FIPS 180-4).
#
# Bend sólo tiene enteros de 24 bits, así que cada palabra de 32 bits se
# representa como dos mitades de 16 bits (hi, lo). Para reducir el número de
# interacciones en HVM, las rondas trabajan con el estado "aplanado" en 16
# argumentos en lugar de tuplas y las rotaciones se expanden con constantes.

from lib/bytes import *

# Constantes K en formato plano [hi, lo, hi, lo, ...].
def Sha256/K() -> List(u24):
  return [
    0x428a, 0x2f98, 0x7137, 0x4491, 0xb5c0, 0xfbcf, 0xe9b5, 0xdba5,
    0x3956, 0xc25b, 0x59f1, 0x11f1, 0x923f, 0x82a4, 0xab1c, 0x5ed5,
    0xd807, 0xaa98, 0x1283, 0x5b01, 0x2431, 0x85be, 0x550c, 0x7dc3,
    0x72be, 0x5d74, 0x80de, 0xb1fe, 0x9bdc, 0x06a7, 0xc19b, 0xf174,
    0xe49b, 0x69c1, 0xefbe, 0x4786, 0x0fc1, 0x9dc6, 0x240c, 0xa1cc,
    0x2de9, 0x2c6f, 0x4a74, 0x84aa, 0x5cb0, 0xa9dc, 0x76f9, 0x88da,
    0x983e, 0x5152, 0xa831, 0xc66d, 0xb003, 0x27c8, 0xbf59, 0x7fc7,
    0xc6e0, 0x0bf3, 0xd5a7, 0x9147, 0x06ca, 0x6351, 0x1429, 0x2967,
    0x27b7, 0x0a85, 0x2e1b, 0x2138, 0x4d2c, 0x6dfc, 0x5338, 0x0d13,
    0x650a, 0x7354, 0x766a, 0x0abb, 0x81c2, 0xc92e, 0x9272, 0x2c85,
    0xa2bf, 0xe8a1, 0xa81a, 0x664b, 0xc24b, 0x8b70, 0xc76c, 0x51a3,
    0xd192, 0xe819, 0xd699, 0x0624, 0xf40e, 0x3585, 0x106a, 0xa070,
    0x19a4, 0xc116, 0x1e37, 0x6c08, 0x2748, 0x774c, 0x34b0, 0xbcb5,
    0x391c, 0x0cb3, 0x4ed8, 0xaa4a, 0x5b9c, 0xca4f, 0x682e, 0x6ff3,
    0x748f, 0x82ee, 0x78a5, 0x636f, 0x84c8, 0x7814, 0x8cc7, 0x0208,
    0x90be, 0xfffa, 0xa450, 0x6ceb, 0xbef9, 0xa3f7, 0xc671, 0x78f2
  ]

# Estado inicial H0 como tupla plana de 16 mitades.
def Sha256/H0():
  return (0x6a09, 0xe667, 0xbb67, 0xae85, 0x3c6e, 0xf372, 0xa54f, 0xf53a, 0x510e, 0x527f, 0x9b05, 0x688c, 0x1f83, 0xd9ab, 0x5be0, 0xcd19)

def W32/to_bytes(h: u24, l: u24, rest: List(u24)) -> List(u24):
  return List/Cons(h >> 8, List/Cons(h & 0xFF, List/Cons(l >> 8, List/Cons(l & 0xFF, rest))))

# Aplica una función currificada a cada elemento de la lista, en orden.
def Sha256/apply(f, xs):
  match xs:
    case List/Nil:
      return f
    case List/Cons:
      return Sha256/apply(f(xs.head), xs.tail)

# Convierte un bloque de 64 bytes en 32 mitades de 16 bits [hi, lo, ...].
def Sha256/block_words(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      match t = xs.tail:
        case List/Nil:
          return []
        case List/Cons:
          return List/Cons((xs.head << 8) | t.head, Sha256/block_words(t.tail))

# Genera `n` palabras más del "message schedule" a partir de una ventana
# de 16 palabras (w0 es la más antigua). Devuelve una lista plana [hi, lo, ...].
def Sha256/schedule(n, w0h, w0l, w1h, w1l, w2h, w2l, w3h, w3l, w4h, w4l, w5h, w5l, w6h, w6l, w7h, w7l, w8h, w8l, w9h, w9l, w10h, w10l, w11h, w11l, w12h, w12l, w13h, w13l, w14h, w14l, w15h, w15l):
  if n == 0:
    return []
  else:
    s0h = (((w1h >> 7) | (w1l << 9)) ^ ((w1l >> 2) | (w1h << 14)) ^ (w1h >> 3)) & 0xFFFF
    s0l = (((w1l >> 7) | (w1h << 9)) ^ ((w1h >> 2) | (w1l << 14)) ^ ((w1l >> 3) | (w1h << 13))) & 0xFFFF
    s1h = (((w14l >> 1) | (w14h << 15)) ^ ((w14l >> 3) | (w14h << 13)) ^ (w14h >> 10)) & 0xFFFF
    s1l = (((w14h >> 1) | (w14l << 15)) ^ ((w14h >> 3) | (w14l << 13)) ^ ((w14l >> 10) | (w14h << 6))) & 0xFFFF
    nl = s1l + w9l + s0l + w0l
    nh = (s1h + w9h + s0h + w0h + (nl >> 16)) & 0xFFFF
    nl = nl & 0xFFFF
    return List/Cons(nh, List/Cons(nl, Sha256/schedule(n - 1, w1h, w1l, w2h, w2l, w3h, w3l, w4h, w4l, w5h, w5l, w6h, w6l, w7h, w7l, w8h, w8l, w9h, w9l, w10h, w10l, w11h, w11l, w12h, w12l, w13h, w13l, w14h, w14l, w15h, w15l, nh, nl)))

# 64 rondas. `ks` y `ws` son listas planas [hi, lo, hi, lo, ...].
def Sha256/rounds(ah, al, bh, bl, ch, cl, dh, dl, eh, el, fh, fl, gh, gl, hh, hl, ks, ws):
  match ks:
    case List/Nil:
      return (ah, al, bh, bl, ch, cl, dh, dl, eh, el, fh, fl, gh, gl, hh, hl)
    case List/Cons:
      kh = ks.head
      match k2 = ks.tail:
        case List/Nil:
          return (ah, al, bh, bl, ch, cl, dh, dl, eh, el, fh, fl, gh, gl, hh, hl)
        case List/Cons:
          kl = k2.head
          match ws:
            case List/Nil:
              return (ah, al, bh, bl, ch, cl, dh, dl, eh, el, fh, fl, gh, gl, hh, hl)
            case List/Cons:
              wh = ws.head
              match w2 = ws.tail:
                case List/Nil:
                  return (ah, al, bh, bl, ch, cl, dh, dl, eh, el, fh, fl, gh, gl, hh, hl)
                case List/Cons:
                  s1h = (((eh >> 6) | (el << 10)) ^ ((eh >> 11) | (el << 5)) ^ ((el >> 9) | (eh << 7))) & 0xFFFF
                  s1l = (((el >> 6) | (eh << 10)) ^ ((el >> 11) | (eh << 5)) ^ ((eh >> 9) | (el << 7))) & 0xFFFF
                  chh = (eh & fh) ^ ((eh ^ 0xFFFF) & gh)
                  chl = (el & fl) ^ ((el ^ 0xFFFF) & gl)
                  t1l = hl + s1l + chl + kl + w2.head
                  t1h = (hh + s1h + chh + kh + wh + (t1l >> 16)) & 0xFFFF
                  t1l = t1l & 0xFFFF
                  s0h = (((ah >> 2) | (al << 14)) ^ ((ah >> 13) | (al << 3)) ^ ((al >> 6) | (ah << 10))) & 0xFFFF
                  s0l = (((al >> 2) | (ah << 14)) ^ ((al >> 13) | (ah << 3)) ^ ((ah >> 6) | (al << 10))) & 0xFFFF
                  mjh = (ah & bh) ^ (ah & ch) ^ (bh & ch)
                  mjl = (al & bl) ^ (al & cl) ^ (bl & cl)
                  nal = t1l + s0l + mjl
                  nah = (t1h + s0h + mjh + (nal >> 16)) & 0xFFFF
                  nel = dl + t1l
                  neh = (dh + t1h + (nel >> 16)) & 0xFFFF
                  return Sha256/rounds(nah, nal & 0xFFFF, ah, al, bh, bl, ch, cl, neh, nel & 0xFFFF, eh, el, fh, fl, gh, gl, k2.tail, w2.tail)

def Sha256/compress(st, block: List(u24)):
  (ah, al, bh, bl, ch, cl, dh, dl, eh, el, fh, fl, gh, gl, hh, hl) = st
  ws = Sha256/block_words(block)
  full = List/concat(ws, Sha256/apply(Sha256/schedule(48), ws))
  (a2h, a2l, b2h, b2l, c2h, c2l, d2h, d2l, e2h, e2l, f2h, f2l, g2h, g2l, h2h, h2l) = Sha256/rounds(ah, al, bh, bl, ch, cl, dh, dl, eh, el, fh, fl, gh, gl, hh, hl, Sha256/K, full)
  asl = al + a2l
  ash = (ah + a2h + (asl >> 16)) & 0xFFFF
  bsl = bl + b2l
  bsh = (bh + b2h + (bsl >> 16)) & 0xFFFF
  csl = cl + c2l
  csh = (ch + c2h + (csl >> 16)) & 0xFFFF
  dsl = dl + d2l
  dsh = (dh + d2h + (dsl >> 16)) & 0xFFFF
  esl = el + e2l
  esh = (eh + e2h + (esl >> 16)) & 0xFFFF
  fsl = fl + f2l
  fsh = (fh + f2h + (fsl >> 16)) & 0xFFFF
  gsl = gl + g2l
  gsh = (gh + g2h + (gsl >> 16)) & 0xFFFF
  hsl = hl + h2l
  hsh = (hh + h2h + (hsl >> 16)) & 0xFFFF
  return (ash, asl & 0xFFFF, bsh, bsl & 0xFFFF, csh, csl & 0xFFFF, dsh, dsl & 0xFFFF, esh, esl & 0xFFFF, fsh, fsl & 0xFFFF, gsh, gsl & 0xFFFF, hsh, hsl & 0xFFFF)

# Separa los primeros 64 bytes: (bloque, resto, cantidad_tomada).
def Sha256/split64(xs: List(u24), n: u24) -> (List(u24), List(u24), u24):
  if n == 64:
    return ([], xs, 64)
  else:
    match xs:
      case List/Nil:
        return ([], [], n)
      case List/Cons:
        (blk, rest, cnt) = Sha256/split64(xs.tail, n + 1)
        return (List/Cons(xs.head, blk), rest, cnt)

# Relleno final: mensaje restante (< 64 bytes) + 0x80 + ceros + longitud en bits
# (la longitud total está limitada a 2^24 bytes por el tipo u24).
def Sha256/padding(tail: List(u24), tail_len: u24, total: u24) -> List(u24):
  if tail_len < 56:
    zeros = 55 - tail_len
  else:
    zeros = 119 - tail_len
  len_bytes = [0, 0, 0, 0, (total >> 21) & 0xFF, (total >> 13) & 0xFF, (total >> 5) & 0xFF, (total << 3) & 0xFF]
  return Bytes/concat(tail, List/Cons(0x80, Bytes/concat(Bytes/repeat(0, zeros), len_bytes)))

def Sha256/process(st, xs: List(u24), total: u24):
  (blk, rest, cnt) = Sha256/split64(xs, 0)
  if cnt == 64:
    return Sha256/process(Sha256/compress(st, blk), rest, total + 64)
  else:
    padded = Sha256/padding(blk, cnt, total + cnt)
    (b1, b2, *) = Sha256/split64(padded, 0)
    if cnt < 56:
      return Sha256/compress(st, b1)
    else:
      return Sha256/compress(Sha256/compress(st, b1), b2)

def Sha256/state_bytes(st) -> List(u24):
  (ah, al, bh, bl, ch, cl, dh, dl, eh, el, fh, fl, gh, gl, hh, hl) = st
  return W32/to_bytes(ah, al, W32/to_bytes(bh, bl, W32/to_bytes(ch, cl, W32/to_bytes(dh, dl, W32/to_bytes(eh, el, W32/to_bytes(fh, fl, W32/to_bytes(gh, gl, W32/to_bytes(hh, hl, []))))))))

# Hash SHA-256 de una secuencia de bytes; retorna 32 bytes.
def Sha256/digest(xs: List(u24)) -> List(u24):
  return Sha256/state_bytes(Sha256/process(Sha256/H0, xs, 0))
