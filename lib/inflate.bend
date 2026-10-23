from lib/bytes import *

def Inflate/bits(s, need: u24):
  (xs, buf, cnt, over) = s
  if cnt >= need:
    return (buf & ((1 << need) - 1), (xs, buf >> need, cnt - need, over))
  else:
    match xs:
      case List/Nil:
        return Inflate/bits(([], buf, cnt + 8, over + 1), need)
      case List/Cons:
        return Inflate/bits((xs.tail, buf | (xs.head << cnt), cnt + 8, over), need)

def Inflate/align(s):
  (xs, buf, cnt, over) = s
  r = cnt & 7
  return (xs, buf >> r, cnt - r, over)

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

type Huff:
  Empty
  Leaf { sym: u24 }
  Node { zero: Huff, one: Huff }

def Inflate/build(lengths: List(u24)) -> Huff:
  return Inflate/build.go(lengths, 1, 0, Huff/Empty)

def Inflate/build.go(lengths: List(u24), len: u24, first: u24, tree: Huff) -> Huff:
  if len > 15:
    return tree
  else:
    syms = Inflate/syms_with_len(lengths, len, 0)
    count = Inflate/count(syms)
    return Inflate/build.go(lengths, len + 1, (first + count) << 1, Inflate/insert_all(tree, syms, first, len))

def Inflate/syms_with_len(lengths: List(u24), len: u24, sym: u24) -> List(u24):
  match lengths:
    case List/Nil:
      return []
    case List/Cons:
      if lengths.head == len:
        return List/Cons(sym, Inflate/syms_with_len(lengths.tail, len, sym + 1))
      else:
        return Inflate/syms_with_len(lengths.tail, len, sym + 1)

def Inflate/insert_all(tree: Huff, syms: List(u24), code: u24, len: u24) -> Huff:
  match syms:
    case List/Nil:
      return tree
    case List/Cons:
      return Inflate/insert_all(Inflate/insert(tree, code, len, syms.head), syms.tail, code + 1, len)

def Inflate/insert(tree: Huff, code: u24, len: u24, sym: u24) -> Huff:
  if len == 0:
    return Huff/Leaf(sym)
  else:
    bit = (code >> (len - 1)) & 1
    match tree:
      case Huff/Node:
        if bit == 0:
          return Huff/Node(Inflate/insert(tree.zero, code, len - 1, sym), tree.one)
        else:
          return Huff/Node(tree.zero, Inflate/insert(tree.one, code, len - 1, sym))
      case _:
        if bit == 0:
          return Huff/Node(Inflate/insert(Huff/Empty, code, len - 1, sym), Huff/Empty)
        else:
          return Huff/Node(Huff/Empty, Inflate/insert(Huff/Empty, code, len - 1, sym))

def Inflate/decode(s, tree: Huff):
  match tree:
    case Huff/Empty:
      return (0xFFFF, s, Huff/Empty)
    case Huff/Leaf:
      return (tree.sym, s, Huff/Leaf(tree.sym))
    case Huff/Node:
      (bit, s1) = Inflate/bits(s, 1)
      if bit == 0:
        (sym, s2, zero) = Inflate/decode(s1, tree.zero)
        return (sym, s2, Huff/Node(zero, tree.one))
      else:
        (sym, s2, one) = Inflate/decode(s1, tree.one)
        return (sym, s2, Huff/Node(tree.zero, one))

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

def Inflate/CLEN_POS() -> List(u24):
  return [3, 17, 15, 13, 11, 9, 7, 5, 4, 6, 8, 10, 12, 14, 16, 18, 0, 1, 2]

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

def Inflate/MAX_OUTPUT() -> u24:
  return 0x400000

def Inflate/codes(s, o, lit, dist):
  (sym, s1, lit2) = Inflate/decode(s, lit)
  (x1, b1, c1, v1) = s1
  (w0, p0, out0) = o
  o = (w0, p0, out0)
  if p0 >= Inflate/MAX_OUTPUT:
    return ((x1, b1, c1, v1 + 1), o)
  elif v1 > 0:
    return ((x1, b1, c1, v1), o)
  elif sym < 256:
    return Inflate/codes((x1, b1, c1, v1), Inflate/emit(o, sym), lit2, dist)
  elif sym == 256:
    return ((x1, b1, c1, v1), o)
  elif sym > 285:
    return ((x1, b1, c1, v1 + 1), o)
  else:
    li = sym - 257
    (le, s2) = Inflate/bits((x1, b1, c1, v1), Inflate/at(Inflate/LEN_EXTRA, li))
    len = Inflate/at(Inflate/LEN_BASE, li) + le
    (dsym, s3, dist2) = Inflate/decode(s2, dist)
    (de, s4) = Inflate/bits(s3, Inflate/at(Inflate/DIST_EXTRA, dsym))
    d = Inflate/at(Inflate/DIST_BASE, dsym) + de
    (x4, b4, c4, v4) = s4
    (win, pos, out) = o
    if (v4 > 0) | (dsym > 29) | (d > pos):
      return ((x4, b4, c4, v4 + 1), (win, pos, out))
    else:
      return Inflate/codes((x4, b4, c4, v4), Inflate/copy((win, pos, out), len, d), lit2, dist2)

def Inflate/stored(s, o):
  (len, s1) = Inflate/bits(Inflate/align(s), 16)
  (*, s2) = Inflate/bits(s1, 16)
  return Inflate/stored.go(s2, o, len)

def Inflate/stored.go(s, o, n: u24):
  if n == 0:
    return (s, o)
  else:
    (b, s2) = Inflate/bits(s, 8)
    (x, bb, c, v) = s2
    (w0, p0, out0) = o
    if (v > 0) | (p0 >= Inflate/MAX_OUTPUT):
      return ((x, bb, c, v + (p0 >= Inflate/MAX_OUTPUT)), (w0, p0, out0))
    else:
      return Inflate/stored.go((x, bb, c, v), Inflate/emit((w0, p0, out0), b), n - 1)

def Inflate/read3(s, n: u24):
  if n == 0:
    return ([], s)
  else:
    (v, s2) = Inflate/bits(s, 3)
    (vs, s3) = Inflate/read3(s2, n - 1)
    return (List/Cons(v, vs), s3)

def Inflate/clen_lengths(vals: List(u24), hclen: u24, pos: List(u24)) -> List(u24):
  match pos:
    case List/Nil:
      return []
    case List/Cons:
      if pos.head < hclen:
        return List/Cons(Inflate/at(vals, pos.head), Inflate/clen_lengths(vals, hclen, pos.tail))
      else:
        return List/Cons(0, Inflate/clen_lengths(vals, hclen, pos.tail))

def Inflate/read_lengths(s, clen, n: u24, prev: u24, acc: List(u24)):
  if n == 0:
    return (Bytes/reverse(acc), s)
  else:
    (sym, s1, clen2) = Inflate/decode(s, clen)
    if sym < 16:
      return Inflate/read_lengths(s1, clen2, n - 1, sym, List/Cons(sym, acc))
    elif sym == 16:
      (r, s2) = Inflate/bits(s1, 2)
      return Inflate/repeat_len(s2, clen2, n, prev, acc, 3 + r, prev)
    elif sym == 17:
      (r, s2) = Inflate/bits(s1, 3)
      return Inflate/repeat_len(s2, clen2, n, 0, acc, 3 + r, 0)
    else:
      (r, s2) = Inflate/bits(s1, 7)
      return Inflate/repeat_len(s2, clen2, n, 0, acc, 11 + r, 0)

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
    (s3, o2) = (([], 0, 0, 1), o)
  (xs, buf, cnt, over) = s3
  if last | (over > 0):
    return o2
  else:
    return Inflate/blocks((xs, buf, cnt, over), o2)

def Inflate/raw(xs: List(u24)) -> List(u24):
  (*, *, out) = Inflate/blocks((xs, 0, 0, 0), (Map/empty, 0, []))
  return Bytes/reverse(out)

def Inflate/zlib(xs: List(u24)) -> List(u24):
  return Inflate/raw(Bytes/drop(xs, 2))

def Png/unfilter(data: List(u24), columns: u24, bpp: u24) -> List(u24):
  return Png/rows(data, columns, bpp, Bytes/repeat(0, columns))

def Png/rows(data: List(u24), columns: u24, bpp: u24, prev: List(u24)) -> List(u24):
  match data:
    case List/Nil:
      return []
    case List/Cons:
      (row, rest) = Bytes/split(data.tail, columns)
      out = Png/row(data.head, row, prev, Bytes/repeat(0, bpp), Bytes/repeat(0, bpp))
      return Bytes/concat(out, Png/rows(rest, columns, bpp, out))

def Png/row(ftype: u24, row: List(u24), up: List(u24), left: List(u24), upleft: List(u24)) -> List(u24):
  match row:
    case List/Nil:
      return []
    case List/Cons:
      a = Inflate/at(left, 0)
      (b, up_rest) = Bytes/pop(up)
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
      return List/Cons(v, Png/row(ftype, row.tail, up_rest, left2, upleft2))

def Png/abs_diff(x: u24, y: u24) -> u24:
  if x > y:
    return x - y
  else:
    return y - x

def Png/paeth(a: u24, b: u24, c: u24) -> u24:
  pa = Png/abs_diff(b, c)
  pb = Png/abs_diff(a, c)
  pc = Png/abs_diff(a + b, c + c)
  if (pa <= pb) & (pa <= pc):
    return a
  elif pb <= pc:
    return b
  else:
    return c
