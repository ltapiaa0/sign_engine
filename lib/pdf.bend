from lib/bytes import *
from lib/text import *
from lib/inflate import *

type PdfObj:
  Raw { raw: List(u24) }
  Name { name: List(u24) }
  Arr { items: List(PdfObj) }
  Dict { entries: List((List(u24), PdfObj)) }
  Ref { num: u24, gen: u24 }

def Pdf/null() -> PdfObj:
  return PdfObj/Raw([110, 117, 108, 108])

def Pdf/is_null(o: PdfObj) -> u24:
  match o:
    case PdfObj/Raw:
      return Bytes/equal(o.raw, Bytes/from_string("null"))
    case _:
      return 0

def Pdf/num(n: u24) -> PdfObj:
  return PdfObj/Raw(Bytes/from_u24(n))

def Pdf/lit(s: String) -> PdfObj:
  return PdfObj/Raw(Bytes/from_string(s))

def Pdf/name(s: String) -> PdfObj:
  return PdfObj/Name(Bytes/from_string(s))

def Pdf/int(o: PdfObj) -> u24:
  match o:
    case PdfObj/Raw:
      (v, *, *) = Bytes/parse_u24(o.raw)
      return v
    case _:
      return 0

def Pdf/entries(o: PdfObj) -> List((List(u24), PdfObj)):
  match o:
    case PdfObj/Dict:
      return o.entries
    case _:
      return []

def Pdf/items(o: PdfObj) -> List(PdfObj):
  match o:
    case PdfObj/Arr:
      return o.items
    case _:
      return []

def Pdf/is_dict(o: PdfObj) -> u24:
  match o:
    case PdfObj/Dict:
      return 1
    case _:
      return 0

def Pdf/get(o: PdfObj, key: String) -> PdfObj:
  return Pdf/get.go(Pdf/entries(o), Bytes/from_string(key))

def Pdf/get.go(es: List((List(u24), PdfObj)), key: List(u24)) -> PdfObj:
  match es:
    case List/Nil:
      return Pdf/null
    case List/Cons:
      (k, v) = es.head
      if Bytes/equal(k, key):
        return v
      else:
        return Pdf/get.go(es.tail, key)

def Pdf/has(o: PdfObj, key: String) -> u24:
  return Pdf/is_null(Pdf/get(o, key)) == 0

def Pdf/set(o: PdfObj, key: String, value: PdfObj) -> PdfObj:
  return PdfObj/Dict(Pdf/set.go(Pdf/entries(o), Bytes/from_string(key), value))

def Pdf/set.go(es: List((List(u24), PdfObj)), key: List(u24), value: PdfObj) -> List((List(u24), PdfObj)):
  match es:
    case List/Nil:
      return [(key, value)]
    case List/Cons:
      (k, v) = es.head
      if Bytes/equal(k, key):
        return List/Cons((k, value), es.tail)
      else:
        return List/Cons((k, v), Pdf/set.go(es.tail, key, value))

def Pdf/name_is(o: PdfObj, s: String) -> u24:
  match o:
    case PdfObj/Name:
      return Bytes/equal(o.name, Bytes/from_string(s))
    case _:
      return 0

def Pdf/is_delim(c: u24) -> u24:
  return (c == '(') | (c == ')') | (c == '<') | (c == '>') | (c == '[') | (c == ']') | (c == '{') | (c == '}') | (c == '/') | (c == '%')

def Pdf/is_regular(c: u24) -> u24:
  return (Bytes/is_space(c) == 0) & (Pdf/is_delim(c) == 0)

def Pdf/skip(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      if Bytes/is_space(xs.head):
        return Pdf/skip(xs.tail)
      elif xs.head == '%':
        return Pdf/skip(Pdf/skip_line(xs.tail))
      else:
        return xs

def Pdf/skip_line(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      if (xs.head == 10) | (xs.head == 13):
        return xs.tail
      else:
        return Pdf/skip_line(xs.tail)

def Pdf/token(xs: List(u24)) -> (List(u24), List(u24)):
  match xs:
    case List/Nil:
      return ([], [])
    case List/Cons:
      if Pdf/is_regular(xs.head):
        (t, rest) = Pdf/token(xs.tail)
        return (List/Cons(xs.head, t), rest)
      else:
        return ([], xs)

def Pdf/all_digits(xs: List(u24)) -> u24:
  match xs:
    case List/Nil:
      return 1
    case List/Cons:
      if Bytes/is_digit(xs.head):
        return Pdf/all_digits(xs.tail)
      else:
        return 0

def Pdf/is_int_token(xs: List(u24)) -> u24:
  match xs:
    case List/Nil:
      return 0
    case List/Cons:
      return Pdf/all_digits(xs)

def Pdf/head(xs: List(u24)) -> u24:
  match xs:
    case List/Nil:
      return 0
    case List/Cons:
      return xs.head

def Pdf/parse(input: List(u24)) -> (PdfObj, List(u24)):
  match xs = Pdf/skip(input):
    case List/Nil:
      return (Pdf/null, [])
    case List/Cons:
      c = xs.head
      if c == '<':
        match t = xs.tail:
          case List/Nil:
            return (PdfObj/Raw([c]), [])
          case List/Cons:
            if t.head == '<':
              return Pdf/parse_dict(t.tail, [])
            else:
              return Pdf/hex_string(List/Cons(t.head, t.tail), [c])
      elif c == '(':
        return Pdf/lit_string(xs.tail, 1, [c])
      elif c == '[':
        return Pdf/parse_array(xs.tail, [])
      elif c == '/':
        (name, rest) = Pdf/token(xs.tail)
        return (PdfObj/Name(name), rest)
      else:
        (tok, rest) = Pdf/token(List/Cons(c, xs.tail))
        match tok:
          case List/Nil:
            return (PdfObj/Raw([c]), Bytes/drop(rest, 1))
          case List/Cons:
            if Pdf/is_int_token(tok):
              return Pdf/maybe_ref(tok, rest)
            else:
              return (PdfObj/Raw(tok), rest)

def Pdf/unread(tok: List(u24), rest: List(u24)) -> List(u24):
  return List/Cons(32, Bytes/concat(tok, List/Cons(32, rest)))

def Pdf/ref(num: List(u24), gen: List(u24)) -> PdfObj:
  (n, *, *) = Bytes/parse_u24(num)
  (g, *, *) = Bytes/parse_u24(gen)
  return PdfObj/Ref(n, g)

def Pdf/maybe_ref(tok: List(u24), rest: List(u24)) -> (PdfObj, List(u24)):
  (tok2, rest2) = Pdf/token(Pdf/skip(rest))
  if Pdf/is_int_token(tok2):
    match r = Pdf/skip(rest2):
      case List/Nil:
        return (PdfObj/Raw(tok), Pdf/unread(tok2, []))
      case List/Cons:
        if r.head == 'R':
          match t = r.tail:
            case List/Nil:
              return (Pdf/ref(tok, tok2), [])
            case List/Cons:
              if Pdf/is_regular(t.head):
                return (PdfObj/Raw(tok), Pdf/unread(tok2, List/Cons('R', List/Cons(t.head, t.tail))))
              else:
                return (Pdf/ref(tok, tok2), List/Cons(t.head, t.tail))
        else:
          return (PdfObj/Raw(tok), Pdf/unread(tok2, List/Cons(r.head, r.tail)))
  else:
    return (PdfObj/Raw(tok), Pdf/unread(tok2, rest2))

def Pdf/parse_dict(xs: List(u24), acc: List((List(u24), PdfObj))) -> (PdfObj, List(u24)):
  match s = Pdf/skip(xs):
    case List/Nil:
      return (PdfObj/Dict(Pdf/rev_entries(acc, [])), [])
    case List/Cons:
      if s.head == '>':
        match t = s.tail:
          case List/Nil:
            return (PdfObj/Dict(Pdf/rev_entries(acc, [])), [])
          case List/Cons:
            if t.head == '>':
              return (PdfObj/Dict(Pdf/rev_entries(acc, [])), t.tail)
            else:
              return Pdf/parse_dict(List/Cons(t.head, t.tail), acc)
      elif s.head == '/':
        (key, r1) = Pdf/token(s.tail)
        (val, r2) = Pdf/parse(r1)
        return Pdf/parse_dict(r2, List/Cons((key, val), acc))
      else:
        (*, r1) = Pdf/parse(List/Cons(s.head, s.tail))
        return Pdf/parse_dict(r1, acc)

def Pdf/rev_entries(xs: List((List(u24), PdfObj)), acc: List((List(u24), PdfObj))) -> List((List(u24), PdfObj)):
  match xs:
    case List/Nil:
      return acc
    case List/Cons:
      return Pdf/rev_entries(xs.tail, List/Cons(xs.head, acc))

def Pdf/parse_array(xs: List(u24), acc: List(PdfObj)) -> (PdfObj, List(u24)):
  s = Pdf/skip(xs)
  match s:
    case List/Nil:
      return (PdfObj/Arr(Pdf/rev_objs(acc, [])), [])
    case List/Cons:
      if s.head == ']':
        return (PdfObj/Arr(Pdf/rev_objs(acc, [])), s.tail)
      else:
        (v, r) = Pdf/parse(s)
        return Pdf/parse_array(r, List/Cons(v, acc))

def Pdf/rev_objs(xs: List(PdfObj), acc: List(PdfObj)) -> List(PdfObj):
  match xs:
    case List/Nil:
      return acc
    case List/Cons:
      return Pdf/rev_objs(xs.tail, List/Cons(xs.head, acc))

def Pdf/hex_string(xs: List(u24), acc: List(u24)) -> (PdfObj, List(u24)):
  match xs:
    case List/Nil:
      return (PdfObj/Raw(Bytes/reverse(acc)), [])
    case List/Cons:
      if xs.head == '>':
        return (PdfObj/Raw(Bytes/reverse(List/Cons('>', acc))), xs.tail)
      else:
        return Pdf/hex_string(xs.tail, List/Cons(xs.head, acc))

def Pdf/lit_string(xs: List(u24), depth: u24, acc: List(u24)) -> (PdfObj, List(u24)):
  match xs:
    case List/Nil:
      return (PdfObj/Raw(Bytes/reverse(acc)), [])
    case List/Cons:
      c = xs.head
      if c == 92:
        match t = xs.tail:
          case List/Nil:
            return (PdfObj/Raw(Bytes/reverse(List/Cons(c, acc))), [])
          case List/Cons:
            return Pdf/lit_string(t.tail, depth, List/Cons(t.head, List/Cons(c, acc)))
      elif c == '(':
        return Pdf/lit_string(xs.tail, depth + 1, List/Cons(c, acc))
      elif c == ')':
        if depth == 1:
          return (PdfObj/Raw(Bytes/reverse(List/Cons(c, acc))), xs.tail)
        else:
          return Pdf/lit_string(xs.tail, depth - 1, List/Cons(c, acc))
      else:
        return Pdf/lit_string(xs.tail, depth, List/Cons(c, acc))

def Pdf/serialize(o: PdfObj) -> List(u24):
  match o:
    case PdfObj/Raw:
      return o.raw
    case PdfObj/Name:
      return List/Cons('/', o.name)
    case PdfObj/Ref:
      return Bytes/join([Bytes/from_u24(o.num), [' '], Bytes/from_u24(o.gen), Bytes/from_string(" R")])
    case PdfObj/Arr:
      return List/Cons('[', Bytes/concat(Pdf/serialize_items(o.items), [']']))
    case PdfObj/Dict:
      return Bytes/concat(Bytes/from_string("<<"), Bytes/concat(Pdf/serialize_entries(o.entries), Bytes/from_string(">>")))

def Pdf/serialize_items(xs: List(PdfObj)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      match xs.tail:
        case List/Nil:
          return Pdf/serialize(xs.head)
        case List/Cons:
          return Bytes/concat(Pdf/serialize(xs.head), List/Cons(' ', Pdf/serialize_items(xs.tail)))

def Pdf/serialize_entries(es: List((List(u24), PdfObj))) -> List(u24):
  match es:
    case List/Nil:
      return []
    case List/Cons:
      (k, v) = es.head
      return List/Cons('/', Bytes/concat(k, List/Cons(' ', Bytes/concat(Pdf/serialize(v), List/Cons(' ', Pdf/serialize_entries(es.tail))))))

def Pdf/read_indirect(xs: List(u24)) -> (u24, PdfObj, List(u24)):
  (t1, r1) = Pdf/token(Pdf/skip(xs))
  (*, r2) = Pdf/token(Pdf/skip(r1))
  (*, r3) = Pdf/token(Pdf/skip(r2))
  (num, *, *) = Bytes/parse_u24(t1)
  (obj, r4) = Pdf/parse(r3)
  (is_stream, r5) = Bytes/strip_prefix(Pdf/skip(r4), Bytes/from_string("stream"))
  if is_stream:
    data = Pdf/stream_start(r5)
    len_obj = Pdf/get(obj, "Length")
    match len_obj:
      case PdfObj/Raw:
        return (num, obj, Bytes/take(data, Pdf/int(len_obj)))
      case _:
        return (num, obj, Pdf/until_endstream(data))
  else:
    return (num, obj, [])

def Pdf/stream_start(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      if xs.head == 13:
        match t = xs.tail:
          case List/Nil:
            return []
          case List/Cons:
            if t.head == 10:
              return t.tail
            else:
              return t
      elif xs.head == 10:
        return xs.tail
      else:
        return xs

def Pdf/until_endstream(xs: List(u24)) -> List(u24):
  n = Bytes/find(xs, Bytes/from_string("endstream"))
  data = Bytes/take(xs, n)
  return Bytes/reverse(Pdf/strip_eol(Bytes/reverse(data)))

def Pdf/strip_eol(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      if (xs.head == 10) | (xs.head == 13):
        return Pdf/strip_eol(xs.tail)
      else:
        return xs

def Pdf/decode_stream(dict: PdfObj, data: List(u24)) -> List(u24):
  if Pdf/is_flate(Pdf/get(dict, "Filter")):
    raw = Inflate/zlib(data)
    params = Pdf/first_params(Pdf/get(dict, "DecodeParms"))
    if Pdf/int(Pdf/get(params, "Predictor")) >= 10:
      cols = Pdf/int(Pdf/get(params, "Columns"))
      if cols == 0:
        return Png/unfilter(raw, 1, 1)
      else:
        return Png/unfilter(raw, cols, 1)
    else:
      return raw
  else:
    return data

def Pdf/is_flate(filter: PdfObj) -> u24:
  match filter:
    case PdfObj/Arr:
      return Pdf/name_is(Pdf/nth(filter.items, 0), "FlateDecode")
    case _:
      return Pdf/name_is(filter, "FlateDecode")

def Pdf/first_params(p: PdfObj) -> PdfObj:
  match p:
    case PdfObj/Arr:
      match p.items:
        case List/Nil:
          return Pdf/null
        case List/Cons:
          return p.items.head
    case _:
      return p

def Pdf/startxref(pdf: List(u24)) -> u24:
  pos = Bytes/rfind(pdf, Bytes/from_string("startxref"))
  if pos == Bytes/NONE:
    return Bytes/NONE
  else:
    (v, n, *) = Bytes/parse_u24(Pdf/skip(Bytes/drop(pdf, pos + 9)))
    if n == 0:
      return Bytes/NONE
    else:
      return v

def Pdf/xref_set(map, entries):
  match entries:
    case List/Nil:
      return map
    case List/Cons:
      (num, kind, a, b) = entries.head
      return Pdf/xref_set(Map/set(map, num, (kind, a, b)), entries.tail)

def Pdf/xref_get(map, num: u24) -> (u24, u24, u24):
  (m, *) = Map/get_check(map, num)
  match m:
    case Maybe/Some:
      return m.value
    case Maybe/None:
      return (0, 0, 0)

def Pdf/load_xref(pdf: List(u24), off: u24, depth: u24):
  if depth == 0:
    return (Map/empty, Pdf/null, 0, 0)
  else:
    (is_table, xs) = Bytes/strip_prefix(Pdf/skip(Bytes/drop(pdf, off)), Bytes/from_string("xref"))
    if is_table:
      (entries, rest) = Pdf/classic_sections(xs)
      (*, after) = Bytes/strip_prefix(Pdf/skip(rest), Bytes/from_string("trailer"))
      (trailer, *) = Pdf/parse(after)
      (base, base_max) = Pdf/load_prev(pdf, trailer, depth)
      top = Pdf/max(base_max, Pdf/max_num(entries, 0))
      if Pdf/has(trailer, "XRefStm"):
        (*, sdict, sdata) = Pdf/read_indirect(Bytes/drop(pdf, Pdf/int(Pdf/get(trailer, "XRefStm"))))
        stream = Pdf/stream_entries(sdict, sdata)
        hidden = Pdf/xref_set(base, Pdf/filter_kind(entries, 0, 1))
        merged = Pdf/xref_set(Pdf/xref_set(hidden, stream), Pdf/filter_kind(entries, 0, 0))
        return (merged, trailer, 0, Pdf/max(top, Pdf/max_num(stream, 0)))
      else:
        return (Pdf/xref_set(base, entries), trailer, 0, top)
    else:
      (*, sdict, sdata) = Pdf/read_indirect(xs)
      stream = Pdf/stream_entries(sdict, sdata)
      (base, base_max) = Pdf/load_prev(pdf, sdict, depth)
      return (Pdf/xref_set(base, stream), sdict, 1, Pdf/max(base_max, Pdf/max_num(stream, 0)))

def Pdf/load_prev(pdf: List(u24), trailer: PdfObj, depth: u24):
  if Pdf/has(trailer, "Prev"):
    (m, *, *, top) = Pdf/load_xref(pdf, Pdf/int(Pdf/get(trailer, "Prev")), depth - 1)
    return (m, top)
  else:
    return (Map/empty, 0)

def Pdf/filter_kind(entries, kind: u24, keep: u24):
  match entries:
    case List/Nil:
      return []
    case List/Cons:
      (num, k, a, b) = entries.head
      if (k == kind) == keep:
        return List/Cons((num, k, a, b), Pdf/filter_kind(entries.tail, kind, keep))
      else:
        return Pdf/filter_kind(entries.tail, kind, keep)

def Pdf/max_num(entries, acc: u24) -> u24:
  match entries:
    case List/Nil:
      return acc
    case List/Cons:
      (num, *, *, *) = entries.head
      return Pdf/max_num(entries.tail, Pdf/max(acc, num))

def Pdf/max(a: u24, b: u24) -> u24:
  if a > b:
    return a
  else:
    return b

def Pdf/classic_sections(xs: List(u24)):
  match s = Pdf/skip(xs):
    case List/Nil:
      return ([], [])
    case List/Cons:
      if Bytes/is_digit(s.head):
        (start, *, r1) = Bytes/parse_u24(List/Cons(s.head, s.tail))
        (count, *, r2) = Bytes/parse_u24(Pdf/skip(r1))
        (es, r3) = Pdf/classic_entries(r2, start, count)
        (more, r4) = Pdf/classic_sections(r3)
        return (List/concat(es, more), r4)
      else:
        return ([], List/Cons(s.head, s.tail))

def Pdf/classic_entries(xs: List(u24), num: u24, count: u24):
  if count == 0:
    return ([], xs)
  else:
    match s = Pdf/skip(xs):
      case List/Nil:
        return ([], [])
      case List/Cons:
        (off, *, r1) = Bytes/parse_u24(List/Cons(s.head, s.tail))
        (gen, *, r2) = Bytes/parse_u24(Pdf/skip(r1))
        (flag, r3) = Bytes/pop(Pdf/skip(r2))
        (rest, r4) = Pdf/classic_entries(r3, num + 1, count - 1)
        return (List/Cons((num, flag == 'n', off, gen), rest), r4)

def Pdf/stream_entries(dict: PdfObj, data: List(u24)):
  ws = Pdf/items(Pdf/get(dict, "W"))
  w1 = Pdf/int(Pdf/nth(ws, 0))
  w2 = Pdf/int(Pdf/nth(ws, 1))
  w3 = Pdf/int(Pdf/nth(ws, 2))
  index = Pdf/get(dict, "Index")
  if Pdf/is_null(index):
    idx = [0, Pdf/int(Pdf/get(dict, "Size"))]
  else:
    idx = Pdf/ints(Pdf/items(index))
  if w1 + w2 + w3 == 0:
    return []
  else:
    return Pdf/stream_ranges(Pdf/decode_stream(dict, data), idx, w1, w2, w3)

def Pdf/stream_ranges(data: List(u24), idx: List(u24), w1: u24, w2: u24, w3: u24):
  match idx:
    case List/Nil:
      return []
    case List/Cons:
      start = idx.head
      count = Pdf/head(idx.tail)
      (es, rest) = Pdf/stream_rows(data, start, count, w1, w2, w3)
      return List/concat(es, Pdf/stream_ranges(rest, Bytes/drop(idx, 2), w1, w2, w3))

def Pdf/stream_rows(data: List(u24), num: u24, count: u24, w1: u24, w2: u24, w3: u24):
  if count == 0:
    return ([], data)
  else:
    match data:
      case List/Nil:
        return ([], [])
      case List/Cons:
        (f1, d1) = Bytes/split(List/Cons(data.head, data.tail), w1)
        (f2, d2) = Bytes/split(d1, w2)
        (f3, d3) = Bytes/split(d2, w3)
        if w1 == 0:
          kind = 1
        else:
          kind = Bytes/to_uint_be(f1)
        (rest, r) = Pdf/stream_rows(d3, num + 1, count - 1, w1, w2, w3)
        return (List/Cons((num, kind, Bytes/to_uint_be(f2), Bytes/to_uint_be(f3)), rest), r)

def Pdf/nth(xs: List(PdfObj), i: u24) -> PdfObj:
  match xs:
    case List/Nil:
      return Pdf/null
    case List/Cons:
      if i == 0:
        return xs.head
      else:
        return Pdf/nth(xs.tail, i - 1)

def Pdf/ints(xs: List(PdfObj)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      return List/Cons(Pdf/int(xs.head), Pdf/ints(xs.tail))

def Pdf/get_obj(pdf: List(u24), xref, num: u24) -> PdfObj:
  (kind, a, b) = Pdf/xref_get(xref, num)
  if kind == 1:
    (found, obj, *) = Pdf/read_indirect(Bytes/drop(pdf, a))
    if found == num:
      return obj
    else:
      return Pdf/find_obj(pdf, num, b)
  elif kind == 2:
    return Pdf/objstm_get(pdf, xref, a, b)
  else:
    return Pdf/null

def Pdf/find_obj(pdf: List(u24), num: u24, gen: u24) -> PdfObj:
  pattern = Bytes/join([Bytes/from_u24(num), [32], Bytes/from_u24(gen), Bytes/from_string(" obj")])
  pos = Pdf/find_def(pdf, pattern)
  if pos == Bytes/NONE:
    return Pdf/null
  else:
    (*, obj, *) = Pdf/read_indirect(Bytes/drop(pdf, pos))
    return obj

def Pdf/find_def(pdf: List(u24), pattern: List(u24)) -> u24:
  return Pdf/find_def.go(pdf, Bytes/reverse(pattern), Bytes/len(pattern), [], 0, Bytes/NONE)

def Pdf/find_def.go(xs: List(u24), rpat: List(u24), m: u24, win: List(u24), i: u24, last: u24) -> u24:
  if (i >= m) & Bytes/starts_with(win, rpat) & Bytes/is_space(Bytes/at(win, m)):
    found = i - m
  else:
    found = last
  match xs:
    case List/Nil:
      return found
    case List/Cons:
      return Pdf/find_def.go(xs.tail, rpat, m, Bytes/take(List/Cons(xs.head, win), m + 1), i + 1, found)

def Pdf/objstm_get(pdf: List(u24), xref, stm: u24, idx: u24) -> PdfObj:
  (kind, off, *) = Pdf/xref_get(xref, stm)
  if kind == 1:
    (*, dict, raw) = Pdf/read_indirect(Bytes/drop(pdf, off))
    data = Pdf/decode_stream(dict, raw)
    first = Pdf/int(Pdf/get(dict, "First"))
    rel = Pdf/objstm_offset(data, idx)
    (obj, *) = Pdf/parse(Bytes/drop(data, first + rel))
    return obj
  else:
    return Pdf/null

def Pdf/objstm_offset(xs: List(u24), idx: u24) -> u24:
  (*, *, r1) = Bytes/parse_u24(Pdf/skip(xs))
  (off, *, r2) = Bytes/parse_u24(Pdf/skip(r1))
  if idx == 0:
    return off
  else:
    return Pdf/objstm_offset(r2, idx - 1)

def Pdf/resolve(pdf: List(u24), xref, o: PdfObj) -> PdfObj:
  match o:
    case PdfObj/Ref:
      return Pdf/get_obj(pdf, xref, o.num)
    case _:
      return o

def Pdf/first_page(pdf: List(u24), xref, node_ref: PdfObj, depth: u24):
  match node_ref:
    case PdfObj/Ref:
      node = Pdf/get_obj(pdf, xref, node_ref.num)
      if (depth > 0) & (Pdf/name_is(Pdf/get(node, "Type"), "Pages") | Pdf/has(node, "Kids")):
        kids = Pdf/items(Pdf/resolve(pdf, xref, Pdf/get(node, "Kids")))
        return Pdf/first_page(pdf, xref, Pdf/nth(kids, 0), depth - 1)
      else:
        return (node_ref.num, node_ref.gen, node)
    case _:
      return (0, 0, Pdf/null)

def Pdf/docmdp_p(pdf: List(u24), xref, root: PdfObj) -> u24:
  perms = Pdf/resolve(pdf, xref, Pdf/get(root, "Perms"))
  sig = Pdf/resolve(pdf, xref, Pdf/get(perms, "DocMDP"))
  if Pdf/is_dict(sig):
    return Pdf/docmdp_ref(pdf, xref, Pdf/items(Pdf/resolve(pdf, xref, Pdf/get(sig, "Reference"))))
  else:
    return 0

def Pdf/docmdp_ref(pdf: List(u24), xref, refs: List(PdfObj)) -> u24:
  match refs:
    case List/Nil:
      return 2
    case List/Cons:
      r = Pdf/resolve(pdf, xref, refs.head)
      if Pdf/name_is(Pdf/get(r, "TransformMethod"), "DocMDP"):
        p = Pdf/get(Pdf/resolve(pdf, xref, Pdf/get(r, "TransformParams")), "P")
        if Pdf/is_null(p):
          return 2
        else:
          return Pdf/int(p)
      else:
        return Pdf/docmdp_ref(pdf, xref, refs.tail)

type PdfInfo:
  New { len, startxref, xref, trailer, is_stream, size, root_num, root_gen, root, page_num, page_gen, page }

def Pdf/analyze(pdf: List(u24)):
  if Bytes/find(Bytes/take(pdf, 1024), Bytes/from_string("%PDF-")) == Bytes/NONE:
    return Result/Err("pdf: missing %PDF- header")
  else:
    sx = Pdf/startxref(pdf)
    if sx == Bytes/NONE:
      return Result/Err("pdf: startxref not found")
    else:
      (xref, trailer, is_stream, top) = Pdf/load_xref(pdf, sx, 64)
      if Pdf/has(trailer, "Encrypt"):
        return Result/Err("pdf: encrypted documents are not supported")
      else:
        root_ref = Pdf/get(trailer, "Root")
        match root_ref:
          case PdfObj/Ref:
            root = Pdf/get_obj(pdf, xref, root_ref.num)
            if Pdf/is_dict(root) == 0:
              return Result/Err("pdf: catalog (/Root) is not a dictionary")
            elif Pdf/docmdp_p(pdf, xref, root) == 1:
              return Result/Err("pdf: the document is certified and does not allow changes (DocMDP P=1)")
            else:
              (pn, pg, page) = Pdf/first_page(pdf, xref, Pdf/get(root, "Pages"), 32)
              if Pdf/is_dict(page):
                size = Pdf/max(Pdf/int(Pdf/get(trailer, "Size")), top + 1)
                return Result/Ok(PdfInfo/New(Bytes/len(pdf), sx, xref, trailer, is_stream, size, root_ref.num, root_ref.gen, root, pn, pg, page))
              else:
                return Result/Err("pdf: first page not found")
          case _:
            return Result/Err("pdf: trailer has no /Root")

def Pdf/text_string(utf8: List(u24)) -> PdfObj:
  hex = Bytes/to_hex_upper(Bytes/concat([0xFE, 0xFF], Text/utf16be_encode(Text/utf8_decode(utf8))))
  return PdfObj/Raw(List/Cons('<', Bytes/concat(hex, ['>'])))

def Pdf/ascii_string(xs: List(u24)) -> PdfObj:
  return PdfObj/Raw(List/Cons('(', Bytes/concat(Pdf/escape(xs), [')'])))

def Pdf/escape(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      c = xs.head
      if (c == '(') | (c == ')') | (c == 92):
        return List/Cons(92, List/Cons(c, Pdf/escape(xs.tail)))
      else:
        return List/Cons(c, Pdf/escape(xs.tail))

type SigFields:
  New { name, reason, location, contact, time }

def SigFields/new(name, reason, location, contact, time):
  return SigFields/New(name, reason, location, contact, time)

def Pdf/opt_text(d: PdfObj, key: String, v: List(u24)) -> PdfObj:
  match v:
    case List/Nil:
      return d
    case List/Cons:
      return Pdf/set(d, key, Pdf/text_string(v))

def Pdf/opt_date(d: PdfObj, t: List(u24)) -> PdfObj:
  match t:
    case List/Nil:
      return d
    case List/Cons:
      return Pdf/set(d, "M", Pdf/ascii_string(Bytes/join([Bytes/from_string("D:"), t, Bytes/from_string("Z")])))

def Pdf/obj_header(num: u24, gen: u24) -> List(u24):
  return Bytes/join([Bytes/from_u24(num), [' '], Bytes/from_u24(gen), Bytes/from_string(" obj\n")])

def Pdf/obj_footer() -> List(u24):
  return [10, 101, 110, 100, 111, 98, 106, 10]

def Pdf/indirect(num: u24, gen: u24, o: PdfObj) -> List(u24):
  return Bytes/join([Pdf/obj_header(num, gen), Pdf/serialize(o), Pdf/obj_footer])

def Pdf/BYTERANGE_WIDTH() -> u24:
  return 44

def Pdf/BYTERANGE_PLACEHOLDER() -> List(u24):
  return Bytes/from_string("[0 0 0 0                                   ]")

def Pdf/byterange_text(a: u24, b: u24, c: u24) -> List(u24):
  t = Bytes/join([Bytes/from_string("[0 "), Bytes/from_u24(a), [' '], Bytes/from_u24(b), [' '], Bytes/from_u24(c)])
  return Bytes/concat(Bytes/pad_right(t, Pdf/BYTERANGE_WIDTH - 1, ' '), [']'])

def Pdf/sig_dict_parts(f, byterange: List(u24)) -> (List(u24), List(u24)):
  open SigFields: f
  extra = Pdf/opt_text(Pdf/opt_text(Pdf/opt_text(Pdf/opt_text(PdfObj/Dict([]), "Name", f.name), "Reason", f.reason), "Location", f.location), "ContactInfo", f.contact)
  extra2 = Pdf/opt_date(extra, f.time)
  before = Bytes/join([
    Bytes/from_string("<</Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange "),
    byterange,
    Bytes/from_string(" "),
    Pdf/serialize_entries(Pdf/entries(extra2)),
    Bytes/from_string("/Contents ")
  ])
  return (before, Bytes/from_string(">>"))

def Pdf/append_to(pdf: List(u24), xref, arr: PdfObj, item: PdfObj) -> PdfObj:
  resolved = Pdf/resolve(pdf, xref, arr)
  return PdfObj/Arr(List/concat(Pdf/items(resolved), [item]))

def Pdf/updated_catalog(pdf: List(u24), info, widget: u24) -> PdfObj:
  open PdfInfo: info
  acro = Pdf/resolve(pdf, info.xref, Pdf/get(info.root, "AcroForm"))
  fields = Pdf/append_to(pdf, info.xref, Pdf/get(acro, "Fields"), PdfObj/Ref(widget, 0))
  if Pdf/is_dict(acro):
    acro2 = Pdf/set(Pdf/set(acro, "Fields", fields), "SigFlags", Pdf/lit("3"))
  else:
    acro2 = PdfObj/Dict([(Bytes/from_string("Fields"), fields), (Bytes/from_string("SigFlags"), Pdf/lit("3"))])
  return Pdf/set(info.root, "AcroForm", acro2)

def Pdf/updated_page(pdf: List(u24), info, widget: u24) -> PdfObj:
  open PdfInfo: info
  annots = Pdf/append_to(pdf, info.xref, Pdf/get(info.page, "Annots"), PdfObj/Ref(widget, 0))
  return Pdf/set(info.page, "Annots", annots)

def Pdf/copy_trailer_keys(trailer: PdfObj, d: PdfObj) -> PdfObj:
  info = Pdf/get(trailer, "Info")
  id = Pdf/get(trailer, "ID")
  if Pdf/is_null(info):
    d2 = d
  else:
    d2 = Pdf/set(d, "Info", info)
  if Pdf/is_null(id):
    return d2
  else:
    return Pdf/set(d2, "ID", id)

def Pdf/xref_table(objs: List((u24, u24, u24))) -> List(u24):
  match objs:
    case List/Nil:
      return []
    case List/Cons:
      (num, gen, off) = objs.head
      line = Bytes/join([Bytes/from_u24(num), Bytes/from_string(" 1\n"), Bytes/from_u24_padded(off, 10), [' '], Bytes/from_u24_padded(gen, 5), Bytes/from_string(" n\r\n")])
      return Bytes/concat(line, Pdf/xref_table(objs.tail))

def Pdf/xref_rows(objs: List((u24, u24, u24))) -> List(u24):
  match objs:
    case List/Nil:
      return []
    case List/Cons:
      (num, gen, off) = objs.head
      return List/Cons(1, List/Cons(0, Bytes/concat(Bytes/from_uint_be(off, 3), Bytes/concat(Bytes/from_uint_be(gen, 2), Pdf/xref_rows(objs.tail)))))

def Pdf/xref_index(objs: List((u24, u24, u24))) -> List(PdfObj):
  match objs:
    case List/Nil:
      return []
    case List/Cons:
      (num, *, *) = objs.head
      return List/Cons(Pdf/num(num), List/Cons(Pdf/lit("1"), Pdf/xref_index(objs.tail)))

def Pdf/build_update(pdf: List(u24), info, f, byterange: List(u24), sig_len: u24):
  open PdfInfo: info
  base = info.len
  sig_num = info.size
  widget_num = info.size + 1
  (sig_before, sig_after) = Pdf/sig_dict_parts(f, byterange)
  sig_head = Bytes/concat(Pdf/obj_header(sig_num, 0), sig_before)
  contents_len = 2 + 2 * sig_len
  sig_tail = Bytes/concat(sig_after, Pdf/obj_footer)
  off_sig = base + 1
  cs = off_sig + Bytes/len(sig_head)
  ce = cs + contents_len
  widget = PdfObj/Dict([
    (Bytes/from_string("Type"), Pdf/name("Annot")),
    (Bytes/from_string("Subtype"), Pdf/name("Widget")),
    (Bytes/from_string("FT"), Pdf/name("Sig")),
    (Bytes/from_string("T"), Pdf/ascii_string(Bytes/concat(Bytes/from_string("Signature"), Bytes/from_u24(sig_num)))),
    (Bytes/from_string("V"), PdfObj/Ref(sig_num, 0)),
    (Bytes/from_string("F"), Pdf/lit("132")),
    (Bytes/from_string("Rect"), PdfObj/Arr([Pdf/lit("0"), Pdf/lit("0"), Pdf/lit("0"), Pdf/lit("0")])),
    (Bytes/from_string("P"), PdfObj/Ref(info.page_num, info.page_gen))
  ])
  widget_bytes = Pdf/indirect(widget_num, 0, widget)
  off_widget = ce + Bytes/len(sig_tail)
  catalog_bytes = Pdf/indirect(info.root_num, info.root_gen, Pdf/updated_catalog(pdf, info, widget_num))
  off_catalog = off_widget + Bytes/len(widget_bytes)
  page_bytes = Pdf/indirect(info.page_num, info.page_gen, Pdf/updated_page(pdf, info, widget_num))
  off_page = off_catalog + Bytes/len(catalog_bytes)
  off_xref = off_page + Bytes/len(page_bytes)
  objs = Pdf/sort_objs([(info.root_num, info.root_gen, off_catalog), (info.page_num, info.page_gen, off_page), (sig_num, 0, off_sig), (widget_num, 0, off_widget)])
  root_ref = PdfObj/Ref(info.root_num, info.root_gen)
  if info.is_stream:
    xref_num = info.size + 2
    all = Pdf/sort_objs(List/Cons((xref_num, 0, off_xref), objs))
    rows = Pdf/xref_rows(all)
    d0 = PdfObj/Dict([
      (Bytes/from_string("Type"), Pdf/name("XRef")),
      (Bytes/from_string("Size"), Pdf/num(info.size + 3)),
      (Bytes/from_string("W"), PdfObj/Arr([Pdf/lit("1"), Pdf/lit("4"), Pdf/lit("2")])),
      (Bytes/from_string("Index"), PdfObj/Arr(Pdf/xref_index(all))),
      (Bytes/from_string("Root"), root_ref),
      (Bytes/from_string("Prev"), Pdf/num(info.startxref)),
      (Bytes/from_string("Length"), Pdf/num(Bytes/len(rows)))
    ])
    xd = Pdf/copy_trailer_keys(info.trailer, d0)
    xref_part = Bytes/join([Pdf/obj_header(xref_num, 0), Pdf/serialize(xd), Bytes/from_string("\nstream\n"), rows, Bytes/from_string("\nendstream\nendobj\n")])
  else:
    d0 = PdfObj/Dict([
      (Bytes/from_string("Size"), Pdf/num(info.size + 2)),
      (Bytes/from_string("Root"), root_ref),
      (Bytes/from_string("Prev"), Pdf/num(info.startxref))
    ])
    td = Pdf/copy_trailer_keys(info.trailer, d0)
    xref_part = Bytes/join([Bytes/from_string("xref\n"), Pdf/xref_table(objs), Bytes/from_string("trailer\n"), Pdf/serialize(td), Bytes/from_string("\n")])
  tail = Bytes/join([sig_tail, widget_bytes, catalog_bytes, page_bytes, xref_part, Bytes/from_string("startxref\n"), Bytes/from_u24(off_xref), Bytes/from_string("\n%%EOF\n")])
  return (List/Cons(10, sig_head), tail, cs, ce)

def Pdf/sort_objs(xs: List((u24, u24, u24))) -> List((u24, u24, u24)):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      return Pdf/insert_obj(xs.head, Pdf/sort_objs(xs.tail))

def Pdf/insert_obj(x: (u24, u24, u24), sorted: List((u24, u24, u24))) -> List((u24, u24, u24)):
  match sorted:
    case List/Nil:
      return [x]
    case List/Cons:
      (n1, *, *) = x
      (n2, *, *) = sorted.head
      if n1 > n2:
        return List/Cons(sorted.head, Pdf/insert_obj(x, sorted.tail))
      else:
        return List/Cons(x, sorted)

def Pdf/prepare(pdf: List(u24), info, f, sig_len: u24):
  (*, c, cs, ce) = Pdf/build_update(pdf, info, f, Pdf/BYTERANGE_PLACEHOLDER, sig_len)
  total = ce + Bytes/len(c)
  br = Pdf/byterange_text(cs, ce, total - ce)
  (a2, c2, *, *) = Pdf/build_update(pdf, info, f, br, sig_len)
  return (a2, c2, Bytes/concat(pdf, Bytes/concat(a2, c2)))

def Pdf/finish(pdf: List(u24), a: List(u24), c: List(u24), cms: List(u24), sig_len: u24):
  if Bytes/len(cms) > sig_len:
    return Result/Err("pdf: CMS signature does not fit in the reserved space")
  else:
    hex = Bytes/pad_right(Bytes/to_hex_upper(cms), 2 * sig_len, '0')
    return Result/Ok(Bytes/join([pdf, a, ['<'], hex, ['>'], c]))
