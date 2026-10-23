# lib/pdf.bend
# Lectura de la estructura de un PDF (ISO 32000) y escritura de una
# actualización incremental con un campo de firma.
#
# Soporta:
#   - tablas xref clásicas, xref streams (PDF 1.5+) y archivos híbridos
#   - object streams comprimidos (/Type /ObjStm) con FlateDecode
#   - cadenas de actualizaciones previas (/Prev), incluso PDFs ya firmados
# No soporta: PDFs cifrados, archivos de más de 16 MiB (límite de u24).

from lib/bytes import *
from lib/inflate import *

# ---------------------------------------------------------------------------
# Modelo de objetos
# ---------------------------------------------------------------------------

# Los números, cadenas y palabras clave se conservan como texto original
# (Raw) para reescribirlos exactamente igual.
type PdfObj:
  Raw { raw: List(u24) }
  Name { name: List(u24) }
  Arr { items: List(PdfObj) }
  Dict { entries: List((List(u24), PdfObj)) }
  Ref { num: u24, gen: u24 }

# Literal puro ("null" en ASCII): las constantes globales que se duplican
# no deben contener llamadas, o HVM no puede clonarlas.
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

# Número literal para constantes: `Pdf/num(3)` sería una expresión cerrada
# con llamadas a funciones, que HVM no puede duplicar de forma segura.
def Pdf/lit(s: String) -> PdfObj:
  return PdfObj/Raw(Bytes/from_string(s))

def Pdf/name(s: String) -> PdfObj:
  return PdfObj/Name(Bytes/from_string(s))

# Valor entero de un objeto numérico (0 si no lo es).
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

# Busca una clave en un diccionario (null si no existe).
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

# Asigna una clave (reemplaza si existe, agrega al final si no).
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

# ---------------------------------------------------------------------------
# Léxico
# ---------------------------------------------------------------------------

def Pdf/is_delim(c: u24) -> u24:
  return (c == '(') | (c == ')') | (c == '<') | (c == '>') | (c == '[') | (c == ']') | (c == '{') | (c == '}') | (c == '/') | (c == '%')

def Pdf/is_regular(c: u24) -> u24:
  return (Bytes/is_space(c) == 0) & (Pdf/is_delim(c) == 0)

# Salta espacios y comentarios.
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

# Toma caracteres regulares: (token, resto).
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

# ---------------------------------------------------------------------------
# Parser de objetos
# ---------------------------------------------------------------------------

# Lee un objeto PDF. Retorna (objeto, resto).
def Pdf/parse(input: List(u24)) -> (PdfObj, List(u24)):
  xs = Pdf/skip(input)
  match xs:
    case List/Nil:
      return (Pdf/null, [])
    case List/Cons:
      c = xs.head
      if c == '<':
        if Pdf/head(xs.tail) == '<':
          return Pdf/parse_dict(Bytes/drop(xs, 2), [])
        else:
          return Pdf/hex_string(xs.tail, ['<'])
      elif c == '(':
        return Pdf/lit_string(xs.tail, 1, ['('])
      elif c == '[':
        return Pdf/parse_array(xs.tail, [])
      elif c == '/':
        (name, rest) = Pdf/token(xs.tail)
        return (PdfObj/Name(name), rest)
      else:
        (tok, rest) = Pdf/token(xs)
        match tok:
          case List/Nil:
            # Delimitador inesperado: se consume para no ciclar.
            return (PdfObj/Raw([c]), xs.tail)
          case List/Cons:
            if Pdf/is_int_token(tok):
              return Pdf/maybe_ref(tok, rest)
            else:
              return (PdfObj/Raw(tok), rest)

# "n g R" -> referencia; si no, sólo el número.
def Pdf/maybe_ref(tok: List(u24), rest: List(u24)) -> (PdfObj, List(u24)):
  (tok2, rest2) = Pdf/token(Pdf/skip(rest))
  if Pdf/is_int_token(tok2):
    r = Pdf/skip(rest2)
    match r:
      case List/Nil:
        return (PdfObj/Raw(tok), rest)
      case List/Cons:
        if (r.head == 'R') & (Pdf/is_regular(Pdf/head(r.tail)) == 0):
          (n, *, *) = Bytes/parse_u24(tok)
          (g, *, *) = Bytes/parse_u24(tok2)
          return (PdfObj/Ref(n, g), r.tail)
        else:
          return (PdfObj/Raw(tok), rest)
  else:
    return (PdfObj/Raw(tok), rest)

def Pdf/parse_dict(xs: List(u24), acc: List((List(u24), PdfObj))) -> (PdfObj, List(u24)):
  s = Pdf/skip(xs)
  match s:
    case List/Nil:
      return (PdfObj/Dict(Pdf/rev_entries(acc, [])), [])
    case List/Cons:
      if (s.head == '>') & (Pdf/head(s.tail) == '>'):
        return (PdfObj/Dict(Pdf/rev_entries(acc, [])), Bytes/drop(s, 2))
      elif s.head == '/':
        (key, r1) = Pdf/token(s.tail)
        (val, r2) = Pdf/parse(r1)
        return Pdf/parse_dict(r2, List/Cons((key, val), acc))
      else:
        (*, r1) = Pdf/parse(s)
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

# Cadena hexadecimal <...>; acc invertido.
def Pdf/hex_string(xs: List(u24), acc: List(u24)) -> (PdfObj, List(u24)):
  match xs:
    case List/Nil:
      return (PdfObj/Raw(Bytes/reverse(acc)), [])
    case List/Cons:
      if xs.head == '>':
        return (PdfObj/Raw(Bytes/reverse(List/Cons('>', acc))), xs.tail)
      else:
        return Pdf/hex_string(xs.tail, List/Cons(xs.head, acc))

# Cadena literal (...) con paréntesis anidados y escapes; acc invertido.
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

# ---------------------------------------------------------------------------
# Serialización
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Lectura de objetos indirectos
# ---------------------------------------------------------------------------

# Lee "n g obj <objeto> [stream ... endstream]" en `xs`.
# Retorna (objeto, datos_del_stream).
def Pdf/read_indirect(xs: List(u24)) -> (PdfObj, List(u24)):
  (*, r1) = Pdf/token(Pdf/skip(xs))
  (*, r2) = Pdf/token(Pdf/skip(r1))
  (*, r3) = Pdf/token(Pdf/skip(r2))
  (obj, r4) = Pdf/parse(r3)
  r5 = Pdf/skip(r4)
  if Bytes/starts_with(r5, Bytes/from_string("stream")):
    data = Pdf/stream_start(Bytes/drop(r5, 6))
    len_obj = Pdf/get(obj, "Length")
    match len_obj:
      case PdfObj/Raw:
        return (obj, Bytes/take(data, Pdf/int(len_obj)))
      case _:
        return (obj, Pdf/until_endstream(data))
  else:
    return (obj, [])

# Tras la palabra "stream" viene CRLF o LF.
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

# Decodifica un stream (sólo FlateDecode, opcionalmente con predictor PNG).
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

# 1 si el filtro (nombre o arreglo de un elemento) es /FlateDecode.
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

# ---------------------------------------------------------------------------
# Tabla de referencias cruzadas (xref)
# ---------------------------------------------------------------------------
# El mapa xref asocia número de objeto -> (tipo, a, b):
#   tipo 1: objeto en el offset a (generación b)
#   tipo 2: objeto comprimido en el object stream a, índice b
#   tipo 0: libre

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

# Carga la sección xref en `off` y todas las anteriores (/Prev).
# Retorna (mapa, trailer, es_xref_stream).
def Pdf/load_xref(pdf: List(u24), off: u24, depth: u24):
  if depth == 0:
    return (Map/empty, Pdf/null, 0)
  else:
    xs = Pdf/skip(Bytes/drop(pdf, off))
    if Bytes/starts_with(xs, Bytes/from_string("xref")):
      (entries, rest) = Pdf/classic_sections(Bytes/drop(xs, 4))
      (trailer, *) = Pdf/parse(Bytes/drop(Pdf/skip(rest), 7))
      base = Pdf/load_prev(pdf, trailer, depth)
      if Pdf/has(trailer, "XRefStm"):
        (sdict, sdata) = Pdf/read_indirect(Bytes/drop(pdf, Pdf/int(Pdf/get(trailer, "XRefStm"))))
        base2 = Pdf/xref_set(base, Pdf/stream_entries(sdict, sdata))
        return (Pdf/xref_set(base2, entries), trailer, 0)
      else:
        return (Pdf/xref_set(base, entries), trailer, 0)
    else:
      (sdict, sdata) = Pdf/read_indirect(xs)
      base = Pdf/load_prev(pdf, sdict, depth)
      return (Pdf/xref_set(base, Pdf/stream_entries(sdict, sdata)), sdict, 1)

def Pdf/load_prev(pdf: List(u24), trailer: PdfObj, depth: u24):
  if Pdf/has(trailer, "Prev"):
    (m, *, *) = Pdf/load_xref(pdf, Pdf/int(Pdf/get(trailer, "Prev")), depth - 1)
    return m
  else:
    return Map/empty

# Subsecciones "inicio cantidad" seguidas de entradas "offset gen n|f".
def Pdf/classic_sections(xs: List(u24)):
  s = Pdf/skip(xs)
  if Bytes/is_digit(Pdf/head(s)):
    (start, *, r1) = Bytes/parse_u24(s)
    (count, *, r2) = Bytes/parse_u24(Pdf/skip(r1))
    (es, r3) = Pdf/classic_entries(r2, start, count)
    (more, r4) = Pdf/classic_sections(r3)
    return (List/concat(es, more), r4)
  else:
    return ([], s)

def Pdf/classic_entries(xs: List(u24), num: u24, count: u24):
  if count == 0:
    return ([], xs)
  else:
    (off, *, r1) = Bytes/parse_u24(Pdf/skip(xs))
    (gen, *, r2) = Bytes/parse_u24(Pdf/skip(r1))
    r3 = Pdf/skip(r2)
    if Pdf/head(r3) == 'n':
      kind = 1
    else:
      kind = 0
    (rest, r4) = Pdf/classic_entries(Bytes/drop(r3, 1), num + 1, count - 1)
    return (List/Cons((num, kind, off, gen), rest), r4)

# Entradas de un xref stream.
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
    if w1 == 0:
      kind = 1
    else:
      kind = Bytes/to_uint_be(Bytes/take(data, w1))
    d1 = Bytes/drop(data, w1)
    a = Bytes/to_uint_be(Bytes/take(d1, w2))
    d2 = Bytes/drop(d1, w2)
    b = Bytes/to_uint_be(Bytes/take(d2, w3))
    (rest, r) = Pdf/stream_rows(Bytes/drop(d2, w3), num + 1, count - 1, w1, w2, w3)
    return (List/Cons((num, kind, a, b), rest), r)

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

# ---------------------------------------------------------------------------
# Acceso a objetos por número
# ---------------------------------------------------------------------------

def Pdf/get_obj(pdf: List(u24), xref, num: u24) -> PdfObj:
  (kind, a, b) = Pdf/xref_get(xref, num)
  if kind == 1:
    (obj, *) = Pdf/read_indirect(Bytes/drop(pdf, a))
    return obj
  elif kind == 2:
    return Pdf/objstm_get(pdf, xref, a, b)
  else:
    return Pdf/null

# Objeto `idx` dentro del object stream `stm`.
def Pdf/objstm_get(pdf: List(u24), xref, stm: u24, idx: u24) -> PdfObj:
  (kind, off, *) = Pdf/xref_get(xref, stm)
  if kind == 1:
    (dict, raw) = Pdf/read_indirect(Bytes/drop(pdf, off))
    data = Pdf/decode_stream(dict, raw)
    first = Pdf/int(Pdf/get(dict, "First"))
    rel = Pdf/objstm_offset(data, idx)
    (obj, *) = Pdf/parse(Bytes/drop(data, first + rel))
    return obj
  else:
    return Pdf/null

# El encabezado del object stream son pares "num offset".
def Pdf/objstm_offset(xs: List(u24), idx: u24) -> u24:
  (*, *, r1) = Bytes/parse_u24(Pdf/skip(xs))
  (off, *, r2) = Bytes/parse_u24(Pdf/skip(r1))
  if idx == 0:
    return off
  else:
    return Pdf/objstm_offset(r2, idx - 1)

# Resuelve una referencia (un nivel).
def Pdf/resolve(pdf: List(u24), xref, o: PdfObj) -> PdfObj:
  match o:
    case PdfObj/Ref:
      return Pdf/get_obj(pdf, xref, o.num)
    case _:
      return o

# Primera página del árbol /Pages. Retorna (num, gen, dict).
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

# ---------------------------------------------------------------------------
# Análisis del documento
# ---------------------------------------------------------------------------

type PdfInfo:
  New { len, startxref, xref, trailer, is_stream, size, root_num, root_gen, root, page_num, page_gen, page }

# Lee la estructura necesaria para agregar una firma.
# Retorna Result(PdfInfo, String).
def Pdf/analyze(pdf: List(u24)):
  if Bytes/find(Bytes/take(pdf, 1024), Bytes/from_string("%PDF-")) == Bytes/NONE:
    return Result/Err("pdf: falta el encabezado %PDF-")
  else:
    sx = Pdf/startxref(pdf)
    if sx == Bytes/NONE:
      return Result/Err("pdf: no se encontró startxref")
    else:
      (xref, trailer, is_stream) = Pdf/load_xref(pdf, sx, 64)
      if Pdf/has(trailer, "Encrypt"):
        return Result/Err("pdf: los documentos cifrados no están soportados")
      else:
        root_ref = Pdf/get(trailer, "Root")
        match root_ref:
          case PdfObj/Ref:
            root = Pdf/get_obj(pdf, xref, root_ref.num)
            if Pdf/is_dict(root):
              (pn, pg, page) = Pdf/first_page(pdf, xref, Pdf/get(root, "Pages"), 32)
              if Pdf/is_dict(page):
                return Result/Ok(PdfInfo/New(Bytes/len(pdf), sx, xref, trailer, is_stream, Pdf/int(Pdf/get(trailer, "Size")), root_ref.num, root_ref.gen, root, pn, pg, page))
              else:
                return Result/Err("pdf: no se encontró la primera página")
            else:
              return Result/Err("pdf: el catálogo (/Root) no es un diccionario")
          case _:
            return Result/Err("pdf: el trailer no tiene /Root")

# ---------------------------------------------------------------------------
# Texto
# ---------------------------------------------------------------------------

# Decodifica UTF-8 a puntos de código.
def Pdf/utf8_decode(xs: List(u24)) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      c = xs.head
      if c < 0xC0:
        # ASCII (o byte inválido, interpretado como Latin-1)
        return List/Cons(c, Pdf/utf8_decode(xs.tail))
      elif c < 0xE0:
        b1 = Pdf/head(xs.tail)
        return List/Cons(((c & 0x1F) << 6) | (b1 & 0x3F), Pdf/utf8_decode(Bytes/drop(xs, 2)))
      elif c < 0xF0:
        b1 = Bytes/at(xs, 1)
        b2 = Bytes/at(xs, 2)
        return List/Cons(((c & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F), Pdf/utf8_decode(Bytes/drop(xs, 3)))
      else:
        b1 = Bytes/at(xs, 1)
        b2 = Bytes/at(xs, 2)
        b3 = Bytes/at(xs, 3)
        return List/Cons(((c & 0x07) << 18) | ((b1 & 0x3F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F), Pdf/utf8_decode(Bytes/drop(xs, 4)))

# Puntos de código -> UTF-16BE (con pares sustitutos).
def Pdf/utf16be(cps: List(u24)) -> List(u24):
  match cps:
    case List/Nil:
      return []
    case List/Cons:
      c = cps.head
      if c < 0x10000:
        return List/Cons(c >> 8, List/Cons(c & 0xFF, Pdf/utf16be(cps.tail)))
      else:
        v = c - 0x10000
        hi = 0xD800 | (v >> 10)
        lo = 0xDC00 | (v & 0x3FF)
        return List/Cons(hi >> 8, List/Cons(hi & 0xFF, List/Cons(lo >> 8, List/Cons(lo & 0xFF, Pdf/utf16be(cps.tail)))))

# Cadena de texto PDF a partir de UTF-8: <FEFF...> (UTF-16BE en hexadecimal).
def Pdf/text_string(utf8: List(u24)) -> PdfObj:
  hex = Bytes/to_hex_upper(Bytes/concat([0xFE, 0xFF], Pdf/utf16be(Pdf/utf8_decode(utf8))))
  return PdfObj/Raw(List/Cons('<', Bytes/concat(hex, ['>'])))

# Cadena literal ASCII simple, escapando paréntesis y barra invertida.
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

# ---------------------------------------------------------------------------
# Actualización incremental con campo de firma
# ---------------------------------------------------------------------------

type SigFields:
  New { name, reason, location, contact, time }

# Constructor exportable de SigFields (todos los campos en bytes UTF-8;
# `time` en formato YYYYMMDDHHmmSS UTC; los vacíos se omiten).
def SigFields/new(name, reason, location, contact, time):
  return SigFields/New(name, reason, location, contact, time)

def Pdf/opt_text(d: PdfObj, key: String, v: List(u24)) -> PdfObj:
  match v:
    case List/Nil:
      return d
    case List/Cons:
      return Pdf/set(d, key, Pdf/text_string(v))

# /M (D:YYYYMMDDHHmmSSZ) si se indicó la hora de firma.
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

# Ancho fijo del texto de /ByteRange, para poder calcularlo después.
def Pdf/BYTERANGE_WIDTH() -> u24:
  return 44

def Pdf/BYTERANGE_PLACEHOLDER() -> List(u24):
  return Bytes/from_string("[0 0 0 0                                   ]")

def Pdf/byterange_text(a: u24, b: u24, c: u24) -> List(u24):
  t = Bytes/join([Bytes/from_string("[0 "), Bytes/from_u24(a), [' '], Bytes/from_u24(b), [' '], Bytes/from_u24(c)])
  return Bytes/concat(Bytes/pad_right(t, Pdf/BYTERANGE_WIDTH - 1, ' '), [']'])

# Diccionario de firma dividido en (antes de /Contents, después de /Contents).
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

# Agrega `item` a un arreglo que puede ser directo, indirecto o inexistente.
def Pdf/append_to(pdf: List(u24), xref, arr: PdfObj, item: PdfObj) -> PdfObj:
  resolved = Pdf/resolve(pdf, xref, arr)
  return PdfObj/Arr(List/concat(Pdf/items(resolved), [item]))

# Catálogo con /AcroForm que incluye el nuevo campo y /SigFlags 3.
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

# Copia /Info e /ID del trailer original, si existen.
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

# Sección xref clásica para la lista de (num, gen, offset).
def Pdf/xref_table(objs: List((u24, u24, u24))) -> List(u24):
  match objs:
    case List/Nil:
      return []
    case List/Cons:
      (num, gen, off) = objs.head
      line = Bytes/join([Bytes/from_u24(num), Bytes/from_string(" 1\n"), Bytes/from_u24_padded(off, 10), [' '], Bytes/from_u24_padded(gen, 5), Bytes/from_string(" n\r\n")])
      return Bytes/concat(line, Pdf/xref_table(objs.tail))

# Filas binarias del xref stream con /W [1 4 2].
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

# Construye la actualización incremental. Retorna (A, C, cs, ce) donde
# el archivo final es  pdf ++ A ++ "<" hex ">" ++ C  y [cs, ce) es la
# posición absoluta del valor de /Contents incluyendo los delimitadores.
def Pdf/build_update(pdf: List(u24), info, f, byterange: List(u24), sig_len: u24):
  open PdfInfo: info
  base = info.len
  sig_num = info.size
  widget_num = info.size + 1
  (sig_before, sig_after) = Pdf/sig_dict_parts(f, byterange)
  sig_head = Bytes/concat(Pdf/obj_header(sig_num, 0), sig_before)
  contents_len = 2 + 2 * sig_len
  sig_tail = Bytes/concat(sig_after, Pdf/obj_footer)
  # offsets
  off_sig = base + 1
  cs = off_sig + Bytes/len(sig_head)
  ce = cs + contents_len
  widget = PdfObj/Dict([
    (Bytes/from_string("Type"), Pdf/name("Annot")),
    (Bytes/from_string("Subtype"), Pdf/name("Widget")),
    (Bytes/from_string("FT"), Pdf/name("Sig")),
    (Bytes/from_string("T"), Pdf/ascii_string(Bytes/concat(Bytes/from_string("Firma"), Bytes/from_u24(sig_num)))),
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

# Ordena (num, gen, off) por número de objeto (inserción).
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

# Prepara el documento para firmar.
# Retorna (A, C, digest_input) donde digest_input son los bytes cubiertos
# por /ByteRange (todo el archivo excepto el valor de /Contents).
def Pdf/prepare(pdf: List(u24), info, f, sig_len: u24):
  # Primera pasada con /ByteRange provisional (mismo ancho) para medir.
  (*, c, cs, ce) = Pdf/build_update(pdf, info, f, Pdf/BYTERANGE_PLACEHOLDER, sig_len)
  total = ce + Bytes/len(c)
  br = Pdf/byterange_text(cs, ce, total - ce)
  (a2, c2, *, *) = Pdf/build_update(pdf, info, f, br, sig_len)
  return (a2, c2, Bytes/concat(pdf, Bytes/concat(a2, c2)))

# Inserta el CMS (en hexadecimal, relleno con ceros) en /Contents.
def Pdf/finish(pdf: List(u24), a: List(u24), c: List(u24), cms: List(u24), sig_len: u24):
  if Bytes/len(cms) > sig_len:
    return Result/Err("pdf: la firma CMS no cabe en el espacio reservado")
  else:
    hex = Bytes/pad_right(Bytes/to_hex_upper(cms), 2 * sig_len, '0')
    return Result/Ok(Bytes/join([pdf, a, ['<'], hex, ['>'], c]))
