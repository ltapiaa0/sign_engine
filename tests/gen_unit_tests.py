"""Genera test.bend (pruebas unitarias de las librerías Bend).

Los valores esperados se calculan con Python (hashlib, zlib, base64, pow).
Uso:  python3 tests/gen_unit_tests.py && bend run-rs test.bend

Nota: cada prueba recibe un argumento `z` (siempre 0) y todas las
constantes se construyen a través de él. Así ninguna expresión queda
"cerrada": Bend extrae las expresiones cerradas como definiciones globales
y HVM aborta si debe duplicar una de ellas cuando usa funciones con DUPs
("attempt to clone a non-affine global reference").
"""
import base64
import hashlib
import os
import random
import zlib

random.seed(7)
tests = []


def T(name, expr):
    tests.append((name, expr))


def L(b):
    return "Lz(z, [" + ", ".join(str(x) for x in b) + "])"


def S(s):
    return 'S(z, "' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '")'


def HX(b):
    return f'H(z, "{b.hex()}")'


def BI(x):
    h = f"{x:x}"
    if len(h) % 2:
        h = "0" + h
    return f'BI(z, "{h}")'


# --- bytes ------------------------------------------------------------------
T("hex", f'Bytes/equal(Bytes/to_hex({S("Bend!")}), {S("42656e6421")})')
T("hex_decode", f'Bytes/equal(Bytes/from_hex({S("42 65 6E 64 21")}), {S("Bend!")})')
for s in [b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"]:
    enc = base64.b64encode(s).decode()
    T(f"base64_enc_{len(s)}", f"Bytes/equal(Bytes/to_base64({L(s)}), {S(enc)})")
    T(f"base64_dec_{len(s)}", f"Bytes/equal(Bytes/from_base64({S(enc)}), {L(s)})")
T("find", f'Bytes/find({S("abcabc")}, {S("ca")}) == 2')
T("rfind", f'Bytes/rfind({S("abcabc")}, {S("bc")}) == 4')
T("find_none", f'Bytes/find({S("abc")}, {S("x")}) == Bytes/NONE')
T("decimal", f'Bytes/equal(Bytes/from_u24(z + 9876543), {S("9876543")})')
T("parse_u24", f't_parse_u24({S("0042 x")})')
T("from_io", "Bytes/equal(Bytes/from_io(Lz(z, [0xFFFF93, 0x41])), Lz(z, [0x93, 0x41]))")
T("sort", "Bytes/equal(Bytes/join(Bytes/sort(Lz(z, [[3], [1, 2], [1]]))), Lz(z, [1, 1, 2, 3]))")

# --- sha256 -----------------------------------------------------------------
for n in [0, 3, 55, 56, 63, 64, 119, 1000]:
    data = bytes((i * 37 + 11) % 256 for i in range(n))
    T(f"sha256_{n}", f"Bytes/equal(Sha256/digest(t_pattern(z + {n})), {HX(hashlib.sha256(data).digest())})")

# --- bigint -----------------------------------------------------------------
a = random.getrandbits(200)
b = random.getrandbits(150)
n = random.getrandbits(256) | 1 | (1 << 255)
e = random.getrandbits(64) | 1
EQ = lambda expr, x: f"BigInt/cmp({expr}, {BI(x)}) == 1"  # noqa: E731
T("bigint_add", EQ(f"BigInt/add({BI(a)}, {BI(b)})", a + b))
T("bigint_sub", EQ(f"BigInt/sub({BI(a)}, {BI(b)})", a - b))
T("bigint_mul", EQ(f"BigInt/mul({BI(a)}, {BI(b)})", a * b))
T("bigint_mod", EQ(f"BigInt/mod({BI(a * b + 12345)}, {BI(n)})", (a * b + 12345) % n))
T("bigint_modexp", EQ(f'BigInt/modexp({BI(a)}, {HX(e.to_bytes(8, "big"))}, {BI(n)})', pow(a, e, n)))
T("bigint_to_bytes", f'Bytes/equal(BigInt/to_bytes({BI(a)}, 30), {HX(a.to_bytes(30, "big"))})')

# --- asn1 / pem ---------------------------------------------------------------
T("der_len", "Bytes/equal(Der/len_bytes(z + 300), Lz(z, [0x82, 0x01, 0x2c]))")
T("der_int_pad", "Bytes/equal(Der/int(Lz(z, [0x00, 0x80])), Lz(z, [0x02, 0x02, 0x00, 0x80]))")
T("der_int_zero", "Bytes/equal(Der/int(Lz(z, [])), Lz(z, [0x02, 0x01, 0x00]))")
T("der_read", "t_der_read(z)")
pem = "-----BEGIN X-----\nAQID\nBA==\n-----END X-----\n"
T("pem", f"Bytes/equal(Pem/decode({S(pem)}), Lz(z, [1, 2, 3, 4]))")

# --- inflate ------------------------------------------------------------------
text = b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj " * 6
for name, data, lvl in [("inflate_fixed", b"hello hello hello world", 9),
                        ("inflate_dynamic", text, 9),
                        ("inflate_stored", b"stored block!", 0)]:
    T(name, f"Bytes/equal(Inflate/zlib({L(zlib.compress(data, lvl))}), {S(data.decode())})")
T("png_up", "Bytes/equal(Png/unfilter(Lz(z, [2, 1, 2, 2, 1, 1, 0, 5, 5]), 2, 1), Lz(z, [1, 2, 2, 3, 5, 5]))")
T("png_sub", "Bytes/equal(Png/unfilter(Lz(z, [1, 1, 2, 3]), 3, 1), Lz(z, [1, 3, 6]))")

# --- pdf ----------------------------------------------------------------------
src = "<< /A 1 0 R /B [1 2 (x\\)y)] /C <AB> /D -1.5 >>"
T("pdf_roundtrip", f"Bytes/equal(Pdf/serialize(t_parse({S(src)})), {S('<</A 1 0 R /B [1 2 (x\\)y)] /C <AB> /D -1.5 >>')})")
T("pdf_ref", f'Pdf/get_ref_num(t_parse({S("<< /Root 12 0 R >>")})) == 12')
utf16 = "<FEFF" + "Aprobación".encode("utf-16-be").hex().upper() + ">"
T("pdf_text_utf16", f'Bytes/equal(Pdf/serialize(Pdf/text_string({L("Aprobación".encode())})), {S(utf16)})')
T("pdf_startxref", f'Pdf/startxref({S("%PDF-1.4" + chr(10) + "x" + chr(10) + "startxref" + chr(10) + "1234" + chr(10) + "%%EOF")}) == 1234')
T("pdf_byterange_width", "Bytes/len(Pdf/byterange_text(z + 1, 99999, 123)) == Pdf/BYTERANGE_WIDTH")
T("pdf_byterange_placeholder", "Bytes/len(Pdf/BYTERANGE_PLACEHOLDER) == Pdf/BYTERANGE_WIDTH")

# --- rsa / cms ----------------------------------------------------------------
T("emsa_len", "Bytes/len(Rsa/emsa_pkcs1_v15(Bytes/repeat(z, 32), z + 256)) == 256")
T("cms_attrs_sorted", "t_attrs_sorted(z)")

out = ['''# test.bend
# Pruebas unitarias de las librerías. Ejecutar con:  bend run-rs test.bend
# Resultado: (cantidad_de_pruebas, [nombres de las pruebas que fallaron]).
# ARCHIVO GENERADO por tests/gen_unit_tests.py: no editar a mano.

from lib/bytes import *
from lib/sha256 import *
from lib/bigint import *
from lib/rsa import *
from lib/asn1 import *
from lib/inflate import *
from lib/pdf import *
from lib/cms import *

def S(z, s):
  return Bytes/from_string(s)

def H(z, s):
  return Bytes/from_hex(Bytes/from_string(s))

def BI(z, s):
  return BigInt/from_bytes(H(z, s))

def Lz(z, xs):
  return xs

# Bytes de prueba: (i*37 + 11) mod 256
def t_pattern(n):
  return t_pattern.go(0, n)

def t_pattern.go(i, n):
  if i == n:
    return []
  else:
    return List/Cons((i * 37 + 11) % 256, t_pattern.go(i + 1, n))

def t_parse_u24(s):
  (v, n, rest) = Bytes/parse_u24(s)
  return (v == 42) & (n == 4) & Bytes/equal(rest, [32, 120])

def t_parse(s):
  (o, *) = Pdf/parse(s)
  return o

def Pdf/get_ref_num(o):
  match r = Pdf/get(o, "Root"):
    case PdfObj/Ref:
      return r.num
    case _:
      return 0

def t_der_read(z):
  (tag, content, raw, rest) = Der/read(Lz(z, [0x30, 0x03, 0x02, 0x01, 0x05, 0xFF]))
  (t2, c2, *) = Der/child(content, 0)
  return (tag == 0x30) & Bytes/equal(raw, Lz(z, [0x30, 0x03, 0x02, 0x01, 0x05])) & Bytes/equal(rest, Lz(z, [0xFF])) & (t2 == 0x02) & Bytes/equal(c2, Lz(z, [0x05]))

# Los atributos firmados deben quedar ordenados (DER SET OF).
def t_attrs_sorted(z):
  attrs = Cms/signed_attrs(Bytes/repeat(z, 32), Bytes/repeat(z + 1, 10))
  (*, content, *, *) = Der/read(Cms/to_be_signed(attrs))
  (*, *, r0) = Der/child(content, 0)
  (*, *, r1) = Der/child(content, 1)
  (*, *, r2) = Der/child(content, 2)
  return (Bytes/compare(r0, r1) == 0) & (Bytes/compare(r1, r2) == 0)
''']
for i, (name, expr) in enumerate(tests):
    out.append(f"def t{i}(z):\n  return {expr}\n")
out.append("def check(name, ok, rest):\n  if ok:\n    return rest\n  else:\n    return List/Cons(name, rest)\n")
chain = "[]"
for i, (name, _) in reversed(list(enumerate(tests))):
    chain = f'check("{name}", t{i}(z), {chain})'
out.append(f"def run(z):\n  return ({len(tests)}, {chain})\n")
out.append("def main():\n  return run(0)\n")

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(root, "test.bend"), "w") as f:
    f.write("\n".join(out))
print(f"test.bend: {len(tests)} pruebas")
