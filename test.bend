# test.bend
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

def t0(z):
  return Bytes/equal(Bytes/to_hex(S(z, "Bend!")), S(z, "42656e6421"))

def t1(z):
  return Bytes/equal(Bytes/from_hex(S(z, "42 65 6E 64 21")), S(z, "Bend!"))

def t2(z):
  return Bytes/equal(Bytes/to_base64(Lz(z, [])), S(z, ""))

def t3(z):
  return Bytes/equal(Bytes/from_base64(S(z, "")), Lz(z, []))

def t4(z):
  return Bytes/equal(Bytes/to_base64(Lz(z, [102])), S(z, "Zg=="))

def t5(z):
  return Bytes/equal(Bytes/from_base64(S(z, "Zg==")), Lz(z, [102]))

def t6(z):
  return Bytes/equal(Bytes/to_base64(Lz(z, [102, 111])), S(z, "Zm8="))

def t7(z):
  return Bytes/equal(Bytes/from_base64(S(z, "Zm8=")), Lz(z, [102, 111]))

def t8(z):
  return Bytes/equal(Bytes/to_base64(Lz(z, [102, 111, 111])), S(z, "Zm9v"))

def t9(z):
  return Bytes/equal(Bytes/from_base64(S(z, "Zm9v")), Lz(z, [102, 111, 111]))

def t10(z):
  return Bytes/equal(Bytes/to_base64(Lz(z, [102, 111, 111, 98])), S(z, "Zm9vYg=="))

def t11(z):
  return Bytes/equal(Bytes/from_base64(S(z, "Zm9vYg==")), Lz(z, [102, 111, 111, 98]))

def t12(z):
  return Bytes/equal(Bytes/to_base64(Lz(z, [102, 111, 111, 98, 97])), S(z, "Zm9vYmE="))

def t13(z):
  return Bytes/equal(Bytes/from_base64(S(z, "Zm9vYmE=")), Lz(z, [102, 111, 111, 98, 97]))

def t14(z):
  return Bytes/equal(Bytes/to_base64(Lz(z, [102, 111, 111, 98, 97, 114])), S(z, "Zm9vYmFy"))

def t15(z):
  return Bytes/equal(Bytes/from_base64(S(z, "Zm9vYmFy")), Lz(z, [102, 111, 111, 98, 97, 114]))

def t16(z):
  return Bytes/find(S(z, "abcabc"), S(z, "ca")) == 2

def t17(z):
  return Bytes/rfind(S(z, "abcabc"), S(z, "bc")) == 4

def t18(z):
  return Bytes/find(S(z, "abc"), S(z, "x")) == Bytes/NONE

def t19(z):
  return Bytes/equal(Bytes/from_u24(z + 9876543), S(z, "9876543"))

def t20(z):
  return t_parse_u24(S(z, "0042 x"))

def t21(z):
  return Bytes/equal(Bytes/from_io(Lz(z, [0xFFFF93, 0x41])), Lz(z, [0x93, 0x41]))

def t22(z):
  return Bytes/equal(Bytes/join(Bytes/sort(Lz(z, [[3], [1, 2], [1]]))), Lz(z, [1, 1, 2, 3]))

def t23(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 0)), H(z, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))

def t24(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 3)), H(z, "b39fad1a1075f64570b3226d339ea818f9c66ecd2f1c59fd8b9c5a32b54c513f"))

def t25(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 55)), H(z, "2900465fcb533e05a158fd2b3be0e5e3b03740d83060aa3580e0d98a96bf2384"))

def t26(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 56)), H(z, "31454ff48ef36af2f08fd511bdc37d9d5855ac23e992e5ff5445cb6b7674a674"))

def t27(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 63)), H(z, "5f6401b96532c36de4e65beec0409b69b1d181864c8009b7a04f43e5d56350d1"))

def t28(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 64)), H(z, "94eb5de4943613fd048dc93393ab06877405faa39c11f53e9386083339833e7e"))

def t29(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 119)), H(z, "b0dc41b1a384e2f1203f0351b38fbeaafceef577ce1191d5bfc25da39f721eae"))

def t30(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 1000)), H(z, "57799de80e3dd6e2ac4d40c41a150d1662f7f87d0d994776a2fdc37c39b0ea4e"))

def t31(z):
  return BigInt/cmp(BigInt/add(BI(z, "120c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438"), BI(z, "254c665d9dc9f81818e811892f902bd23f0824")), BI(z, "120c5c7fd0a6c8f0b6c2b0f1063eb6f5497bd6de102525bc5c")) == 1

def t32(z):
  return BigInt/cmp(BigInt/sub(BI(z, "120c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438"), BI(z, "254c665d9dc9f81818e811892f902bd23f0824")), BI(z, "120c5c7fd0a67e57ea07755d160e8525266977bdb880a7ac14")) == 1

def t33(z):
  return BigInt/cmp(BigInt/mul(BI(z, "120c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438"), BI(z, "254c665d9dc9f81818e811892f902bd23f0824")), BI(z, "02a12c417592609d35fa6ceb5bf6112aa13387f6132959ed6ca8388f8c66e94a998d7b05918f82b727db17e0")) == 1

def t34(z):
  return BigInt/cmp(BigInt/mod(BI(z, "02a12c417592609d35fa6ceb5bf6112aa13387f6132959ed6ca8388f8c66e94a998d7b05918f82b727db4819"), BI(z, "eb0d549b6f03675a1600a35a099950d836f675cc81e74ef5e8e25d940ed90475")), BI(z, "ba7081a5791b35ecd90d8b098d39cde2741a2b32be7b5c42504ee70f2c861ecc")) == 1

def t35(z):
  return BigInt/cmp(BigInt/modexp(BI(z, "120c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438"), H(z, "3d9c172411e20b8f"), BI(z, "eb0d549b6f03675a1600a35a099950d836f675cc81e74ef5e8e25d940ed90475")), BI(z, "067b21173e82a75e95e8630ae59ffab15977cf42c4d16c5ff1bef5f2457f43b8")) == 1

def t36(z):
  return Bytes/equal(BigInt/to_bytes(BI(z, "120c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438"), 30), H(z, "0000000000120c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438"))

def t37(z):
  return Bytes/equal(Der/len_bytes(z + 300), Lz(z, [0x82, 0x01, 0x2c]))

def t38(z):
  return Bytes/equal(Der/int(Lz(z, [0x00, 0x80])), Lz(z, [0x02, 0x02, 0x00, 0x80]))

def t39(z):
  return Bytes/equal(Der/int(Lz(z, [])), Lz(z, [0x02, 0x01, 0x00]))

def t40(z):
  return t_der_read(z)

def t41(z):
  return Bytes/equal(Pem/decode(S(z, "-----BEGIN X-----\nAQID\nBA==\n-----END X-----\n")), Lz(z, [1, 2, 3, 4]))

def t42(z):
  return Bytes/equal(Inflate/zlib(Lz(z, [120, 218, 203, 72, 205, 201, 201, 87, 200, 64, 34, 203, 243, 139, 114, 82, 0, 104, 125, 8, 197])), S(z, "hello hello hello world"))

def t43(z):
  return Bytes/equal(Inflate/zlib(Lz(z, [120, 218, 51, 84, 48, 80, 200, 79, 202, 82, 176, 177, 81, 208, 15, 169, 44, 72, 85, 208, 119, 78, 44, 73, 204, 201, 79, 87, 208, 15, 72, 76, 79, 45, 86, 48, 2, 42, 8, 82, 176, 179, 83, 72, 205, 75, 1, 41, 52, 28, 137, 26, 0, 110, 22, 84, 97])), S(z, "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj 1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj 1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj 1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj 1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj 1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj "))

def t44(z):
  return Bytes/equal(Inflate/zlib(Lz(z, [120, 1, 1, 13, 0, 242, 255, 115, 116, 111, 114, 101, 100, 32, 98, 108, 111, 99, 107, 33, 36, 94, 4, 222])), S(z, "stored block!"))

def t45(z):
  return Bytes/equal(Png/unfilter(Lz(z, [2, 1, 2, 2, 1, 1, 0, 5, 5]), 2, 1), Lz(z, [1, 2, 2, 3, 5, 5]))

def t46(z):
  return Bytes/equal(Png/unfilter(Lz(z, [1, 1, 2, 3]), 3, 1), Lz(z, [1, 3, 6]))

def t47(z):
  return Bytes/equal(Pdf/serialize(t_parse(S(z, "<< /A 1 0 R /B [1 2 (x\\)y)] /C <AB> /D -1.5 >>"))), S(z, "<</A 1 0 R /B [1 2 (x\\)y)] /C <AB> /D -1.5 >>"))

def t48(z):
  return Pdf/get_ref_num(t_parse(S(z, "<< /Root 12 0 R >>"))) == 12

def t49(z):
  return Bytes/equal(Pdf/serialize(Pdf/text_string(Lz(z, [65, 112, 114, 111, 98, 97, 99, 105, 195, 179, 110]))), S(z, "<FEFF004100700072006F006200610063006900F3006E>"))

def t50(z):
  return Pdf/startxref(S(z, "%PDF-1.4\nx\nstartxref\n1234\n%%EOF")) == 1234

def t51(z):
  return Bytes/len(Pdf/byterange_text(z + 1, 99999, 123)) == Pdf/BYTERANGE_WIDTH

def t52(z):
  return Bytes/len(Pdf/BYTERANGE_PLACEHOLDER) == Pdf/BYTERANGE_WIDTH

def t53(z):
  return Bytes/len(Rsa/emsa_pkcs1_v15(Bytes/repeat(z, 32), z + 256)) == 256

def t54(z):
  return t_attrs_sorted(z)

def check(name, ok, rest):
  if ok:
    return rest
  else:
    return List/Cons(name, rest)

def run(z):
  return (55, check("hex", t0(z), check("hex_decode", t1(z), check("base64_enc_0", t2(z), check("base64_dec_0", t3(z), check("base64_enc_1", t4(z), check("base64_dec_1", t5(z), check("base64_enc_2", t6(z), check("base64_dec_2", t7(z), check("base64_enc_3", t8(z), check("base64_dec_3", t9(z), check("base64_enc_4", t10(z), check("base64_dec_4", t11(z), check("base64_enc_5", t12(z), check("base64_dec_5", t13(z), check("base64_enc_6", t14(z), check("base64_dec_6", t15(z), check("find", t16(z), check("rfind", t17(z), check("find_none", t18(z), check("decimal", t19(z), check("parse_u24", t20(z), check("from_io", t21(z), check("sort", t22(z), check("sha256_0", t23(z), check("sha256_3", t24(z), check("sha256_55", t25(z), check("sha256_56", t26(z), check("sha256_63", t27(z), check("sha256_64", t28(z), check("sha256_119", t29(z), check("sha256_1000", t30(z), check("bigint_add", t31(z), check("bigint_sub", t32(z), check("bigint_mul", t33(z), check("bigint_mod", t34(z), check("bigint_modexp", t35(z), check("bigint_to_bytes", t36(z), check("der_len", t37(z), check("der_int_pad", t38(z), check("der_int_zero", t39(z), check("der_read", t40(z), check("pem", t41(z), check("inflate_fixed", t42(z), check("inflate_dynamic", t43(z), check("inflate_stored", t44(z), check("png_up", t45(z), check("png_sub", t46(z), check("pdf_roundtrip", t47(z), check("pdf_ref", t48(z), check("pdf_text_utf16", t49(z), check("pdf_startxref", t50(z), check("pdf_byterange_width", t51(z), check("pdf_byterange_placeholder", t52(z), check("emsa_len", t53(z), check("cms_attrs_sorted", t54(z), []))))))))))))))))))))))))))))))))))))))))))))))))))))))))

def main():
  return run(0)
