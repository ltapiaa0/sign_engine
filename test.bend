from lib/bytes import *
from lib/sha256 import *
from lib/bigint import *
from lib/rsa import *
from lib/asn1 import *
from lib/inflate import *
from lib/pdf import *
from lib/cms import *
from lib/text import *
from lib/x509 import *

def S(z, s):
  return Bytes/from_string(s)

def H(z, s):
  return Bytes/from_hex(Bytes/from_string(s))

def BI(z, s):
  return BigInt/from_bytes(H(z, s))

def Lz(z, xs):
  return xs

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

def t_prefix(full, part):
  return Bytes/starts_with(full, part) & (Bytes/len(part) > 0)

def t_split(s):
  (a, b) = Bytes/split(s, 2)
  return Bytes/equal(a, [97, 98]) & Bytes/equal(b, [99, 100, 101, 102])

def t_strip_prefix(yes, no):
  (ok1, r1) = Bytes/strip_prefix(yes, [115, 116, 114, 101, 97, 109])
  (ok2, r2) = Bytes/strip_prefix(no, [115, 116, 114, 101, 97, 109])
  return ok1 & Bytes/equal(r1, [88]) & (ok2 == 0) & Bytes/equal(r2, [115, 116, 114, 88, 97, 109])

def t_pem(s):
  match blocks = Pem/decode_all(s):
    case List/Nil:
      return 0
    case List/Cons:
      (label, der) = blocks.head
      return Bytes/equal(label, [88]) & Bytes/equal(der, [1, 2, 3, 4])

def t_key_block(s):
  match found = X509/first_key(Pem/decode_all(s), 0):
    case Result/Ok:
      return Bytes/equal(found.val, [4, 5, 6])
    case Result/Err:
      return 0

def t_cert_rejects_key(s):
  match found = X509/cert_ders(s):
    case Result/Ok:
      return 0
    case Result/Err:
      return 1

def t_zero_width(s):
  return Bytes/len(Pdf/stream_entries(t_parse(s), [1])) == 0

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
  return Bytes/find(S(z, "-------BEGIN"), S(z, "-----BEGIN")) == 2

def t19(z):
  return Bytes/rfind(S(z, "aaaa"), S(z, "aa")) == 2

def t20(z):
  return Bytes/find(S(z, "abc"), S(z, "")) == 0

def t21(z):
  return t_split(S(z, "abcdef"))

def t22(z):
  return t_strip_prefix(S(z, "streamX"), S(z, "strXam"))

def t23(z):
  return Bytes/find(S(z, "abc"), S(z, "x")) == Bytes/NONE

def t24(z):
  return Bytes/equal(Bytes/from_u24(z + 9876543), S(z, "9876543"))

def t25(z):
  return t_parse_u24(S(z, "0042 x"))

def t26(z):
  return Bytes/equal(Bytes/from_io(Lz(z, [0xFFFF93, 0x41])), Lz(z, [0x93, 0x41]))

def t27(z):
  return Bytes/equal(Bytes/join(Bytes/sort(Lz(z, [[3], [1, 2], [1]]))), Lz(z, [1, 1, 2, 3]))

def t28(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 0)), H(z, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))

def t29(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 3)), H(z, "b39fad1a1075f64570b3226d339ea818f9c66ecd2f1c59fd8b9c5a32b54c513f"))

def t30(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 55)), H(z, "2900465fcb533e05a158fd2b3be0e5e3b03740d83060aa3580e0d98a96bf2384"))

def t31(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 56)), H(z, "31454ff48ef36af2f08fd511bdc37d9d5855ac23e992e5ff5445cb6b7674a674"))

def t32(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 63)), H(z, "5f6401b96532c36de4e65beec0409b69b1d181864c8009b7a04f43e5d56350d1"))

def t33(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 64)), H(z, "94eb5de4943613fd048dc93393ab06877405faa39c11f53e9386083339833e7e"))

def t34(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 119)), H(z, "b0dc41b1a384e2f1203f0351b38fbeaafceef577ce1191d5bfc25da39f721eae"))

def t35(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 1000)), H(z, "57799de80e3dd6e2ac4d40c41a150d1662f7f87d0d994776a2fdc37c39b0ea4e"))

def t36(z):
  return BigInt/cmp(BigInt/add(BI(z, "120c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438"), BI(z, "254c665d9dc9f81818e811892f902bd23f0824")), BI(z, "120c5c7fd0a6c8f0b6c2b0f1063eb6f5497bd6de102525bc5c")) == 1

def t37(z):
  return BigInt/cmp(BigInt/sub(BI(z, "120c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438"), BI(z, "254c665d9dc9f81818e811892f902bd23f0824")), BI(z, "120c5c7fd0a67e57ea07755d160e8525266977bdb880a7ac14")) == 1

def t38(z):
  return BigInt/cmp(BigInt/mul(BI(z, "120c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438"), BI(z, "254c665d9dc9f81818e811892f902bd23f0824")), BI(z, "02a12c417592609d35fa6ceb5bf6112aa13387f6132959ed6ca8388f8c66e94a998d7b05918f82b727db17e0")) == 1

def t39(z):
  return BigInt/cmp(BigInt/mod(BI(z, "02a12c417592609d35fa6ceb5bf6112aa13387f6132959ed6ca8388f8c66e94a998d7b05918f82b727db4819"), BI(z, "eb0d549b6f03675a1600a35a099950d836f675cc81e74ef5e8e25d940ed90475")), BI(z, "ba7081a5791b35ecd90d8b098d39cde2741a2b32be7b5c42504ee70f2c861ecc")) == 1

def t40(z):
  return BigInt/cmp(BigInt/modexp(BI(z, "120c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438"), H(z, "3d9c172411e20b8f"), BI(z, "eb0d549b6f03675a1600a35a099950d836f675cc81e74ef5e8e25d940ed90475")), BI(z, "067b21173e82a75e95e8630ae59ffab15977cf42c4d16c5ff1bef5f2457f43b8")) == 1

def t41(z):
  return Bytes/equal(BigInt/to_bytes(BI(z, "120c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438"), 30), H(z, "0000000000120c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438"))

def t42(z):
  return Bytes/equal(Der/len_bytes(z + 300), Lz(z, [0x82, 0x01, 0x2c]))

def t43(z):
  return Bytes/equal(Der/int(Lz(z, [0x00, 0x80])), Lz(z, [0x02, 0x02, 0x00, 0x80]))

def t44(z):
  return Bytes/equal(Der/int(Lz(z, [])), Lz(z, [0x02, 0x01, 0x00]))

def t45(z):
  return t_der_read(z)

def t46(z):
  return t_pem(S(z, "-----BEGIN X-----\nAQID\nBA==\n-----END X-----\n"))

def t47(z):
  return t_key_block(S(z, "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nBAUG\n-----END PRIVATE KEY-----\n"))

def t48(z):
  return t_cert_rejects_key(S(z, "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nBAUG\n-----END PRIVATE KEY-----\n"))

def t49(z):
  return Bytes/equal(Inflate/zlib(Lz(z, [120, 218, 203, 72, 205, 201, 201, 87, 200, 64, 34, 203, 243, 139, 114, 82, 0, 104, 125, 8, 197])), S(z, "hello hello hello world"))

def t50(z):
  return Bytes/equal(Inflate/zlib(Lz(z, [120, 218, 51, 84, 48, 80, 200, 79, 202, 82, 176, 177, 81, 208, 15, 169, 44, 72, 85, 208, 119, 78, 44, 73, 204, 201, 79, 87, 208, 15, 72, 76, 79, 45, 86, 48, 2, 42, 8, 82, 176, 179, 83, 72, 205, 75, 1, 41, 52, 28, 137, 26, 0, 110, 22, 84, 97])), S(z, "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj 1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj 1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj 1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj 1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj 1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj "))

def t51(z):
  return Bytes/equal(Inflate/zlib(Lz(z, [120, 1, 1, 13, 0, 242, 255, 115, 116, 111, 114, 101, 100, 32, 98, 108, 111, 99, 107, 33, 36, 94, 4, 222])), S(z, "stored block!"))

def t52(z):
  return t_prefix(S(z, "0 0 obj << /Type /Page /Parent 2 0 R /Contents 40 0 R >> endobj 1 0 obj << /Type /Page /Parent 2 0 R /Contents 41 0 R >> endobj 2 0 obj << /Type /Page /Parent 2 0 R /Contents 42 0 R >> endobj 3 0 obj << /Type /Page /Parent 2 0 R /Contents 43 0 R >> endobj 4 0 obj << /Type /Page /Parent 2 0 R /Contents 44 0 R >> endobj 5 0 obj << /Type /Page /Parent 2 0 R /Contents 45 0 R >> endobj 6 0 obj << /Type /Page /Parent 2 0 R /Contents 46 0 R >> endobj 7 0 obj << /Type /Page /Parent 2 0 R /Contents 47 0 R >> endobj 8 0 obj << /Type /Page /Parent 2 0 R /Contents 48 0 R >> endobj 9 0 obj << /Type /Page /Parent 2 0 R /Contents 49 0 R >> endobj 10 0 obj << /Type /Page /Parent 2 0 R /Contents 50 0 R >> endobj 11 0 obj << /Type /Page /Parent 2 0 R /Contents 51 0 R >> endobj "), Inflate/zlib(Lz(z, [120, 218, 149, 210, 59, 10, 132, 48, 20, 133, 225, 173, 156, 29, 36, 198, 196, 7, 136, 141, 27, 16, 153, 13, 204, 96, 16, 44, 162, 168, 141, 187, 247, 81, 158, 169, 78, 19, 184, 185, 124, 183, 250, 45, 44, 150, 223, 140, 166, 129, 249, 156, 107, 132, 233, 191, 211, 251, 110, 49, 29, 112, 247, 122, 128, 233, 150, 116, 220, 227, 14, 111, 223, 143, 182, 69, 76, 227])))

def t53(z):
  return Bytes/len(Inflate/zlib(Lz(z, [120, 156, 255, 255, 255, 255, 19, 55]))) < 100000

def t54(z):
  return Bytes/equal(Png/unfilter(Lz(z, [2, 1, 2, 2, 1, 1, 0, 5, 5]), 2, 1), Lz(z, [1, 2, 2, 3, 5, 5]))

def t55(z):
  return Bytes/equal(Png/unfilter(Lz(z, [1, 1, 2, 3]), 3, 1), Lz(z, [1, 3, 6]))

def t56(z):
  return Bytes/equal(Pdf/serialize(t_parse(S(z, "<< /A 1 0 R /B [1 2 (x\\)y)] /C <AB> /D -1.5 >>"))), S(z, "<</A 1 0 R /B [1 2 (x\\)y)] /C <AB> /D -1.5 >>"))

def t57(z):
  return Pdf/get_ref_num(t_parse(S(z, "<< /Root 12 0 R >>"))) == 12

def t58(z):
  return Bytes/equal(Pdf/serialize(Pdf/text_string(Lz(z, [65, 112, 112, 114, 111, 118, 101, 100, 32, 226, 156, 147, 32, 226, 130, 172, 32, 240, 159, 152, 128]))), S(z, "<FEFF0041007000700072006F00760065006400202713002020AC0020D83DDE00>"))

def t59(z):
  return Pdf/startxref(S(z, "%PDF-1.4\nx\nstartxref\n1234\n%%EOF")) == 1234

def t60(z):
  return t_zero_width(S(z, "<< /W [0 0 0] /Size 16000000 >>"))

def t61(z):
  return Bytes/len(Pdf/byterange_text(z + 1, 99999, 123)) == Pdf/BYTERANGE_WIDTH

def t62(z):
  return Bytes/len(Pdf/BYTERANGE_PLACEHOLDER) == Pdf/BYTERANGE_WIDTH

def t63(z):
  return Bytes/equal(X509/find_cn(Der/children(H(z, "310f300d06035504031e06004100f120ac"))), Lz(z, [65, 195, 177, 226, 130, 172]))

def t64(z):
  return Bytes/equal(Text/utf8_encode(Text/utf8_decode(Lz(z, [65, 112, 112, 114, 111, 118, 101, 100, 32, 226, 156, 147, 32, 226, 130, 172, 32, 240, 159, 152, 128]))), Lz(z, [65, 112, 112, 114, 111, 118, 101, 100, 32, 226, 156, 147, 32, 226, 130, 172, 32, 240, 159, 152, 128]))

def t65(z):
  return Bytes/equal(Text/utf8_encode(Text/utf16be_decode(Lz(z, [0, 65, 0, 112, 0, 112, 0, 114, 0, 111, 0, 118, 0, 101, 0, 100, 0, 32, 39, 19, 0, 32, 32, 172, 0, 32, 216, 61, 222, 0]))), Lz(z, [65, 112, 112, 114, 111, 118, 101, 100, 32, 226, 156, 147, 32, 226, 130, 172, 32, 240, 159, 152, 128]))

def t66(z):
  return Bytes/len(Rsa/emsa_pkcs1_v15(Bytes/repeat(z, 32), z + 256)) == 256

def t67(z):
  return t_attrs_sorted(z)

def check(name, ok, rest):
  if ok:
    return rest
  else:
    return List/Cons(name, rest)

def run(z):
  return (68, check("hex", t0(z), check("hex_decode", t1(z), check("base64_enc_0", t2(z), check("base64_dec_0", t3(z), check("base64_enc_1", t4(z), check("base64_dec_1", t5(z), check("base64_enc_2", t6(z), check("base64_dec_2", t7(z), check("base64_enc_3", t8(z), check("base64_dec_3", t9(z), check("base64_enc_4", t10(z), check("base64_dec_4", t11(z), check("base64_enc_5", t12(z), check("base64_dec_5", t13(z), check("base64_enc_6", t14(z), check("base64_dec_6", t15(z), check("find", t16(z), check("rfind", t17(z), check("find_overlap", t18(z), check("rfind_overlap", t19(z), check("find_empty", t20(z), check("split", t21(z), check("strip_prefix", t22(z), check("find_none", t23(z), check("decimal", t24(z), check("parse_u24", t25(z), check("from_io", t26(z), check("sort", t27(z), check("sha256_0", t28(z), check("sha256_3", t29(z), check("sha256_55", t30(z), check("sha256_56", t31(z), check("sha256_63", t32(z), check("sha256_64", t33(z), check("sha256_119", t34(z), check("sha256_1000", t35(z), check("bigint_add", t36(z), check("bigint_sub", t37(z), check("bigint_mul", t38(z), check("bigint_mod", t39(z), check("bigint_modexp", t40(z), check("bigint_to_bytes", t41(z), check("der_len", t42(z), check("der_int_pad", t43(z), check("der_int_zero", t44(z), check("der_read", t45(z), check("pem", t46(z), check("pem_key_from_bundle", t47(z), check("pem_cert_file_with_key", t48(z), check("inflate_fixed", t49(z), check("inflate_dynamic", t50(z), check("inflate_stored", t51(z), check("inflate_truncated", t52(z), check("inflate_garbage", t53(z), check("png_up", t54(z), check("png_sub", t55(z), check("pdf_roundtrip", t56(z), check("pdf_ref", t57(z), check("pdf_text_utf16", t58(z), check("pdf_startxref", t59(z), check("pdf_xref_zero_width", t60(z), check("pdf_byterange_width", t61(z), check("pdf_byterange_placeholder", t62(z), check("x509_bmp_cn", t63(z), check("text_utf8_roundtrip", t64(z), check("text_utf16_decode", t65(z), check("emsa_len", t66(z), check("cms_attrs_sorted", t67(z), [])))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))

def main():
  return run(0)
