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
from lib/json import *
from lib/http import *
from lib/clock import *
from lib/service import *

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

def test_hex(z):
  return Bytes/equal(Bytes/to_hex(S(z, "Bend!")), S(z, "42656e6421"))

def test_hex_decode(z):
  return Bytes/equal(Bytes/from_hex(S(z, "42 65 6E 64 21")), S(z, "Bend!"))

def test_base64_enc_0(z):
  return Bytes/equal(Bytes/to_base64(Lz(z, [])), S(z, ""))

def test_base64_dec_0(z):
  return Bytes/equal(Bytes/from_base64(S(z, "")), Lz(z, []))

def test_base64_enc_1(z):
  return Bytes/equal(Bytes/to_base64(Lz(z, [102])), S(z, "Zg=="))

def test_base64_dec_1(z):
  return Bytes/equal(Bytes/from_base64(S(z, "Zg==")), Lz(z, [102]))

def test_base64_enc_2(z):
  return Bytes/equal(Bytes/to_base64(Lz(z, [102, 111])), S(z, "Zm8="))

def test_base64_dec_2(z):
  return Bytes/equal(Bytes/from_base64(S(z, "Zm8=")), Lz(z, [102, 111]))

def test_base64_enc_3(z):
  return Bytes/equal(Bytes/to_base64(Lz(z, [102, 111, 111])), S(z, "Zm9v"))

def test_base64_dec_3(z):
  return Bytes/equal(Bytes/from_base64(S(z, "Zm9v")), Lz(z, [102, 111, 111]))

def test_base64_enc_4(z):
  return Bytes/equal(Bytes/to_base64(Lz(z, [102, 111, 111, 98])), S(z, "Zm9vYg=="))

def test_base64_dec_4(z):
  return Bytes/equal(Bytes/from_base64(S(z, "Zm9vYg==")), Lz(z, [102, 111, 111, 98]))

def test_base64_enc_5(z):
  return Bytes/equal(Bytes/to_base64(Lz(z, [102, 111, 111, 98, 97])), S(z, "Zm9vYmE="))

def test_base64_dec_5(z):
  return Bytes/equal(Bytes/from_base64(S(z, "Zm9vYmE=")), Lz(z, [102, 111, 111, 98, 97]))

def test_base64_enc_6(z):
  return Bytes/equal(Bytes/to_base64(Lz(z, [102, 111, 111, 98, 97, 114])), S(z, "Zm9vYmFy"))

def test_base64_dec_6(z):
  return Bytes/equal(Bytes/from_base64(S(z, "Zm9vYmFy")), Lz(z, [102, 111, 111, 98, 97, 114]))

def test_find(z):
  return Bytes/find(S(z, "abcabc"), S(z, "ca")) == 2

def test_rfind(z):
  return Bytes/rfind(S(z, "abcabc"), S(z, "bc")) == 4

def test_find_overlap(z):
  return Bytes/find(S(z, "-------BEGIN"), S(z, "-----BEGIN")) == 2

def test_rfind_overlap(z):
  return Bytes/rfind(S(z, "aaaa"), S(z, "aa")) == 2

def test_find_empty(z):
  return Bytes/find(S(z, "abc"), S(z, "")) == 0

def test_split(z):
  return t_split(S(z, "abcdef"))

def test_strip_prefix(z):
  return t_strip_prefix(S(z, "streamX"), S(z, "strXam"))

def test_find_none(z):
  return Bytes/find(S(z, "abc"), S(z, "x")) == Bytes/NONE

def test_decimal(z):
  return Bytes/equal(Bytes/from_u24(z + 9876543), S(z, "9876543"))

def test_parse_u24(z):
  return t_parse_u24(S(z, "0042 x"))

def test_from_io(z):
  return Bytes/equal(Bytes/from_io(Lz(z, [0xFFFF93, 0x41])), Lz(z, [0x93, 0x41]))

def test_sort(z):
  return Bytes/equal(Bytes/join(Bytes/sort(Lz(z, [[3], [1, 2], [1]]))), Lz(z, [1, 1, 2, 3]))

def test_sha256_0(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 0)), H(z, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))

def test_sha256_3(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 3)), H(z, "b39fad1a1075f64570b3226d339ea818f9c66ecd2f1c59fd8b9c5a32b54c513f"))

def test_sha256_55(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 55)), H(z, "2900465fcb533e05a158fd2b3be0e5e3b03740d83060aa3580e0d98a96bf2384"))

def test_sha256_56(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 56)), H(z, "31454ff48ef36af2f08fd511bdc37d9d5855ac23e992e5ff5445cb6b7674a674"))

def test_sha256_63(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 63)), H(z, "5f6401b96532c36de4e65beec0409b69b1d181864c8009b7a04f43e5d56350d1"))

def test_sha256_64(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 64)), H(z, "94eb5de4943613fd048dc93393ab06877405faa39c11f53e9386083339833e7e"))

def test_sha256_119(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 119)), H(z, "b0dc41b1a384e2f1203f0351b38fbeaafceef577ce1191d5bfc25da39f721eae"))

def test_sha256_1000(z):
  return Bytes/equal(Sha256/digest(t_pattern(z + 1000)), H(z, "57799de80e3dd6e2ac4d40c41a150d1662f7f87d0d994776a2fdc37c39b0ea4e"))

def test_bigint_add(z):
  return BigInt/cmp(BigInt/add(BI(z, "120c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438"), BI(z, "254c665d9dc9f81818e811892f902bd23f0824")), BI(z, "120c5c7fd0a6c8f0b6c2b0f1063eb6f5497bd6de102525bc5c")) == 1

def test_bigint_sub(z):
  return BigInt/cmp(BigInt/sub(BI(z, "120c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438"), BI(z, "254c665d9dc9f81818e811892f902bd23f0824")), BI(z, "120c5c7fd0a67e57ea07755d160e8525266977bdb880a7ac14")) == 1

def test_bigint_mul(z):
  return BigInt/cmp(BigInt/mul(BI(z, "120c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438"), BI(z, "254c665d9dc9f81818e811892f902bd23f0824")), BI(z, "02a12c417592609d35fa6ceb5bf6112aa13387f6132959ed6ca8388f8c66e94a998d7b05918f82b727db17e0")) == 1

def test_bigint_mod(z):
  return BigInt/cmp(BigInt/mod(BI(z, "02a12c417592609d35fa6ceb5bf6112aa13387f6132959ed6ca8388f8c66e94a998d7b05918f82b727db4819"), BI(z, "eb0d549b6f03675a1600a35a099950d836f675cc81e74ef5e8e25d940ed90475")), BI(z, "ba7081a5791b35ecd90d8b098d39cde2741a2b32be7b5c42504ee70f2c861ecc")) == 1

def test_bigint_modexp(z):
  return BigInt/cmp(BigInt/modexp(BI(z, "120c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438"), H(z, "3d9c172411e20b8f"), BI(z, "eb0d549b6f03675a1600a35a099950d836f675cc81e74ef5e8e25d940ed90475")), BI(z, "067b21173e82a75e95e8630ae59ffab15977cf42c4d16c5ff1bef5f2457f43b8")) == 1

def test_bigint_to_bytes(z):
  return Bytes/equal(BigInt/to_bytes(BI(z, "120c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438"), 30), H(z, "0000000000120c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438"))

def test_der_len(z):
  return Bytes/equal(Der/len_bytes(z + 300), Lz(z, [0x82, 0x01, 0x2c]))

def test_der_int_pad(z):
  return Bytes/equal(Der/int(Lz(z, [0x00, 0x80])), Lz(z, [0x02, 0x02, 0x00, 0x80]))

def test_der_int_zero(z):
  return Bytes/equal(Der/int(Lz(z, [])), Lz(z, [0x02, 0x01, 0x00]))

def test_der_read(z):
  return t_der_read(z)

def test_pem(z):
  return t_pem(S(z, "-----BEGIN X-----\nAQID\nBA==\n-----END X-----\n"))

def test_pem_key_from_bundle(z):
  return t_key_block(S(z, "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nBAUG\n-----END PRIVATE KEY-----\n"))

def test_pem_cert_file_with_key(z):
  return t_cert_rejects_key(S(z, "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nBAUG\n-----END PRIVATE KEY-----\n"))

def test_inflate_fixed(z):
  return Bytes/equal(Inflate/zlib(Lz(z, [120, 218, 203, 72, 205, 201, 201, 87, 200, 64, 34, 203, 243, 139, 114, 82, 0, 104, 125, 8, 197])), S(z, "hello hello hello world"))

def test_inflate_dynamic(z):
  return Bytes/equal(Inflate/zlib(Lz(z, [120, 218, 51, 84, 48, 80, 200, 79, 202, 82, 176, 177, 81, 208, 15, 169, 44, 72, 85, 208, 119, 78, 44, 73, 204, 201, 79, 87, 208, 15, 72, 76, 79, 45, 86, 48, 2, 42, 8, 82, 176, 179, 83, 72, 205, 75, 1, 41, 52, 28, 137, 26, 0, 110, 22, 84, 97])), S(z, "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj 1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj 1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj 1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj 1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj 1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj "))

def test_inflate_stored(z):
  return Bytes/equal(Inflate/zlib(Lz(z, [120, 1, 1, 13, 0, 242, 255, 115, 116, 111, 114, 101, 100, 32, 98, 108, 111, 99, 107, 33, 36, 94, 4, 222])), S(z, "stored block!"))

def test_inflate_truncated(z):
  return t_prefix(S(z, "0 0 obj << /Type /Page /Parent 2 0 R /Contents 40 0 R >> endobj 1 0 obj << /Type /Page /Parent 2 0 R /Contents 41 0 R >> endobj 2 0 obj << /Type /Page /Parent 2 0 R /Contents 42 0 R >> endobj 3 0 obj << /Type /Page /Parent 2 0 R /Contents 43 0 R >> endobj 4 0 obj << /Type /Page /Parent 2 0 R /Contents 44 0 R >> endobj 5 0 obj << /Type /Page /Parent 2 0 R /Contents 45 0 R >> endobj 6 0 obj << /Type /Page /Parent 2 0 R /Contents 46 0 R >> endobj 7 0 obj << /Type /Page /Parent 2 0 R /Contents 47 0 R >> endobj 8 0 obj << /Type /Page /Parent 2 0 R /Contents 48 0 R >> endobj 9 0 obj << /Type /Page /Parent 2 0 R /Contents 49 0 R >> endobj 10 0 obj << /Type /Page /Parent 2 0 R /Contents 50 0 R >> endobj 11 0 obj << /Type /Page /Parent 2 0 R /Contents 51 0 R >> endobj "), Inflate/zlib(Lz(z, [120, 218, 149, 210, 59, 10, 132, 48, 20, 133, 225, 173, 156, 29, 36, 198, 196, 7, 136, 141, 27, 16, 153, 13, 204, 96, 16, 44, 162, 168, 141, 187, 247, 81, 158, 169, 78, 19, 184, 185, 124, 183, 250, 45, 44, 150, 223, 140, 166, 129, 249, 156, 107, 132, 233, 191, 211, 251, 110, 49, 29, 112, 247, 122, 128, 233, 150, 116, 220, 227, 14, 111, 223, 143, 182, 69, 76, 227])))

def test_inflate_garbage(z):
  return Bytes/len(Inflate/zlib(Lz(z, [120, 156, 255, 255, 255, 255, 19, 55]))) < 100000

def test_png_up(z):
  return Bytes/equal(Png/unfilter(Lz(z, [2, 1, 2, 2, 1, 1, 0, 5, 5]), 2, 1), Lz(z, [1, 2, 2, 3, 5, 5]))

def test_png_sub(z):
  return Bytes/equal(Png/unfilter(Lz(z, [1, 1, 2, 3]), 3, 1), Lz(z, [1, 3, 6]))

def test_pdf_roundtrip(z):
  return Bytes/equal(Pdf/serialize(t_parse(S(z, "<< /A 1 0 R /B [1 2 (x\\)y)] /C <AB> /D -1.5 >>"))), S(z, "<</A 1 0 R /B [1 2 (x\\)y)] /C <AB> /D -1.5 >>"))

def test_pdf_ref(z):
  return Pdf/get_ref_num(t_parse(S(z, "<< /Root 12 0 R >>"))) == 12

def test_pdf_text_utf16(z):
  return Bytes/equal(Pdf/serialize(Pdf/text_string(Lz(z, [65, 112, 112, 114, 111, 118, 101, 100, 32, 226, 156, 147, 32, 226, 130, 172, 32, 240, 159, 152, 128]))), S(z, "<FEFF0041007000700072006F00760065006400202713002020AC0020D83DDE00>"))

def test_pdf_startxref(z):
  return Pdf/startxref(S(z, "%PDF-1.4\nx\nstartxref\n1234\n%%EOF")) == 1234

def test_pdf_xref_zero_width(z):
  return t_zero_width(S(z, "<< /W [0 0 0] /Size 16000000 >>"))

def test_pdf_byterange_width(z):
  return Bytes/len(Pdf/byterange_text(z + 1, 99999, 123)) == Pdf/BYTERANGE_WIDTH

def test_pdf_byterange_placeholder(z):
  return Bytes/len(Pdf/BYTERANGE_PLACEHOLDER) == Pdf/BYTERANGE_WIDTH

def test_x509_bmp_cn(z):
  return Bytes/equal(X509/find_cn(Der/children(H(z, "310f300d06035504031e06004100f120ac"))), Lz(z, [65, 195, 177, 226, 130, 172]))

def test_text_utf8_roundtrip(z):
  return Bytes/equal(Text/utf8_encode(Text/utf8_decode(Lz(z, [65, 112, 112, 114, 111, 118, 101, 100, 32, 226, 156, 147, 32, 226, 130, 172, 32, 240, 159, 152, 128]))), Lz(z, [65, 112, 112, 114, 111, 118, 101, 100, 32, 226, 156, 147, 32, 226, 130, 172, 32, 240, 159, 152, 128]))

def test_text_utf16_decode(z):
  return Bytes/equal(Text/utf8_encode(Text/utf16be_decode(Lz(z, [0, 65, 0, 112, 0, 112, 0, 114, 0, 111, 0, 118, 0, 101, 0, 100, 0, 32, 39, 19, 0, 32, 32, 172, 0, 32, 216, 61, 222, 0]))), Lz(z, [65, 112, 112, 114, 111, 118, 101, 100, 32, 226, 156, 147, 32, 226, 130, 172, 32, 240, 159, 152, 128]))

def test_emsa_len(z):
  return Bytes/len(Rsa/emsa_pkcs1_v15(Bytes/repeat(z, 32), z + 256)) == 256

def test_cms_attrs_sorted(z):
  return t_attrs_sorted(z)

def t_json_field(text, key):
  (ok, json) = Json/parse(text)
  match json:
    case Json/Obj:
      (found, v) = Service/lookup(json.entries, key)
      match v:
        case Json/Str:
          return (ok & found, v.bytes)
        case _:
          return (0, [])
    case _:
      return (0, [])

def t_json_bad(s):
  (ok, *) = Json/parse(s)
  return ok == 0

def t_b64(s, n, expected):
  (ok, count, bytes) = Bytes/from_base64_strict(s)
  return ok & (count == n) & Bytes/equal(bytes, expected)

def t_b64_bad(s):
  (ok, *, *) = Bytes/from_base64_strict(s)
  return ok == 0

def t_http_bad(s):
  (ok, *) = Http/parse(s)
  return ok == 0

def t_cl(s, st, n):
  (a, b) = Http/content_length(s)
  return (a == st) & (b == n)

def t_civil(days, y, m, d):
  (a, b, c) = Clock/civil(days)
  return (a == y) & (b == m) & (c == d)

def t_now(stat, uptime, expected):
  (ok, days, secs) = Clock/now(stat, uptime)
  return ok & Bytes/equal(Clock/stamp(days, secs), expected)

def t_conf_ok(text):
  c = Service/conf(text)
  open Conf: c
  return Service/empty(c.error)

def t_route(conf, head, complete):
  match route = Service/route(conf, head, complete):
    case Route/Reply:
      return route.status
    case Route/Body:
      return 1000 + route.kind * 100 + route.expect * 10 + route.accept_pdf
    case Route/Status:
      return 2000
    case Route/Download:
      return 3000

def t_post(z, accept_pdf, body):
  return Service/post(S(z, "token=t\n"), 0, accept_pdf, body, Lz(z, [1]), Lz(z, [2]), S(z, "btime 1792754473\n"), S(z, "601\n"), Lz(z, []))

def t_post_status(z, body):
  match out = t_post(z, 0, body):
    case Outcome/Reply:
      return out.status
    case Outcome/Sign:
      return 0

def test_json_parse(z):
  (ok, s) = t_json_field(S(z, "{\"a\": \"x\\\"y\\n\\u00e9\\ud83d\\ude00\", \"b\": [1, -2.5e3, true, false, null, {}], \"c\": {\"d\": []}}"), S(z, "a"))
  return ok & Bytes/equal(s, Lz(z, [120, 34, 121, 10, 195, 169, 240, 159, 152, 128]))

def test_json_lone_surrogate(z):
  (ok, s) = t_json_field(S(z, "{\"a\": \"\\ud800x\"}"), S(z, "a"))
  return ok & Bytes/equal(s, Lz(z, [239, 191, 189, 120]))

def test_json_invalid(z):
  return t_json_bad(S(z, "{\"a\": 1,}")) & t_json_bad(S(z, "{\"a\": 01}")) & t_json_bad(S(z, "{\"a\": \"x")) & t_json_bad(S(z, "{\"a\": \"x\ny\"}")) & t_json_bad(S(z, "{\"a\": 1} x")) & t_json_bad(S(z, "{\"a\" 1}")) & t_json_bad(S(z, "[1,]")) & t_json_bad(S(z, "{\"a\": tru}")) & t_json_bad(S(z, "{\"a\": 1.}")) & t_json_bad(S(z, "{\"a\": -}")) & t_json_bad(Lz(z, []))

def test_json_quote(z):
  return Bytes/equal(Json/quote(Lz(z, [34, 92, 10, 1, 195, 169])), Lz(z, [34, 92, 34, 92, 92, 92, 110, 92, 117, 48, 48, 48, 49, 195, 169, 34]))

def test_json_object_text(z):
  return Bytes/equal(Json/object_text([Json/member("a", Json/quote(S(z, "x"))), Json/member("b", Json/bool_text(z + 1))]), S(z, "{\"a\": \"x\", \"b\": true}"))

def test_base64_strict(z):
  return t_b64(S(z, "TWFu"), 3, S(z, "Man")) & t_b64(S(z, "TWE="), 2, S(z, "Ma")) & t_b64(S(z, "TQ=="), 1, S(z, "M")) & t_b64(Lz(z, []), 0, Lz(z, []))

def test_base64_strict_invalid(z):
  return t_b64_bad(S(z, "TWE")) & t_b64_bad(S(z, "T===")) & t_b64_bad(S(z, "TW=u")) & t_b64_bad(S(z, "TWF-")) & t_b64_bad(S(z, "TQ==TQ==")) & t_b64_bad(S(z, "TW E")) & t_b64_bad(S(z, "TWFu\n"))

def test_measure(z):
  (n, xs) = Bytes/measure(Lz(z, [7, 8, 9]))
  return (n == 3) & Bytes/equal(xs, Lz(z, [7, 8, 9]))

def test_http_parse(z):
  (ok, req) = Http/parse(S(z, "POST /api/v1/sign?x=1 HTTP/1.1\r\nHost: Example:80\r\nContent-Length: 12\r\nX-A:  b c \r\n\r\n"))
  open Request: req
  (nhost, host) = Http/header(req.headers, S(z, "host"))
  (nxa, xa) = Http/header(req.headers, S(z, "x-a"))
  return ok & Bytes/equal(req.method, S(z, "POST")) & Bytes/equal(req.path, S(z, "/api/v1/sign")) & (nhost == 1) & Bytes/equal(host, S(z, "Example:80")) & (nxa == 1) & Bytes/equal(xa, S(z, "b c"))

def test_http_invalid(z):
  return t_http_bad(S(z, "GET /x\r\n\r\n")) & t_http_bad(S(z, "GET x HTTP/1.1\r\n\r\n")) & t_http_bad(S(z, "GET / HTTP/1.1\r\nBad Header: x\r\n\r\n")) & t_http_bad(S(z, "GET / HTTP/1.1\r\nA: 1\r\n folded\r\n\r\n")) & t_http_bad(S(z, "GET / HTTP/2\r\n\r\n")) & t_http_bad(S(z, "GET / HTTP/1.1 x\r\n\r\n")) & t_http_bad(S(z, "GET / HTTP/1.1\r\nNoColon\r\n\r\n"))

def test_content_length(z):
  return t_cl(S(z, "12"), 0, 12) & t_cl(Lz(z, []), 1, 0) & t_cl(S(z, "1a"), 1, 0) & t_cl(S(z, "16777215"), 0, 16777215) & t_cl(S(z, "16777216"), 2, 0) & t_cl(S(z, "99999999999"), 2, 0) & t_cl(S(z, "-1"), 1, 0)

def test_http_helpers(z):
  return Bytes/equal(Http/origin_host(S(z, "https://Example.com:8443/path")), S(z, "example.com:8443")) & Bytes/equal(Http/origin_host(S(z, "null")), Lz(z, [])) & Bytes/equal(Http/media_type(S(z, "Application/JSON; charset=utf-8")), S(z, "application/json")) & Http/same(S(z, "abc"), S(z, "abc")) & (Http/same(S(z, "abc"), S(z, "abd")) == 0) & (Http/same(S(z, "abc"), S(z, "ab")) == 0)

def test_http_response(z):
  return Bytes/equal(Http/response(200, S(z, "text/plain"), Lz(z, []), S(z, "hi")), S(z, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nConnection: close\r\n\r\nhi"))

def test_clock_civil(z):
  return t_civil(z, 1970, 1, 1) & t_civil(z + 11016, 2000, 2, 29) & t_civil(z + 11017, 2000, 3, 1) & t_civil(z + 20749, 2026, 10, 23) & t_civil(z + 2932896, 9999, 12, 31)

def test_clock_now(z):
  return t_now(S(z, "cpu 1 2\nbtime 1792754473\nprocesses 5\n"), S(z, "601.04 2373.98\n"), S(z, "20261023113114")) & t_now(S(z, "btime 1700000000\n"), S(z, "1234567.89 1.00\n"), S(z, "20231129050927"))

def test_clock_missing(z):
  (ok, *, *) = Clock/now(S(z, "cpu 1\n"), S(z, "5.0\n"))
  return ok == 0

def test_clock_iso(z):
  return Bytes/equal(Clock/iso(z + 20749, 41474), S(z, "2026-10-23T11:31:14Z"))

def test_clock_elapsed(z):
  return (Clock/elapsed(z + 20749, 100, 20750, 50) == 86350) & (Clock/elapsed(z + 20749, 100, 20749, 50) == 0) & (Clock/elapsed(z + 1, 0, 200, 0) == 0xFFFFFF)

def test_conf(z):
  c = Service/conf(S(z, "token=t\nallowed_hosts= A.example:1 ,b:2,,\nmax_pdf=100\n"))
  open Conf: c
  return Bytes/equal(c.token, S(z, "t")) & (c.max_pdf == 100) & (c.sig_size == 8192) & Service/member(S(z, "a.example:1"), c.hosts) & Service/member(S(z, "b:2"), c.hosts) & Service/empty(c.error) & Bytes/equal(c.jobs, S(z, "jobs"))

def test_conf_errors(z):
  return (t_conf_ok(Lz(z, [])) == 0) & (t_conf_ok(S(z, "token=t\nsig_size=10\n")) == 0) & t_conf_ok(S(z, "anonymous=1\n"))

def test_route_public(z):
  c = S(z, "token=t\n")
  return (t_route(c, S(z, "GET /health HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"), 1) == 200) & (t_route(c, S(z, "GET / HTTP/1.1\r\nHost: LOCALHOST:8080\r\n\r\n"), 1) == 200) & (t_route(c, S(z, "GET /health HTTP/1.1\r\nHost: evil:1\r\n\r\n"), 1) == 403) & (t_route(c, S(z, "GET /health HTTP/1.1\r\n\r\n"), 1) == 403) & (t_route(c, S(z, "GET /health HTTP/1.1\r\nHost: localhost:8080\r\nOrigin: http://evil.example\r\n\r\n"), 1) == 403) & (t_route(c, S(z, "GET /health HTTP/1.1\r\nHost: localhost:8080\r\nOrigin: http://localhost:8080\r\n\r\n"), 1) == 200) & (t_route(c, S(z, "PUT / HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"), 1) == 405) & (t_route(c, S(z, "GET / HTTP/1.1\r\n"), 2) == 431) & (t_route(Lz(z, []), S(z, "GET /health HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"), 1) == 500)

def test_route_api(z):
  c = S(z, "token=t\n")
  return (t_route(c, S(z, "POST /api/v1/sign HTTP/1.1\r\nHost: localhost:8080\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n"), 1) == 401) & (t_route(c, S(z, "POST /api/v1/sign HTTP/1.1\r\nHost: localhost:8080\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n"), 1) == 1000) & (t_route(c, S(z, "POST /api/v1/jobs HTTP/1.1\r\nHost: localhost:8080\r\nAuthorization: Bearer t\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 10\r\nExpect: 100-continue\r\nAccept: application/pdf\r\n\r\n"), 1) == 1111) & (t_route(c, S(z, "POST /api/v1/sign HTTP/1.1\r\nHost: localhost:8080\r\nAuthorization: Bearer t\r\nContent-Type: text/plain\r\nContent-Length: 10\r\n\r\n"), 1) == 415) & (t_route(c, S(z, "POST /api/v1/sign HTTP/1.1\r\nHost: localhost:8080\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 16777215\r\n\r\n"), 1) == 413) & (t_route(c, S(z, "POST /api/v1/sign HTTP/1.1\r\nHost: localhost:8080\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\n\r\n"), 1) == 400) & (t_route(c, S(z, "POST /api/v1/other HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"), 1) == 404)

def test_route_jobs(z):
  c = S(z, "token=t\n")
  return (t_route(c, S(z, "GET /api/v1/jobs/0123456789abcdef0123456789abcdef HTTP/1.1\r\nHost: localhost:8080\r\nAuthorization: Bearer t\r\n\r\n"), 1) == 2000) & (t_route(c, S(z, "GET /api/v1/jobs/0123456789abcdef0123456789abcdef/pdf HTTP/1.1\r\nHost: localhost:8080\r\nAuthorization: Bearer t\r\n\r\n"), 1) == 3000) & (t_route(c, S(z, "GET /api/v1/jobs/0123456789ABCDEF0123456789abcdef HTTP/1.1\r\nHost: localhost:8080\r\nAuthorization: Bearer t\r\n\r\n"), 1) == 404) & (t_route(c, S(z, "GET /api/v1/jobs/0123456789abcdef0123456789abcdef HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"), 1) == 401)

def test_post_errors(z):
  return (t_post_status(z, S(z, "{\"pdf\": \"abc\"}")) == 400) & (t_post_status(z, S(z, "{\"pdf\": \"aGVsbG8=\"}")) == 400) & (t_post_status(z, S(z, "[]")) == 400) & (t_post_status(z, S(z, "{\"pdf\": \"JVBERi0xLjQK\", \"reason\": 5}")) == 400) & (t_post_status(z, S(z, "{\"reason\": \"x\"}")) == 400) & (t_post_status(z, S(z, "{\"pdf\": \"JVBERi0xLjQK\", \"key\": \"k\"}")) == 403) & (t_post_status(z, S(z, "{\"pdf\": ")) == 400)

def test_post_sign(z):
  match out = t_post(z, 1, S(z, "{\"pdf\": \"JVBERi0xLjQK\", \"reason\": \"a\\r\\nb\", \"name\": \"ignored\"}")):
    case Outcome/Reply:
      return 0
    case Outcome/Sign:
      return (out.mode == 1) & Bytes/equal(out.pdf, S(z, "%PDF-1.4\n")) & Bytes/equal(out.key, Lz(z, [1])) & Bytes/equal(out.params, S(z, "reason=a b\ntime=20261023113114\nsig_size=8192\n"))

def test_job_status(z):
  r = Service/job_status(S(z, "0123456789abcdef0123456789abcdef"), S(z, "done\n20749\n41474\n20749\n41500\n"), S(z, "btime 1792754473\n"), S(z, "601\n"), Lz(z, []))
  return Bytes/find(r, S(z, "{\"id\": \"0123456789abcdef0123456789abcdef\", \"status\": \"done\", \"created\": \"2026-10-23T11:31:14Z\", \"finished\": \"2026-10-23T11:31:40Z\"}")) != Bytes/NONE

def test_job_stale(z):
  r = Service/job_status(S(z, "0123456789abcdef0123456789abcdef"), S(z, "running\n20000\n0\n"), S(z, "btime 1792754473\n"), S(z, "601\n"), Lz(z, []))
  return Bytes/find(r, S(z, "\"error\": \"the signer stopped before finishing\"")) != Bytes/NONE

def summary(xs):
  match xs:
    case List/Nil:
      return (0, [])
    case List/Cons:
      (name, ok) = xs.head
      (n, fails) = summary(xs.tail)
      if ok:
        return (n + 1, fails)
      else:
        return (n + 1, List/Cons(name, fails))

def run(z):
  return summary([
    ("hex", test_hex(z)),
    ("hex_decode", test_hex_decode(z)),
    ("base64_enc_0", test_base64_enc_0(z)),
    ("base64_dec_0", test_base64_dec_0(z)),
    ("base64_enc_1", test_base64_enc_1(z)),
    ("base64_dec_1", test_base64_dec_1(z)),
    ("base64_enc_2", test_base64_enc_2(z)),
    ("base64_dec_2", test_base64_dec_2(z)),
    ("base64_enc_3", test_base64_enc_3(z)),
    ("base64_dec_3", test_base64_dec_3(z)),
    ("base64_enc_4", test_base64_enc_4(z)),
    ("base64_dec_4", test_base64_dec_4(z)),
    ("base64_enc_5", test_base64_enc_5(z)),
    ("base64_dec_5", test_base64_dec_5(z)),
    ("base64_enc_6", test_base64_enc_6(z)),
    ("base64_dec_6", test_base64_dec_6(z)),
    ("find", test_find(z)),
    ("rfind", test_rfind(z)),
    ("find_overlap", test_find_overlap(z)),
    ("rfind_overlap", test_rfind_overlap(z)),
    ("find_empty", test_find_empty(z)),
    ("split", test_split(z)),
    ("strip_prefix", test_strip_prefix(z)),
    ("find_none", test_find_none(z)),
    ("decimal", test_decimal(z)),
    ("parse_u24", test_parse_u24(z)),
    ("from_io", test_from_io(z)),
    ("sort", test_sort(z)),
    ("sha256_0", test_sha256_0(z)),
    ("sha256_3", test_sha256_3(z)),
    ("sha256_55", test_sha256_55(z)),
    ("sha256_56", test_sha256_56(z)),
    ("sha256_63", test_sha256_63(z)),
    ("sha256_64", test_sha256_64(z)),
    ("sha256_119", test_sha256_119(z)),
    ("sha256_1000", test_sha256_1000(z)),
    ("bigint_add", test_bigint_add(z)),
    ("bigint_sub", test_bigint_sub(z)),
    ("bigint_mul", test_bigint_mul(z)),
    ("bigint_mod", test_bigint_mod(z)),
    ("bigint_modexp", test_bigint_modexp(z)),
    ("bigint_to_bytes", test_bigint_to_bytes(z)),
    ("der_len", test_der_len(z)),
    ("der_int_pad", test_der_int_pad(z)),
    ("der_int_zero", test_der_int_zero(z)),
    ("der_read", test_der_read(z)),
    ("pem", test_pem(z)),
    ("pem_key_from_bundle", test_pem_key_from_bundle(z)),
    ("pem_cert_file_with_key", test_pem_cert_file_with_key(z)),
    ("inflate_fixed", test_inflate_fixed(z)),
    ("inflate_dynamic", test_inflate_dynamic(z)),
    ("inflate_stored", test_inflate_stored(z)),
    ("inflate_truncated", test_inflate_truncated(z)),
    ("inflate_garbage", test_inflate_garbage(z)),
    ("png_up", test_png_up(z)),
    ("png_sub", test_png_sub(z)),
    ("pdf_roundtrip", test_pdf_roundtrip(z)),
    ("pdf_ref", test_pdf_ref(z)),
    ("pdf_text_utf16", test_pdf_text_utf16(z)),
    ("pdf_startxref", test_pdf_startxref(z)),
    ("pdf_xref_zero_width", test_pdf_xref_zero_width(z)),
    ("pdf_byterange_width", test_pdf_byterange_width(z)),
    ("pdf_byterange_placeholder", test_pdf_byterange_placeholder(z)),
    ("x509_bmp_cn", test_x509_bmp_cn(z)),
    ("text_utf8_roundtrip", test_text_utf8_roundtrip(z)),
    ("text_utf16_decode", test_text_utf16_decode(z)),
    ("emsa_len", test_emsa_len(z)),
    ("cms_attrs_sorted", test_cms_attrs_sorted(z)),
    ("json_parse", test_json_parse(z)),
    ("json_lone_surrogate", test_json_lone_surrogate(z)),
    ("json_invalid", test_json_invalid(z)),
    ("json_quote", test_json_quote(z)),
    ("json_object_text", test_json_object_text(z)),
    ("base64_strict", test_base64_strict(z)),
    ("base64_strict_invalid", test_base64_strict_invalid(z)),
    ("measure", test_measure(z)),
    ("http_parse", test_http_parse(z)),
    ("http_invalid", test_http_invalid(z)),
    ("content_length", test_content_length(z)),
    ("http_helpers", test_http_helpers(z)),
    ("http_response", test_http_response(z)),
    ("clock_civil", test_clock_civil(z)),
    ("clock_now", test_clock_now(z)),
    ("clock_missing", test_clock_missing(z)),
    ("clock_iso", test_clock_iso(z)),
    ("clock_elapsed", test_clock_elapsed(z)),
    ("conf", test_conf(z)),
    ("conf_errors", test_conf_errors(z)),
    ("route_public", test_route_public(z)),
    ("route_api", test_route_api(z)),
    ("route_jobs", test_route_jobs(z)),
    ("post_errors", test_post_errors(z)),
    ("post_sign", test_post_sign(z)),
    ("job_status", test_job_status(z)),
    ("job_stale", test_job_stale(z)),
  ])

def main():
  return run(0)
