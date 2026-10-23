from lib/bytes import *
from lib/asn1 import *
from lib/sha256 import *
from lib/rsa import *
from lib/x509 import *
from lib/pdf import *

type Found:
  New { end, range, dict }

def Verify/OID_DATA() -> List(u24):
  return [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]

def Verify/OID_CONTENT_TYPE() -> List(u24):
  return [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03]

def Verify/OID_MESSAGE_DIGEST() -> List(u24):
  return [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04]

def Verify/OID_SIGNING_CERT_V2() -> List(u24):
  return [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f]

def Verify/OID_SHA256() -> List(u24):
  return [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]

def Verify/OID_RSA() -> List(u24):
  return [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]

def Verify/OID_SHA256_RSA() -> List(u24):
  return [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]

def Verify/run(pdf: List(u24)) -> (u24, List(u24), List((List(u24), List(u24)))):
  (n, data) = Bytes/measure(pdf)
  sx = Pdf/startxref(data)
  (xref, trailer, *, *) = Pdf/load_xref(data, sx, 64)
  root = Pdf/resolve(data, xref, Pdf/get(trailer, "Root"))
  form = Pdf/resolve(data, xref, Pdf/get(root, "AcroForm"))
  found = Verify/sort(Verify/fields(data, xref, Pdf/items(Pdf/resolve(data, xref, Pdf/get(form, "Fields"))), 8), [])
  (count, ok, lines, files) = Verify/each(data, n, sx, found, 1)
  if count == 0:
    return (0, Bytes/from_string("verify: no signatures found\n"), [])
  else:
    summary = Bytes/join([Bytes/from_string("verify: "), Bytes/from_u24(count), Bytes/from_string(" signature(s), "), Verify/word(ok), [10]])
    return (ok, Bytes/concat(lines, summary), files)

def Verify/word(ok: u24) -> List(u24):
  if ok:
    return Bytes/from_string("ok")
  else:
    return Bytes/from_string("FAIL")

def Verify/fields(pdf: List(u24), xref, refs: List(PdfObj), depth: u24) -> List(Found):
  match refs:
    case List/Nil:
      return []
    case List/Cons:
      field = Pdf/resolve(pdf, xref, refs.head)
      rest = Verify/fields(pdf, xref, refs.tail, depth)
      kids = Pdf/items(Pdf/resolve(pdf, xref, Pdf/get(field, "Kids")))
      v = Pdf/resolve(pdf, xref, Pdf/get(field, "V"))
      range = Pdf/ints(Pdf/items(Pdf/get(v, "ByteRange")))
      below = Verify/below(pdf, xref, kids, depth)
      if Pdf/name_is(Pdf/get(field, "FT"), "Sig") & Pdf/is_dict(v) & (Bytes/len(range) == 4):
        return List/Cons(Found/New(Verify/end(range), range, v), Verify/append(below, rest))
      else:
        return Verify/append(below, rest)

def Verify/below(pdf: List(u24), xref, kids: List(PdfObj), depth: u24) -> List(Found):
  if depth == 0:
    return []
  else:
    return Verify/fields(pdf, xref, kids, depth - 1)

def Verify/end(range: List(u24)) -> u24:
  return Bytes/at(range, 2) + Bytes/at(range, 3)

def Verify/sort(xs: List(Found), acc: List(Found)) -> List(Found):
  match xs:
    case List/Nil:
      return acc
    case List/Cons:
      return Verify/sort(xs.tail, Verify/insert(xs.head, acc))

def Verify/insert(x: Found, sorted: List(Found)) -> List(Found):
  match sorted:
    case List/Nil:
      return [x]
    case List/Cons:
      open Found: x
      head = sorted.head
      open Found: head
      if x.end <= head.end:
        return List/Cons(Found/New(x.end, x.range, x.dict), List/Cons(Found/New(head.end, head.range, head.dict), sorted.tail))
      else:
        return List/Cons(Found/New(head.end, head.range, head.dict), Verify/insert(Found/New(x.end, x.range, x.dict), sorted.tail))

def Verify/each(pdf: List(u24), n: u24, sx: u24, found: List(Found), k: u24) -> (u24, u24, List(u24), List((List(u24), List(u24)))):
  match found:
    case List/Nil:
      return (0, 1, [], [])
    case List/Cons:
      f = found.head
      open Found: f
      (ok, line, cms, content) = Verify/signature(pdf, n, sx, f.range, f.dict)
      (count, ok_rest, lines, files) = Verify/each(pdf, n, sx, found.tail, k + 1)
      name = Bytes/from_u24(k)
      head = Bytes/join([Bytes/from_string("signature "), name, Bytes/from_string(": "), line, [10]])
      mine = [(Bytes/join([Bytes/from_string("sig"), name, Bytes/from_string(".der")]), cms), (Bytes/join([Bytes/from_string("content"), name, Bytes/from_string(".bin")]), content)]
      return (count + 1, ok & ok_rest, Bytes/concat(head, lines), Verify/append(mine, files))

def Verify/append(xs, ys):
  match xs:
    case List/Nil:
      return ys
    case List/Cons:
      return List/Cons(xs.head, Verify/append(xs.tail, ys))

def Verify/signature(pdf: List(u24), n: u24, sx: u24, range: List(u24), dict: PdfObj) -> (u24, List(u24), List(u24), List(u24)):
  o1 = Bytes/at(range, 0)
  l1 = Bytes/at(range, 1)
  o2 = Bytes/at(range, 2)
  l2 = Bytes/at(range, 3)
  end = o2 + l2
  raw = Verify/raw(Pdf/get(dict, "Contents"))
  gap = Bytes/take(Bytes/drop(pdf, l1), o2 - l1)
  (*, *, cms, *) = Der/read(Bytes/from_hex(raw))
  content = Bytes/concat(Bytes/take(pdf, l1), Bytes/take(Bytes/drop(pdf, o2), l2))
  (cms_ok, cms_msg, cn) = Verify/cms(cms, Sha256/digest(content))
  (upd_ok, upd_msg) = Verify/updates(pdf, n, sx, end, Verify/docmdp(dict))
  filter = Pdf/name_is(Pdf/get(dict, "SubFilter"), "ETSI.CAdES.detached") | Pdf/name_is(Pdf/get(dict, "SubFilter"), "adbe.pkcs7.detached")
  if (o1 != 0) | (l1 >= o2) | (end > n):
    return (0, Bytes/from_string("FAIL invalid /ByteRange"), cms, content)
  elif Bytes/equal(gap, raw) == 0:
    return (0, Bytes/from_string("FAIL the /ByteRange gap is not exactly the /Contents string"), cms, content)
  elif filter == 0:
    return (0, Bytes/from_string("FAIL unsupported /SubFilter"), cms, content)
  elif cms_ok == 0:
    return (0, Bytes/concat(Bytes/from_string("FAIL "), cms_msg), cms, content)
  elif upd_ok == 0:
    return (0, Bytes/concat(Bytes/from_string("FAIL "), upd_msg), cms, content)
  else:
    return (1, Bytes/join([Bytes/from_string("ok, "), upd_msg, Bytes/from_string(", signer "), cn]), cms, content)

def Verify/raw(o: PdfObj) -> List(u24):
  match o:
    case PdfObj/Raw:
      return o.raw
    case _:
      return []

def Verify/docmdp(dict: PdfObj) -> u24:
  return Verify/docmdp.go(Pdf/items(Pdf/get(dict, "Reference")))

def Verify/docmdp.go(refs: List(PdfObj)) -> u24:
  match refs:
    case List/Nil:
      return 0
    case List/Cons:
      r = refs.head
      if Pdf/name_is(Pdf/get(r, "TransformMethod"), "DocMDP"):
        p = Pdf/get(Pdf/get(r, "TransformParams"), "P")
        if Pdf/is_null(p):
          return 2
        else:
          return Pdf/int(p)
      else:
        return Verify/docmdp.go(refs.tail)

def Verify/attr(attrs: List((u24, List(u24), List(u24))), oid: List(u24)) -> (u24, u24, List(u24)):
  match attrs:
    case List/Nil:
      return (0, 0, [])
    case List/Cons:
      (*, a, *) = attrs.head
      (*, a_oid, *) = Der/child(a, 0)
      (*, values, *) = Der/child(a, 1)
      if Bytes/equal(a_oid, oid):
        (vt, vc, *) = Der/child(values, 0)
        return (1, vt, vc)
      else:
        return Verify/attr(attrs.tail, oid)

def Verify/cms(cms: List(u24), digest: List(u24)) -> (u24, List(u24), List(u24)):
  (t0, ci, *, *) = Der/read(cms)
  (*, ci_oid, *) = Der/child(ci, 0)
  (*, wrapped, *) = Der/child(ci, 1)
  (*, sd, *) = Der/child(wrapped, 0)
  items = Der/children(sd)
  certs = Verify/certs(items)
  (*, infos, *) = Verify/last(items)
  (*, si, *) = Der/child(infos, 0)
  si_items = Der/children(si)
  (*, sid, *) = Der/nth(si_items, 1)
  (*, *, issuer) = Der/child(sid, 0)
  (*, *, serial) = Der/child(sid, 1)
  (*, dalg, *) = Der/nth(si_items, 2)
  (*, dalg_oid, *) = Der/child(dalg, 0)
  (tattrs, attrs, *) = Der/nth(si_items, 3)
  (*, salg, *) = Der/nth(si_items, 4)
  (*, salg_oid, *) = Der/child(salg, 0)
  (*, signature, *) = Der/nth(si_items, 5)
  list = Der/children(attrs)
  (has_ct, *, ct) = Verify/attr(list, Verify/OID_CONTENT_TYPE)
  (has_md, md_tag, md) = Verify/attr(list, Verify/OID_MESSAGE_DIGEST)
  (has_ess, *, ess) = Verify/attr(list, Verify/OID_SIGNING_CERT_V2)
  rsa_alg = Bytes/equal(salg_oid, Verify/OID_RSA) | Bytes/equal(salg_oid, Verify/OID_SHA256_RSA)
  match signer = Verify/signer(certs, issuer, serial):
    case Result/Err:
      return (0, Bytes/from_string("signer certificate not found in the CMS"), [])
    case Result/Ok:
      cert = signer.val
      open CertInfo: cert
      cert_hash = Sha256/digest(cert.der)
      valid = Rsa/verify_hash(cert.n, cert.e, Sha256/digest(Der/tlv(0x31, attrs)), signature)
      if (t0 != 0x30) | (Bytes/equal(ci_oid, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]) == 0):
        return (0, Bytes/from_string("not a CMS SignedData"), [])
      elif Bytes/equal(dalg_oid, Verify/OID_SHA256) == 0:
        return (0, Bytes/from_string("digest algorithm is not SHA-256"), [])
      elif tattrs != 0xA0:
        return (0, Bytes/from_string("signed attributes missing"), [])
      elif (has_ct == 0) | (Bytes/equal(ct, Verify/OID_DATA) == 0):
        return (0, Bytes/from_string("contentType attribute missing or not id-data"), [])
      elif (has_md == 0) | (md_tag != 0x04) | (Bytes/equal(md, digest) == 0):
        return (0, Bytes/from_string("messageDigest does not match the signed byte ranges"), [])
      elif (has_ess == 0) | (Bytes/equal(Verify/ess_hash(ess), cert_hash) == 0):
        return (0, Bytes/from_string("signingCertificateV2 does not match the signer certificate"), [])
      elif rsa_alg == 0:
        return (0, Bytes/from_string("signature algorithm is not RSA"), [])
      elif valid == 0:
        return (0, Bytes/from_string("RSA signature does not verify"), [])
      else:
        return (1, [], cert.subject_cn)

def Verify/ess_hash(ess: List(u24)) -> List(u24):
  (*, certs, *) = Der/child(ess, 0)
  (*, id, *) = Der/child(certs, 0)
  (t, c, *) = Der/child(id, 0)
  (*, c2, *) = Der/child(id, 1)
  if t == 0x04:
    return c
  elif Bytes/equal(Verify/alg_oid(c), Verify/OID_SHA256):
    return c2
  else:
    return []

def Verify/alg_oid(alg: List(u24)) -> List(u24):
  (*, oid, *) = Der/child(alg, 0)
  return oid

def Verify/certs(items: List((u24, List(u24), List(u24)))) -> List(List(u24)):
  match items:
    case List/Nil:
      return []
    case List/Cons:
      (tag, content, *) = items.head
      if tag == 0xA0:
        return Verify/ders(Der/children(content))
      else:
        return Verify/certs(items.tail)

def Verify/ders(xs: List((u24, List(u24), List(u24)))) -> List(List(u24)):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      (*, *, der) = xs.head
      return List/Cons(der, Verify/ders(xs.tail))

def Verify/last(xs: List((u24, List(u24), List(u24)))) -> (u24, List(u24), List(u24)):
  match xs:
    case List/Nil:
      return (0, [], [])
    case List/Cons:
      match xs.tail:
        case List/Nil:
          return xs.head
        case List/Cons:
          return Verify/last(xs.tail)

def Verify/signer(certs: List(List(u24)), issuer: List(u24), serial: List(u24)):
  match certs:
    case List/Nil:
      return Result/Err(0)
    case List/Cons:
      match info = X509/read_cert_der(certs.head):
        case Result/Ok:
          c = info.val
          open CertInfo: c
          if Bytes/equal(c.issuer, issuer) & Bytes/equal(c.serial, serial):
            return Result/Ok(CertInfo/New(c.der, c.issuer, c.serial, c.subject_cn, c.n, c.e))
          else:
            return Verify/signer(certs.tail, issuer, serial)
        case Result/Err:
          return Verify/signer(certs.tail, issuer, serial)

def Verify/updates(pdf: List(u24), n: u24, sx: u24, end: u24, docmdp: u24) -> (u24, List(u24)):
  if end >= n:
    return (1, Bytes/from_string("covers the whole file"))
  elif docmdp == 1:
    return (0, Bytes/from_string("the document is certified with DocMDP P=1 but was changed afterwards"))
  else:
    prefix = Bytes/take(pdf, end)
    (old, old_trailer, *, *) = Pdf/load_xref(prefix, Pdf/startxref(prefix), 64)
    root_num = Verify/ref_num(Pdf/get(old_trailer, "Root"))
    old_root = Pdf/get_obj(prefix, old, root_num)
    form_num = Verify/ref_num(Pdf/get(old_root, "AcroForm"))
    (ok, msg) = Verify/sections(pdf, prefix, old, root_num, form_num, sx, end, 64)
    if ok:
      return (1, Bytes/join([Bytes/from_string("covers a revision of "), Bytes/from_u24(end), Bytes/from_string(" bytes, later updates only add signatures")]))
    else:
      return (0, msg)

def Verify/ref_num(o: PdfObj) -> u24:
  match o:
    case PdfObj/Ref:
      return o.num
    case _:
      return 0

def Verify/sections(pdf: List(u24), prefix: List(u24), old, root_num: u24, form_num: u24, off: u24, end: u24, depth: u24) -> (u24, List(u24)):
  if (off < end) | (depth == 0):
    return (1, [])
  else:
    (entries, trailer) = Verify/section(pdf, off)
    (ok, msg) = Verify/entries(pdf, prefix, old, root_num, form_num, entries)
    if ok:
      if Pdf/has(trailer, "Prev"):
        return Verify/sections(pdf, prefix, old, root_num, form_num, Pdf/int(Pdf/get(trailer, "Prev")), end, depth - 1)
      else:
        return (1, [])
    else:
      return (0, msg)

def Verify/section(pdf: List(u24), off: u24):
  (is_table, xs) = Bytes/strip_prefix(Pdf/skip(Bytes/drop(pdf, off)), Bytes/from_string("xref"))
  if is_table:
    (entries, rest) = Pdf/classic_sections(xs)
    (*, after) = Bytes/strip_prefix(Pdf/skip(rest), Bytes/from_string("trailer"))
    (trailer, *) = Pdf/parse(after)
    return (entries, trailer)
  else:
    (*, sdict, sdata) = Pdf/read_indirect(xs)
    return (Pdf/stream_entries(sdict, sdata), sdict)

def Verify/entries(pdf: List(u24), prefix: List(u24), old, root_num: u24, form_num: u24, entries) -> (u24, List(u24)):
  match entries:
    case List/Nil:
      return (1, [])
    case List/Cons:
      (num, kind, a, *) = entries.head
      (ok, msg) = Verify/entry(pdf, prefix, old, root_num, form_num, num, kind, a)
      if ok:
        return Verify/entries(pdf, prefix, old, root_num, form_num, entries.tail)
      else:
        return (0, msg)

def Verify/entry(pdf: List(u24), prefix: List(u24), old, root_num: u24, form_num: u24, num: u24, kind: u24, a: u24) -> (u24, List(u24)):
  label = Bytes/concat(Bytes/from_string("object "), Bytes/from_u24(num))
  if kind == 0:
    if num == 0:
      return (1, [])
    else:
      return (0, Bytes/concat(label, Bytes/from_string(" deleted by a later update")))
  elif kind == 2:
    return (0, Bytes/concat(label, Bytes/from_string(" is compressed in a later update (not analyzed)")))
  else:
    (*, new, *) = Pdf/read_indirect(Bytes/drop(pdf, a))
    before = Pdf/get_obj(prefix, old, num)
    if Pdf/is_null(before):
      if Verify/added_ok(new):
        return (1, [])
      else:
        return (0, Bytes/concat(label, Bytes/from_string(" added by a later update is not a signature")))
    elif num == root_num:
      return Verify/same_except(before, new, "AcroForm", label)
    elif num == form_num:
      return Verify/same_except2(before, new, "Fields", "SigFlags", label)
    elif Pdf/name_is(Pdf/get(before, "Type"), "Page"):
      return Verify/same_except(before, new, "Annots", label)
    else:
      return (0, Bytes/concat(label, Bytes/from_string(" modified by a later update")))

def Verify/added_ok(o: PdfObj) -> u24:
  sig = Pdf/name_is(Pdf/get(o, "Type"), "Sig") | Pdf/has(o, "ByteRange")
  widget = Pdf/name_is(Pdf/get(o, "Subtype"), "Widget") & Pdf/name_is(Pdf/get(o, "FT"), "Sig")
  xref = Pdf/name_is(Pdf/get(o, "Type"), "XRef")
  return sig | widget | xref

def Verify/same_except(before: PdfObj, after: PdfObj, key: String, label: List(u24)) -> (u24, List(u24)):
  if Bytes/equal(Pdf/serialize(Verify/without(before, key)), Pdf/serialize(Verify/without(after, key))):
    return (1, [])
  else:
    return (0, Bytes/join([label, Bytes/from_string(" changed outside /"), Bytes/from_string(key)]))

def Verify/same_except2(before: PdfObj, after: PdfObj, k1: String, k2: String, label: List(u24)) -> (u24, List(u24)):
  return Verify/same_except(Verify/without(before, k1), Verify/without(after, k1), k2, label)

def Verify/without(o: PdfObj, key: String) -> PdfObj:
  match o:
    case PdfObj/Dict:
      return PdfObj/Dict(Verify/drop_key(o.entries, Bytes/from_string(key)))
    case _:
      return o

def Verify/drop_key(es: List((List(u24), PdfObj)), key: List(u24)) -> List((List(u24), PdfObj)):
  match es:
    case List/Nil:
      return []
    case List/Cons:
      (k, v) = es.head
      if Bytes/equal(k, key):
        return Verify/drop_key(es.tail, key)
      else:
        return List/Cons((k, v), Verify/drop_key(es.tail, key))
