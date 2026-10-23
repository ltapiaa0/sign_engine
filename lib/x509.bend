from lib/bytes import *
from lib/text import *
from lib/asn1 import *
from lib/rsa import *

def X509/OID_RSA() -> List(u24):
  return [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]

def X509/OID_CN() -> List(u24):
  return [0x55, 0x04, 0x03]

def X509/is_key_label(label: List(u24)) -> u24:
  return Pem/is_label(label, "RSA PRIVATE KEY") | Pem/is_label(label, "PRIVATE KEY") | Pem/is_label(label, "")

def X509/is_cert_label(label: List(u24)) -> u24:
  return Pem/is_label(label, "CERTIFICATE") | Pem/is_label(label, "")

def X509/has_secret(label: List(u24)) -> u24:
  return Bytes/find(label, Bytes/from_string("PRIVATE KEY")) != Bytes/NONE

def X509/first_key(blocks: List((List(u24), List(u24))), encrypted: u24):
  match blocks:
    case List/Nil:
      if encrypted:
        return Result/Err("key: encrypted private keys are not supported")
      else:
        return Result/Err("key: no private key found")
    case List/Cons:
      (label, der) = blocks.head
      if X509/is_key_label(label):
        return Result/Ok(der)
      else:
        return X509/first_key(blocks.tail, encrypted | Pem/is_label(label, "ENCRYPTED PRIVATE KEY"))

def X509/read_rsa_key(input: List(u24)):
  match found = X509/first_key(Pem/decode_all(input), 0):
    case Result/Err:
      return Result/Err(found.val)
    case Result/Ok:
      return X509/rsa_key_der(found.val)

def X509/rsa_key_der(der: List(u24)):
  (tag, content, *, *) = Der/read(der)
  if tag != 0x30:
    return Result/Err("key: not a DER SEQUENCE")
  else:
    (t1, *, *) = Der/child(content, 1)
    if t1 == 0x30:
      (*, alg, *) = Der/child(content, 1)
      (*, oid, *) = Der/child(alg, 0)
      if Bytes/equal(oid, X509/OID_RSA):
        (*, inner, *) = Der/child(content, 2)
        return X509/rsa_key_pkcs1(inner)
      else:
        return Result/Err("key: unsupported algorithm (RSA only)")
    elif t1 == 0x02:
      return X509/rsa_key_pkcs1(der)
    else:
      return Result/Err("key: unrecognized format (encrypted PKCS#8?)")

def X509/cert_ders(input: List(u24)):
  blocks = Pem/decode_all(input)
  if X509/any_secret(blocks):
    return Result/Err("certificate: the certificate file must not contain a private key")
  else:
    match certs = X509/cert_blocks(blocks):
      case List/Nil:
        return Result/Err("certificate: no certificate found")
      case List/Cons:
        return Result/Ok(List/Cons(certs.head, certs.tail))

def X509/any_secret(blocks: List((List(u24), List(u24)))) -> u24:
  match blocks:
    case List/Nil:
      return 0
    case List/Cons:
      (label, *) = blocks.head
      return X509/has_secret(label) | X509/any_secret(blocks.tail)

def X509/cert_blocks(blocks: List((List(u24), List(u24)))) -> List(List(u24)):
  match blocks:
    case List/Nil:
      return []
    case List/Cons:
      (label, der) = blocks.head
      if X509/is_cert_label(label):
        return List/Cons(der, X509/cert_blocks(blocks.tail))
      else:
        return X509/cert_blocks(blocks.tail)

def X509/rsa_key_pkcs1(der: List(u24)):
  (tag, content, *, *) = Der/read(der)
  if tag != 0x30:
    return Result/Err("key: invalid RSAPrivateKey")
  else:
    ints = X509/int_values(Der/children(content))
    if X509/count(ints) < 9:
      return Result/Err("key: incomplete RSAPrivateKey")
    else:
      n = X509/nth(ints, 1)
      e = X509/nth(ints, 2)
      d = X509/nth(ints, 3)
      p = X509/nth(ints, 4)
      q = X509/nth(ints, 5)
      dp = X509/nth(ints, 6)
      dq = X509/nth(ints, 7)
      qinv = X509/nth(ints, 8)
      return Result/Ok(RsaKey/new(n, e, d, p, q, dp, dq, qinv))

def X509/int_values(xs: List((u24, List(u24), List(u24)))) -> List(List(u24)):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      (*, body, *) = xs.head
      return List/Cons(Der/int_value(body), X509/int_values(xs.tail))

def X509/nth(xs: List(List(u24)), i: u24) -> List(u24):
  match xs:
    case List/Nil:
      return []
    case List/Cons:
      if i == 0:
        return xs.head
      else:
        return X509/nth(xs.tail, i - 1)

def X509/count(xs) -> u24:
  match xs:
    case List/Nil:
      return 0
    case List/Cons:
      return 1 + X509/count(xs.tail)

type CertInfo:
  New { der, issuer, serial, subject_cn, n, e }

def X509/read_cert(input: List(u24)):
  match ders = X509/cert_ders(input):
    case Result/Err:
      return Result/Err(ders.val)
    case Result/Ok:
      match list = ders.val:
        case List/Nil:
          return Result/Err("certificate: no certificate found")
        case List/Cons:
          return X509/read_cert_der(list.head)

def X509/read_cert_der(input: List(u24)):
  (tag, cert, der, *) = Der/read(input)
  if tag != 0x30:
    return Result/Err("certificate: not a DER SEQUENCE")
  else:
    (*, tbs, *) = Der/child(cert, 0)
    (t0, *, *) = Der/child(tbs, 0)
    if t0 == 0xA0:
      off = 1
    else:
      off = 0
    (*, *, serial) = Der/child(tbs, off)
    (*, *, issuer) = Der/child(tbs, off + 2)
    (*, subject, *) = Der/child(tbs, off + 4)
    (*, spki, *) = Der/child(tbs, off + 5)
    (*, bitstr, *) = Der/child(spki, 1)
    (*, pub, *, *) = Der/read(Bytes/drop(bitstr, 1))
    (*, n_body, *) = Der/child(pub, 0)
    (*, e_body, *) = Der/child(pub, 1)
    return Result/Ok(CertInfo/New(der, issuer, serial, X509/find_cn(Der/children(subject)), Der/int_value(n_body), Der/int_value(e_body)))

def X509/find_cn(rdns: List((u24, List(u24), List(u24)))) -> List(u24):
  match rdns:
    case List/Nil:
      return []
    case List/Cons:
      (*, set_body, *) = rdns.head
      match found = X509/find_cn_atv(Der/children(set_body)):
        case List/Nil:
          return X509/find_cn(rdns.tail)
        case List/Cons:
          return found

def X509/find_cn_atv(atvs: List((u24, List(u24), List(u24)))) -> List(u24):
  match atvs:
    case List/Nil:
      return []
    case List/Cons:
      (*, atv, *) = atvs.head
      (*, oid, *) = Der/child(atv, 0)
      if Bytes/equal(oid, X509/OID_CN):
        (tag, value, *) = Der/child(atv, 1)
        return X509/text_utf8(tag, value)
      else:
        return X509/find_cn_atv(atvs.tail)

def X509/text_utf8(tag: u24, value: List(u24)) -> List(u24):
  if tag == 0x1E:
    return Text/utf8_encode(Text/utf16be_decode(value))
  elif tag == 0x1C:
    return Text/utf8_encode(Text/utf32be_decode(value))
  elif tag == 0x14:
    return Text/utf8_encode(value)
  else:
    return value
