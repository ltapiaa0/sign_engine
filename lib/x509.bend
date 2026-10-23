# lib/x509.bend
# Lectura de llaves privadas RSA (PKCS#1 / PKCS#8) y certificados X.509.

from lib/bytes import *
from lib/asn1 import *
from lib/rsa import *

# OID rsaEncryption 1.2.840.113549.1.1.1 (contenido)
def X509/OID_RSA() -> List(u24):
  return [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]

# OID commonName 2.5.4.3 (contenido)
def X509/OID_CN() -> List(u24):
  return [0x55, 0x04, 0x03]

# ---------------------------------------------------------------------------
# Llaves privadas
# ---------------------------------------------------------------------------

# Lee una llave privada RSA en DER o PEM (PKCS#1 "RSA PRIVATE KEY" o
# PKCS#8 "PRIVATE KEY" sin cifrar). Retorna Result(RsaKey, String).
def X509/read_rsa_key(input: List(u24)):
  der = Pem/decode(input)
  (tag, content, *, *) = Der/read(der)
  if tag != 0x30:
    return Result/Err("llave: no es una SEQUENCE DER")
  else:
    (t1, *, *) = Der/child(content, 1)
    if t1 == 0x30:
      # PKCS#8: SEQ { version, AlgorithmIdentifier, OCTET STRING(PKCS#1) }
      (*, alg, *) = Der/child(content, 1)
      (*, oid, *) = Der/child(alg, 0)
      if Bytes/equal(oid, X509/OID_RSA):
        (*, inner, *) = Der/child(content, 2)
        return X509/rsa_key_pkcs1(inner)
      else:
        return Result/Err("llave: algoritmo no soportado (sólo RSA)")
    elif t1 == 0x02:
      return X509/rsa_key_pkcs1(der)
    else:
      return Result/Err("llave: formato no reconocido (¿PKCS#8 cifrado?)")

# RSAPrivateKey ::= SEQ { version, n, e, d, p, q, dp, dq, qinv }
def X509/rsa_key_pkcs1(der: List(u24)):
  (tag, content, *, *) = Der/read(der)
  if tag != 0x30:
    return Result/Err("llave: RSAPrivateKey inválida")
  else:
    ints = X509/int_values(Der/children(content))
    if X509/count(ints) < 9:
      return Result/Err("llave: RSAPrivateKey incompleta")
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

# ---------------------------------------------------------------------------
# Certificados
# ---------------------------------------------------------------------------

type CertInfo:
  New { der, issuer, serial, subject_cn, n, e }

# Lee un certificado X.509 (DER o PEM) y extrae los datos necesarios para
# CMS: emisor (Name DER completo), número de serie (INTEGER DER completo),
# CN del sujeto y la llave pública RSA (n, e).
def X509/read_cert(input: List(u24)):
  der = Pem/decode(input)
  (tag, cert, *, *) = Der/read(der)
  if tag != 0x30:
    return Result/Err("certificado: no es una SEQUENCE DER")
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
    # BIT STRING: primer byte = bits sin usar (0), luego RSAPublicKey
    (*, pub, *, *) = Der/read(Bytes/drop(bitstr, 1))
    (*, n_body, *) = Der/child(pub, 0)
    (*, e_body, *) = Der/child(pub, 1)
    return Result/Ok(CertInfo/New(der, issuer, serial, X509/find_cn(Der/children(subject)), Der/int_value(n_body), Der/int_value(e_body)))

# Busca el atributo commonName dentro de un Name (lista de RDN SETs).
def X509/find_cn(rdns: List((u24, List(u24), List(u24)))) -> List(u24):
  match rdns:
    case List/Nil:
      return []
    case List/Cons:
      (*, set_body, *) = rdns.head
      (*, atv, *) = Der/child(set_body, 0)
      (*, oid, *) = Der/child(atv, 0)
      if Bytes/equal(oid, X509/OID_CN):
        (*, value, *) = Der/child(atv, 1)
        return value
      else:
        return X509/find_cn(rdns.tail)
