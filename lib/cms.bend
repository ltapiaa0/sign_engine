from lib/bytes import *
from lib/asn1 import *
from lib/sha256 import *
from lib/x509 import *

def Cms/OID_SIGNED_DATA() -> List(u24):
  return [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]

def Cms/OID_MESSAGE_DIGEST() -> List(u24):
  return [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04]

def Cms/OID_SIGNING_CERT_V2() -> List(u24):
  return [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f]

def Cms/ALG_SHA256() -> List(u24):
  return [0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00]

def Cms/ALG_RSA() -> List(u24):
  return [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]

def Cms/ATTR_CONTENT_TYPE() -> List(u24):
  return [0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03, 0x31, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]

def Cms/ENCAP_DATA() -> List(u24):
  return [0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]

def Cms/INT_1() -> List(u24):
  return [0x02, 0x01, 0x01]

def Cms/attribute(oid: List(u24), value: List(u24)) -> List(u24):
  return Der/seq([Der/oid(oid), Der/set([value])])

def Cms/signed_attrs(digest: List(u24), cert_der: List(u24)) -> List(List(u24)):
  ct = Cms/ATTR_CONTENT_TYPE
  md = Cms/attribute(Cms/OID_MESSAGE_DIGEST, Der/octet_string(digest))
  ess = Der/seq([Der/seq([Der/seq([Der/octet_string(Sha256/digest(cert_der))])])])
  sc = Cms/attribute(Cms/OID_SIGNING_CERT_V2, ess)
  return [ct, md, sc]

def Cms/to_be_signed(attrs: List(List(u24))) -> List(u24):
  return Der/set(attrs)

def Cms/assemble(cert, chain: List(List(u24)), attrs: List(List(u24)), signature: List(u24)) -> List(u24):
  open CertInfo: cert
  sha256 = Cms/ALG_SHA256
  signed_attrs = Der/tlv(0xA0, Bytes/join(Bytes/sort(attrs)))
  signer_info = Der/seq([
    Cms/INT_1,
    Der/seq([cert.issuer, cert.serial]),
    sha256,
    signed_attrs,
    Cms/ALG_RSA,
    Der/octet_string(signature)
  ])
  certs = Der/tlv(0xA0, Bytes/join(Bytes/sort(List/Cons(cert.der, chain))))
  signed_data = Der/seq([
    Cms/INT_1,
    Der/set([sha256]),
    Cms/ENCAP_DATA,
    certs,
    Der/set([signer_info])
  ])
  return Der/seq([Der/oid(Cms/OID_SIGNED_DATA), Der/ctx(0, signed_data)])
