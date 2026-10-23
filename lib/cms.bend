# lib/cms.bend
# Construcción de CMS SignedData (RFC 5652) "detached", con los atributos
# firmados que exige CAdES-BES / PAdES B-B:
#   - contentType          (id-data)
#   - messageDigest        (SHA-256 del contenido)
#   - signingCertificateV2 (SHA-256 del certificado del firmante, RFC 5035)
#
# El flujo es en dos pasos para permitir firmar fuera de Bend (HSM, token):
#   1. Cms/signed_attrs(digest, cert_der)  -> atributos (lista DER)
#      Cms/to_be_signed(attrs)             -> bytes que se firman (SET OF DER)
#   2. Cms/assemble(cert, chain, attrs, firma) -> ContentInfo DER

from lib/bytes import *
from lib/asn1 import *
from lib/sha256 import *
from lib/x509 import *

# ---------------------------------------------------------------------------
# OIDs (contenido codificado)
# ---------------------------------------------------------------------------

def Cms/OID_SIGNED_DATA() -> List(u24):
  return [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]

def Cms/OID_DATA() -> List(u24):
  return [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]

def Cms/OID_SHA256() -> List(u24):
  return [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]

def Cms/OID_RSA() -> List(u24):
  return [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]

def Cms/OID_CONTENT_TYPE() -> List(u24):
  return [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03]

def Cms/OID_MESSAGE_DIGEST() -> List(u24):
  return [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04]

def Cms/OID_SIGNING_CERT_V2() -> List(u24):
  return [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f]

# AlgorithmIdentifier { oid, NULL }
def Cms/alg_id(oid: List(u24)) -> List(u24):
  return Der/seq([Der/oid(oid), Der/null])

# Constantes DER precalculadas como literales de bytes.
# Importante en Bend/HVM: una expresión cerrada que llama funciones (p. ej.
# `Cms/alg_id(Cms/OID_SHA256)`) se extrae como definición global, y HVM
# aborta si debe duplicarla antes de evaluarla ("attempt to clone a
# non-affine global reference"). Los literales de datos sí se pueden duplicar.

# AlgorithmIdentifier { sha256, NULL }
def Cms/ALG_SHA256() -> List(u24):
  return [0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00]

# AlgorithmIdentifier { rsaEncryption, NULL }
def Cms/ALG_RSA() -> List(u24):
  return [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]

# Attribute { contentType, SET { id-data } }
def Cms/ATTR_CONTENT_TYPE() -> List(u24):
  return [0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03, 0x31, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]

# EncapsulatedContentInfo { id-data } (contenido "detached")
def Cms/ENCAP_DATA() -> List(u24):
  return [0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]

# INTEGER 1
def Cms/INT_1() -> List(u24):
  return [0x02, 0x01, 0x01]

# ---------------------------------------------------------------------------
# Atributos firmados
# ---------------------------------------------------------------------------

def Cms/attribute(oid: List(u24), value: List(u24)) -> List(u24):
  return Der/seq([Der/oid(oid), Der/set([value])])

# Lista de atributos firmados (cada uno codificado en DER).
def Cms/signed_attrs(digest: List(u24), cert_der: List(u24)) -> List(List(u24)):
  ct = Cms/ATTR_CONTENT_TYPE
  md = Cms/attribute(Cms/OID_MESSAGE_DIGEST, Der/octet_string(digest))
  # SigningCertificateV2 ::= SEQ { SEQ OF ESSCertIDv2 }
  # ESSCertIDv2 ::= SEQ { certHash OCTET STRING }  (hashAlgorithm = sha256 por defecto)
  ess = Der/seq([Der/seq([Der/seq([Der/octet_string(Sha256/digest(cert_der))])])])
  sc = Cms/attribute(Cms/OID_SIGNING_CERT_V2, ess)
  return [ct, md, sc]

# Bytes sobre los que se calcula la firma: los atributos como SET OF (tag 0x31).
def Cms/to_be_signed(attrs: List(List(u24))) -> List(u24):
  return Der/set(attrs)

# ---------------------------------------------------------------------------
# SignedData
# ---------------------------------------------------------------------------

# Arma el ContentInfo final.
#   cert:      CertInfo del firmante
#   chain:     lista de certificados DER adicionales (intermedios), puede ser []
#   attrs:     atributos devueltos por Cms/signed_attrs
#   signature: firma RSA PKCS#1 v1.5 sobre Cms/to_be_signed(attrs)
def Cms/assemble(cert, chain: List(List(u24)), attrs: List(List(u24)), signature: List(u24)) -> List(u24):
  open CertInfo: cert
  sha256 = Cms/ALG_SHA256
  # [0] IMPLICIT SignedAttributes: mismo contenido que el SET, con tag 0xA0
  signed_attrs = Der/tlv(0xA0, Bytes/join(Bytes/sort(attrs)))
  signer_info = Der/seq([
    Cms/INT_1,
    Der/seq([cert.issuer, cert.serial]),
    sha256,
    signed_attrs,
    Cms/ALG_RSA,
    Der/octet_string(signature)
  ])
  certs = Der/tlv(0xA0, Bytes/concat(cert.der, Bytes/join(chain)))
  signed_data = Der/seq([
    Cms/INT_1,
    Der/set([sha256]),
    Cms/ENCAP_DATA,
    certs,
    Der/set([signer_info])
  ])
  return Der/seq([Der/oid(Cms/OID_SIGNED_DATA), Der/ctx(0, signed_data)])
