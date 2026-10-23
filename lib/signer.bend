# lib/signer.bend
# Orquestación de la firma de un PDF: une las librerías pdf, cms, rsa y x509.
#
#   Signer/sign_pdf(pdf, key, certs, params) -> Result(pdf_firmado, error)
#
# `params` es un texto "clave=valor" por línea (UTF-8):
#   name=...       nombre del firmante (por defecto, el CN del certificado)
#   reason=...     motivo
#   location=...   lugar
#   contact=...    contacto
#   time=YYYYMMDDHHmmSS   hora UTC de la firma (/M)
#   sig_size=N     bytes reservados para el CMS (por defecto 8192)

from lib/bytes import *
from lib/sha256 import *
from lib/rsa import *
from lib/asn1 import *
from lib/x509 import *
from lib/cms import *
from lib/pdf import *

# ---------------------------------------------------------------------------
# Parámetros
# ---------------------------------------------------------------------------

# Lista de (clave, valor) a partir del texto de parámetros.
def Signer/parse_params(text: List(u24)) -> List((List(u24), List(u24))):
  return Signer/parse_lines(Bytes/lines(text))

def Signer/parse_lines(lines: List(List(u24))) -> List((List(u24), List(u24))):
  match lines:
    case List/Nil:
      return []
    case List/Cons:
      line = lines.head
      eq = Bytes/find(line, ['='])
      if eq == Bytes/NONE:
        return Signer/parse_lines(lines.tail)
      else:
        key = Bytes/trim(Bytes/take(line, eq))
        val = Bytes/trim(Bytes/drop(line, eq + 1))
        return List/Cons((key, val), Signer/parse_lines(lines.tail))

def Signer/param(ps: List((List(u24), List(u24))), key: String) -> List(u24):
  return Signer/param.go(ps, Bytes/from_string(key))

def Signer/param.go(ps: List((List(u24), List(u24))), key: List(u24)) -> List(u24):
  match ps:
    case List/Nil:
      return []
    case List/Cons:
      (k, v) = ps.head
      if Bytes/equal(k, key):
        return v
      else:
        return Signer/param.go(ps.tail, key)

def Signer/or_default(v: List(u24), d: List(u24)) -> List(u24):
  match v:
    case List/Nil:
      return d
    case List/Cons:
      return v

def Signer/DEFAULT_SIG_SIZE() -> u24:
  return 8192

# ---------------------------------------------------------------------------
# Firma
# ---------------------------------------------------------------------------

# Primer elemento y resto de una lista de certificados.
def Signer/split_certs(certs: List(List(u24))) -> (List(u24), List(List(u24))):
  match certs:
    case List/Nil:
      return ([], [])
    case List/Cons:
      return (certs.head, certs.tail)

# Firma un PDF. `key_bytes` y `cert_bytes` en PEM o DER; el PEM de
# certificados puede traer la cadena completa (firmante primero).
def Signer/sign_pdf(pdf: List(u24), key_bytes: List(u24), cert_bytes: List(u24), params_text: List(u24)):
  match key = X509/read_rsa_key(key_bytes):
    case Result/Err:
      return Result/Err(key.val)
    case Result/Ok:
      (signer_der, chain) = Signer/split_certs(Pem/decode_all(cert_bytes))
      match cert = X509/read_cert(signer_der):
        case Result/Err:
          return Result/Err(cert.val)
        case Result/Ok:
          match info = Pdf/analyze(pdf):
            case Result/Err:
              return Result/Err(info.val)
            case Result/Ok:
              return Signer/sign_with(pdf, info.val, key.val, cert.val, chain, Signer/parse_params(params_text))

def Signer/sign_with(pdf: List(u24), info, key, cert, chain: List(List(u24)), ps):
  open CertInfo: cert
  open RsaKey: key
  if Bytes/equal(Bytes/strip_zeros(key.n), Bytes/strip_zeros(cert.n)) == 0:
    return Result/Err("la llave privada no corresponde al certificado")
  else:
    (size_v, size_n, *) = Bytes/parse_u24(Signer/param(ps, "sig_size"))
    if size_n == 0:
      sig_len = Signer/DEFAULT_SIG_SIZE
    else:
      sig_len = size_v
    fields = SigFields/new(Signer/or_default(Signer/param(ps, "name"), cert.subject_cn), Signer/param(ps, "reason"), Signer/param(ps, "location"), Signer/param(ps, "contact"), Signer/param(ps, "time"))
    (a, c, covered) = Pdf/prepare(pdf, info, fields, sig_len)
    attrs = Cms/signed_attrs(Sha256/digest(covered), cert.der)
    match sig = Rsa/sign_hash_checked(key, Sha256/digest(Cms/to_be_signed(attrs))):
      case Result/Err:
        return Result/Err(sig.val)
      case Result/Ok:
        return Pdf/finish(pdf, a, c, Cms/assemble(cert, chain, attrs, sig.val), sig_len)
