from lib/bytes import *
from lib/sha256 import *
from lib/rsa import *
from lib/asn1 import *
from lib/x509 import *
from lib/cms import *
from lib/pdf import *

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

def Signer/MAX_SIG_SIZE() -> u24:
  return 0x40000

def Signer/sig_size(ps: List((List(u24), List(u24)))) -> u24:
  (value, digits, *) = Bytes/parse_u24(Signer/param(ps, "sig_size"))
  if digits == 0:
    return Signer/DEFAULT_SIG_SIZE
  else:
    return value

def Signer/longer_than(xs: List(u24), n: u24) -> u24:
  match Bytes/drop(xs, n):
    case List/Nil:
      return 0
    case List/Cons:
      return 1

def Signer/split_certs(certs: List(List(u24))) -> (List(u24), List(List(u24))):
  match certs:
    case List/Nil:
      return ([], [])
    case List/Cons:
      return (certs.head, certs.tail)

def Signer/valid_chain(chain: List(List(u24))) -> u24:
  match chain:
    case List/Nil:
      return 1
    case List/Cons:
      match cert = X509/read_cert_der(chain.head):
        case Result/Ok:
          return Signer/valid_chain(chain.tail)
        case Result/Err:
          return 0

def Signer/sign_pdf(pdf: List(u24), key_bytes: List(u24), cert_bytes: List(u24), params_text: List(u24)):
  match key = X509/read_rsa_key(key_bytes):
    case Result/Err:
      return Result/Err(key.val)
    case Result/Ok:
      match ders = X509/cert_ders(cert_bytes):
        case Result/Err:
          return Result/Err(ders.val)
        case Result/Ok:
          (signer_der, chain) = Signer/split_certs(ders.val)
          match cert = X509/read_cert_der(signer_der):
            case Result/Err:
              return Result/Err(cert.val)
            case Result/Ok:
              if Signer/valid_chain(chain) == 0:
                return Result/Err("certificate: invalid certificate in the chain")
              else:
                return Signer/sign_checked(pdf, key.val, cert.val, chain, Signer/parse_params(params_text))

def Signer/sign_checked(pdf: List(u24), key, cert, chain: List(List(u24)), ps):
  sig_len = Signer/sig_size(ps)
  if (sig_len < 1024) | (sig_len > Signer/MAX_SIG_SIZE):
    return Result/Err("signer: sig_size must be between 1024 and 262144")
  elif Signer/longer_than(pdf, 0xFFFFFF - 0x10000 - 2 * sig_len):
    return Result/Err("pdf: document too large (limit 16 MiB)")
  else:
    match info = Pdf/analyze(pdf):
      case Result/Err:
        return Result/Err(info.val)
      case Result/Ok:
        return Signer/sign_with(pdf, info.val, key, cert, chain, ps, sig_len)

def Signer/sign_with(pdf: List(u24), info, key, cert, chain: List(List(u24)), ps, sig_len: u24):
  open CertInfo: cert
  open RsaKey: key
  if Bytes/equal(Bytes/strip_zeros(key.n), Bytes/strip_zeros(cert.n)) == 0:
    return Result/Err("signer: private key does not match the certificate")
  else:
    fields = SigFields/new(Signer/or_default(Signer/param(ps, "name"), cert.subject_cn), Signer/param(ps, "reason"), Signer/param(ps, "location"), Signer/param(ps, "contact"), Signer/param(ps, "time"))
    (a, c, covered) = Pdf/prepare(pdf, info, fields, sig_len)
    attrs = Cms/signed_attrs(Sha256/digest(covered), cert.der)
    match sig = Rsa/sign_hash_checked(key, Sha256/digest(Cms/to_be_signed(attrs))):
      case Result/Err:
        return Result/Err(sig.val)
      case Result/Ok:
        return Pdf/finish(pdf, a, c, Cms/assemble(cert, chain, attrs, sig.val), sig_len)
