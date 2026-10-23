# lib/rsa.bend
# Firmas RSA PKCS#1 v1.5 (RFC 8017, sección 8.2) con SHA-256.
#
# La llave privada se representa como un objeto con los enteros de la
# llave en bytes big-endian (tal como vienen en el DER), y la operación
# privada usa el Teorema Chino del Resto (CRT): las dos exponenciaciones
# módulo p y módulo q son independientes, por lo que HVM puede evaluarlas
# en paralelo.

from lib/bytes import *
from lib/bigint import *

# Se usa `type` de un solo constructor en vez de `object`: en Bend 0.2.38
# los `object` construidos dentro de un módulo importado transitivamente
# hacen fallar al compilador.
type RsaKey:
  New { n, e, d, p, q, dp, dq, qinv }

def RsaKey/new(n, e, d, p, q, dp, dq, qinv):
  return RsaKey/New(n, e, d, p, q, dp, dq, qinv)

# DigestInfo DER para SHA-256 (prefijo antes de los 32 bytes del hash).
def Rsa/SHA256_PREFIX() -> List(u24):
  return [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]

# Longitud en bytes del módulo.
def Rsa/modulus_len(key: RsaKey) -> u24:
  open RsaKey: key
  return Bytes/len(Bytes/strip_zeros(key.n))

# EMSA-PKCS1-v1_5: 00 01 FF..FF 00 || DigestInfo(SHA-256, hash)
def Rsa/emsa_pkcs1_v15(hash: List(u24), k: u24) -> List(u24):
  t = Bytes/concat(Rsa/SHA256_PREFIX, hash)
  ps = k - Bytes/len(t) - 3
  return Bytes/concat([0x00, 0x01], Bytes/concat(Bytes/repeat(0xFF, ps), List/Cons(0x00, t)))

# Operación privada RSA con CRT: m^d mod n.
def Rsa/private_op(key: RsaKey, m: List(u24)) -> List(u24):
  open RsaKey: key
  p = BigInt/from_bytes(key.p)
  q = BigInt/from_bytes(key.q)
  ctxp = BigInt/mont_ctx(p)
  ctxq = BigInt/mont_ctx(q)
  # Las dos exponenciaciones son independientes: HVM puede hacerlas en paralelo.
  m1 = BigInt/modexp_ctx(m, key.dp, ctxp)
  m2 = BigInt/modexp_ctx(m, key.dq, ctxq)
  # h = qinv * (m1 - m2) mod p
  m2p = BigInt/mod_ctx(m2, ctxp)
  if BigInt/cmp(m1, m2p) == 0:
    diff = BigInt/sub(BigInt/add(m1, p), m2p)
  else:
    diff = BigInt/sub(m1, m2p)
  h = BigInt/mulmod_ctx(BigInt/from_bytes(key.qinv), diff, ctxp)
  return BigInt/add(m2, BigInt/mul(h, q))

# Operación pública: s^e mod n.
def Rsa/public_op(n: List(u24), e: List(u24), s: List(u24)) -> List(u24):
  return BigInt/modexp(s, e, BigInt/from_bytes(n))

# Firma un hash SHA-256 (32 bytes). Retorna la firma de k bytes.
def Rsa/sign_hash(key: RsaKey, hash: List(u24)) -> List(u24):
  k = Rsa/modulus_len(key)
  em = BigInt/from_bytes(Rsa/emsa_pkcs1_v15(hash, k))
  return BigInt/to_bytes(Rsa/private_op(key, em), k)

# Verifica una firma PKCS#1 v1.5 sobre un hash SHA-256 (1 si es válida).
def Rsa/verify_hash(n: List(u24), e: List(u24), hash: List(u24), sig: List(u24)) -> u24:
  k = Bytes/len(Bytes/strip_zeros(n))
  em = BigInt/to_bytes(Rsa/public_op(n, e, BigInt/from_bytes(sig)), k)
  return Bytes/equal(em, Rsa/emsa_pkcs1_v15(hash, k))

# Firma y verifica con la llave pública antes de devolver la firma, como
# contramedida ante fallos de cómputo (un error en CRT filtraría la llave).
# Retorna Result/Ok(firma) o Result/Err(mensaje).
def Rsa/sign_hash_checked(key: RsaKey, hash: List(u24)):
  open RsaKey: key
  n = key.n
  e = key.e
  sig = Rsa/sign_hash(key, hash)
  if Rsa/verify_hash(n, e, hash, sig):
    return Result/Ok(sig)
  else:
    return Result/Err("rsa: la verificación de la firma falló")
