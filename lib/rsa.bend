from lib/bytes import *
from lib/bigint import *

type RsaKey:
  New { n, e, d, p, q, dp, dq, qinv }

def RsaKey/new(n, e, d, p, q, dp, dq, qinv):
  return RsaKey/New(n, e, d, p, q, dp, dq, qinv)

def Rsa/SHA256_PREFIX() -> List(u24):
  return [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]

def Rsa/modulus_len(key: RsaKey) -> u24:
  open RsaKey: key
  return Bytes/len(Bytes/strip_zeros(key.n))

def Rsa/emsa_pkcs1_v15(hash: List(u24), k: u24) -> List(u24):
  t = Bytes/concat(Rsa/SHA256_PREFIX, hash)
  ps = k - Bytes/len(t) - 3
  return Bytes/concat([0x00, 0x01], Bytes/concat(Bytes/repeat(0xFF, ps), List/Cons(0x00, t)))

def Rsa/private_op(key: RsaKey, m: List(u24)) -> List(u24):
  open RsaKey: key
  p = BigInt/from_bytes(key.p)
  q = BigInt/from_bytes(key.q)
  ctxp = BigInt/mont_ctx(p)
  ctxq = BigInt/mont_ctx(q)
  m1 = BigInt/modexp_ctx(m, key.dp, ctxp)
  m2 = BigInt/modexp_ctx(m, key.dq, ctxq)
  m2p = BigInt/mod_ctx(m2, ctxp)
  if BigInt/cmp(m1, m2p) == 0:
    diff = BigInt/sub(BigInt/add(m1, p), m2p)
  else:
    diff = BigInt/sub(m1, m2p)
  h = BigInt/mulmod_ctx(BigInt/from_bytes(key.qinv), diff, ctxp)
  return BigInt/add(m2, BigInt/mul(h, q))

def Rsa/public_op(n: List(u24), e: List(u24), s: List(u24)) -> List(u24):
  return BigInt/modexp(s, e, BigInt/from_bytes(n))

def Rsa/sign_hash(key: RsaKey, hash: List(u24)) -> List(u24):
  k = Rsa/modulus_len(key)
  em = BigInt/from_bytes(Rsa/emsa_pkcs1_v15(hash, k))
  return BigInt/to_bytes(Rsa/private_op(key, em), k)

def Rsa/verify_hash(n: List(u24), e: List(u24), hash: List(u24), sig: List(u24)) -> u24:
  k = Bytes/len(Bytes/strip_zeros(n))
  em = BigInt/to_bytes(Rsa/public_op(n, e, BigInt/from_bytes(sig)), k)
  return Bytes/equal(em, Rsa/emsa_pkcs1_v15(hash, k))

def Rsa/MIN_MODULUS_LEN() -> u24:
  return 62

def Rsa/sign_hash_checked(key: RsaKey, hash: List(u24)):
  open RsaKey: key
  n = key.n
  e = key.e
  if Rsa/modulus_len(key) < Rsa/MIN_MODULUS_LEN:
    return Result/Err("rsa: modulus too small")
  else:
    sig = Rsa/sign_hash(key, hash)
    if Rsa/verify_hash(n, e, hash, sig):
      return Result/Ok(sig)
    else:
      return Result/Err("rsa: signature self-check failed")
