# Module `lib/rsa.bend`

RSA signatures with EMSA-PKCS1-v1_5 encoding and SHA-256 (RFC 8017 §8.2,
§9.2).

## Types

```
type RsaKey:
  New { n, e, d, p, q, dp, dq, qinv }
```

Every field is a big-endian byte string without leading zeros, as read from
an `RSAPrivateKey` structure. `RsaKey/new(...)` is the exported constructor.
`d` is kept for completeness; the private operation uses the CRT parameters.

## API

| Function | Contract |
|---|---|
| `Rsa/modulus_len(key) -> u24` | Length of `n` in bytes (`k`). |
| `Rsa/emsa_pkcs1_v15(hash, k)` | `00 01 FF..FF 00 ‖ DigestInfo(SHA-256) ‖ hash`, exactly `k` bytes. Requires `k ≥ 62` (51 bytes of DigestInfo, 3 separator bytes and at least 8 bytes of `FF` padding). |
| `Rsa/private_op(key, m)` | `m^d mod n` using CRT (big integers). |
| `Rsa/public_op(n, e, s)` | `s^e mod n` (`n`, `e` as bytes). |
| `Rsa/sign_hash(key, hash)` | Signature of a 32-byte SHA-256 hash, `k` bytes. |
| `Rsa/verify_hash(n, e, hash, sig) -> u24` | `1` when `sig^e mod n` equals the expected encoded message. |
| `Rsa/sign_hash_checked(key, hash)` | `Result/Ok(signature)` after verifying it with `(n, e)`; `Result/Err("rsa: modulus too small")` when `k < Rsa/MIN_MODULUS_LEN` (62); `Result/Err("rsa: signature self-check failed")` when the verification fails (FR-7, NFR-5). |

`Rsa/SHA256_PREFIX` is the DER `DigestInfo` header for SHA-256:
`30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20`.

## Private operation (CRT)

```
ctx_p = mont_ctx(p), ctx_q = mont_ctx(q)
m1 = m^dp mod p            (modexp_ctx, independent of m2: evaluated in parallel by HVM)
m2 = m^dq mod q
h  = qinv · (m1 - (m2 mod p)) mod p      (adding p first when m1 < m2 mod p)
s  = m2 + h·q
```

`m` is the encoded message as a big integer (`< n < R_p^2`), so reducing it
modulo `p` and `q` uses `BigInt/to_mont` without long division.

## Tests

`emsa_len` in `test.bend`; signatures were checked byte-for-byte against
`openssl dgst -sha256 -sign` during development; every end-to-end signature is
self-verified and validated by `openssl cms -verify`, `pdfsig` and the Bend
verifier.
