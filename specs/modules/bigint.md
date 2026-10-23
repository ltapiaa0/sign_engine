# Module `lib/bigint.bend`

Arbitrary precision unsigned integers and modular arithmetic for RSA.

## Representation

A big integer is a little-endian `List(u24)` of 12-bit limbs (rule P-3).
Functions accept non-normalized inputs (high zero limbs); `BigInt/normalize`
removes them. The empty list is zero.

## API

### Conversion

| Function | Contract |
|---|---|
| `BigInt/from_bytes(bs)` | Big-endian bytes to a normalized big integer. Every 3 bytes become 2 limbs (`BigInt/from_le3`). |
| `BigInt/to_bytes(n, len)` | Big-endian bytes, left-padded with zeros to `len`. If the value needs more than `len` bytes the result is longer than `len`. |
| `BigInt/normalize(n)` | Removes high zero limbs. |
| `BigInt/fit(n, k)` | Exactly `k` limbs: pads with zeros or truncates (truncation drops high limbs). |
| `BigInt/bits_msb(n)` | Bits from the most significant (of the top limb, including its leading zeros) to the least significant. |
| `BigInt/bit_len(n) -> u24` | Number of significant bits; `0` for zero. |
| `BigInt/pow2(e)` | `2^e`. |
| `BigInt/head(xs)`, `BigInt/tail(xs)`, `BigInt/at(xs, i)` | Total list accessors (`0`, `[]`, `[]` when empty or out of range). |

### Arithmetic

| Function | Contract |
|---|---|
| `BigInt/cmp(a, b) -> u24` | `0` if `a < b`, `1` if equal, `2` if `a > b`. Normalizes both, compares lengths, then limbs from the top. |
| `BigInt/add(a, b)` | `a + b` (may contain a high zero limb only if inputs did). |
| `BigInt/sub(a, b)` | `a - b`, normalized. Requires `a ≥ b`. |
| `BigInt/mul(a, b)` | Schoolbook product, normalized. `BigInt/muladd(a, d, r, c)` computes `r + a·d + c` in one pass. |
| `BigInt/shl1(r, bit)` | `2·r + bit`, growing by one limb when needed. |
| `BigInt/mod(a, m)` | `a mod m` by binary long division: for each bit of `a` from the top, `r = 2r + bit`, subtract `m` when `r ≥ m`. Cost `O(bits(a) · limbs(m))`; used only on cold paths. |
| `BigInt/double_mod(r, times, m)` | Doubles `r` modulo `m` `times` times (`r < m`). |

### Montgomery arithmetic

For an odd modulus `n` with `k` limbs, `R = 2^(12k)`.

| Function | Contract |
|---|---|
| `BigInt/mont_ctx(n) -> (nk, k, ninv, r2, r3, nn)` | Context: `nn` = normalized `n`, `k` = limbs of `nn` plus one when the top limb is `≥ 0x400` (guarantees `4n < R`), `nk` = `nn` padded to `k` limbs, `ninv = -n^-1 mod 2^12`, `r2 = R^2 mod n` (`< n`), `r3 = R^3 mod n` (`< 2n`). Requires `n` odd and `n > 1`. |
| `BigInt/mont_mul(a, b, nk, ninv, k)` | `a·b·R^-1 mod n` as exactly `k` limbs, `< 2n`, for `a < R` and `b < 2n` (see bounds). |
| `BigInt/to_mont(x, ctx)` | `x·R mod n`, `< n`. |
| `BigInt/from_mont(y, ctx)` | `y·R^-1 mod n`, `< n`. |
| `BigInt/mod_ctx(x, ctx)` | `x mod n`. |
| `BigInt/mulmod_ctx(a, b, ctx)` | `a·b mod n` for `a, b < R^2`. |
| `BigInt/modexp_ctx(base, exp, ctx)` | `base^exp mod n`; `exp` is big-endian bytes; any `base`. |
| `BigInt/modexp(base, exp, n)` | `BigInt/modexp_ctx(base, exp, BigInt/mont_ctx(n))`. |
| `BigInt/reduce_once(x, n)` | `x mod n` for `x < 2n`. |
| `BigInt/reduce_small(x, n)` | `x mod n` by repeated subtraction (for `x` a small multiple of `n`). |

## Algorithms

### `ninv` (`BigInt/mont_ninv`)

Newton iteration for the inverse of `n0` (lowest limb, odd) modulo 2^12:
starting from `x = n0` (correct to 3 bits), `x ← x·(2 - n0·x) mod 2^12`
doubles the number of correct bits; four iterations are applied
(`BigInt/inv_step`). The result is negated modulo 2^12.

### Montgomery multiplication (CIOS)

The state of one multiplication is a list of `k + 1` pairs
`(t_j, b_j | n_j << 12)` built by `BigInt/pack(b, nk)` with `t = 0`; the last
pair has `b = n = 0` and holds the top limb of `t` (rule P-17).

For each limb `a_i` of `a` (`BigInt/mont_loop`):

- `BigInt/mont_row0` handles `j = 0`: `x = t_0 + a_i·b_0`,
  `m = (x mod 2^12)·ninv mod 2^12`, `y = (x mod 2^12) + m·n_0` (≡ 0 mod 2^12),
  carries `c1 = x >> 12`, `c2 = y >> 12`.
- `BigInt/mont_row` handles `j ≥ 1`:
  `x = t_j + a_i·b_j + c1`, `y = (x mod 2^12) + m·n_j + c2`, emits
  `(y mod 2^12, bn_{j-1})` and continues with `c1 = x >> 12`, `c2 = y >> 12`.
  Each of `x` and `y` is at most `(2^12-1) + (2^12-1)^2 + (2^12-1) = 2^24-1`,
  so two independent carry chains never overflow.
- After the last pair it emits `(c1 + c2, bn_k)`. Emitting each limb next to
  the previous position's `bn` performs the division by `2^12` of CIOS.

`BigInt/unpack(st, k)` returns the `k` low limbs of `t`.

Bounds: after processing `a`, `t < (a·b + R·n)/R`. With `a < R` and `b < 2n`
the result is `< 3n`; with `a, b < 2n` and `4n < R` it is `< 2n`, which also
guarantees that the top pair is zero and fits the `k` returned limbs. All
exponentiation inputs are kept `< 2n` so no intermediate subtraction is
needed.

### `R^2 mod n` without long division (`BigInt/mont_ctx`)

Let `b = bit_len(n)`. `2^(b-1) < n` is already reduced. `BigInt/double_mod`
doubles it `15k - (b-1)` times to obtain `c = 2^(15k) mod n`. Two Montgomery
squarings give `mont(c, c) = 2^(30k - 12k) = 2^(18k)` and
`mont(·, ·) = 2^(36k - 12k) = 2^(24k) = R^2`; `reduce_once` makes it `< n`.
`r3 = mont(r2, r2) = R^3 mod n` (`< 2n`).

### Entering Montgomery form (`BigInt/to_mont`)

For `x < R^2`, split `x = lo + hi·R` (`lo = take(x, k)`, `hi = drop(x, k)`):
`x·R ≡ mont(lo, r2) + mont(hi, r3)`. The first term is `< 2n`, the second
`< 3n`, so the sum is reduced with `BigInt/reduce_small` (at most four
subtractions). Inputs with more than `2k` limbs are first reduced with
`BigInt/mod`.

### Exponentiation (`BigInt/modexp_ctx`)

Fixed 4-bit window, left to right:

1. `bm = to_mont(base)`, `one = mont(1, r2) = R mod n`.
2. `table = [one, bm, bm^2, ..., bm^15]` (Montgomery form,
   `BigInt/mont_table`).
3. For each nibble of `strip_zeros(exp)` (`BigInt/nibbles`): four squarings
   (`BigInt/mont_sq4`) then one multiplication by `table[nibble]`, also for
   nibble `0` (multiplication by `one`), so the sequence of operations depends
   only on the exponent length.
4. `from_mont(acc)`.

An exponent of zero bytes yields `1 mod n`.


## Internal helpers

| Function | Purpose |
|---|---|
| `BigInt/to_le3(n)` | Limbs to little-endian bytes, two limbs (24 bits) per three bytes. |
| `BigInt/inv_step(n0, x)` | One Newton step `x·(2 - n0·x) mod 2^12`. |
| `BigInt/pack`, `BigInt/unpack` | Build the Montgomery state list and read back its `k` low limbs. |
| `BigInt/mont_row0`, `BigInt/mont_row`, `BigInt/mont_loop` | CIOS row for `j = 0`, rows for `j ≥ 1`, loop over the limbs of `a`. |
| `BigInt/mont_table`, `BigInt/mont_sq4`, `BigInt/nibbles` | Window table, four squarings, exponent nibbles. |

## Tests

`bigint_add`, `bigint_sub`, `bigint_mul`, `bigint_mod`, `bigint_modexp`
(256-bit modulus, 64-bit exponent, 200-bit base) and `bigint_to_bytes`;
RSA end-to-end tests exercise 512-bit and 1024-bit CRT moduli and the 2048-bit
public operation.
