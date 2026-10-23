# Module `lib/inflate.bend`

DEFLATE decompression (RFC 1951), the zlib wrapper (RFC 1950) and PNG row
predictors (RFC 2083 §6), as needed for PDF cross-reference streams and object
streams.

## API

| Function | Contract |
|---|---|
| `Inflate/zlib(xs)` | Skips the 2-byte zlib header and inflates the rest. The Adler-32 trailer is ignored. |
| `Inflate/raw(xs)` | Inflates a raw DEFLATE stream (stored, fixed and dynamic Huffman blocks) until the final block or the end of input. |
| `Png/unfilter(data, columns, bpp)` | Reverses PNG filtering for rows of `columns` bytes, each preceded by its filter type (0 None, 1 Sub, 2 Up, 3 Average, 4 Paeth); `bpp` is bytes per pixel. |

## Design

- **Bit reader.** State `(bytes, buffer, count, overrun)`;
  `Inflate/bits(s, n)` returns the next `n ≤ 16` bits LSB-first. Reading past
  the end supplies zero bits and increments `overrun`. `Inflate/align` drops
  the bits up to the next byte boundary (stored blocks).
- **Huffman tables.** `Inflate/build(lengths)` assigns canonical codes
  (RFC 1951 §3.2.2): for each code length 1..15 the symbols with that length
  (`Inflate/syms_with_len`, in symbol order) receive consecutive codes starting
  at `first`, and `first` for the next length is `(first + count) << 1`. Each
  code is inserted MSB-first into a binary tree
  (`type Huff: Empty | Leaf { sym } | Node { zero, one }`, `Inflate/insert`).
- **Decoding.** `Inflate/decode(s, tree) -> (symbol, s, tree)` walks the tree
  one bit at a time and returns the tree rebuilt along the walked path, so the
  table is threaded through the loop instead of being copied for every symbol
  (rule P-14). A path that ends in `Empty` (incomplete or invalid code) yields
  `0xFFFF` without consuming further bits.
- **Fixed tables.** `Inflate/fixed_lit(z)` / `Inflate/fixed_dist(z)` take a
  runtime zero (rule P-7).
- **Dynamic tables.** `Inflate/dynamic` reads HLIT, HDIST, HCLEN, the code
  length code lengths (in the order given by `Inflate/CLEN_POS`, the inverse
  of the RFC permutation), then the literal/length and distance code lengths
  with repeat codes 16, 17, 18 (`Inflate/read_lengths`, `Inflate/repeat_len`).
- **Output.** State `(window, position, reversed_output)`. The window is a
  Bend `Map` keyed by `position mod 2^15` holding the last 32 KiB for
  back-references (`Inflate/copy`). The output list is reversed once at the
  end.
- **Length and distance codes.** `Inflate/LEN_BASE`, `Inflate/LEN_EXTRA`,
  `Inflate/DIST_BASE`, `Inflate/DIST_EXTRA` (RFC 1951 §3.2.5).

## Truncated and corrupt input

A well-formed zlib stream never reads past its end (the Adler-32 trailer
follows the DEFLATE data), so `overrun > 0` means truncated input.
Decompression stops, keeping only the output produced from real input bits,
when:

- a symbol, length or distance was read with padding bits (`overrun > 0`);
- a literal/length symbol is above 285 or a distance symbol above 29;
- a distance points before the start of the output;
- a block has the reserved type 3;
- the output reaches `Inflate/MAX_OUTPUT` (4 MiB), which bounds the time and
  memory a small compressed stream can demand.

Corrupt and invalid conditions also set `overrun`, which stops the block loop
(`Inflate/blocks`). Every loop consumes input or decrements a bounded counter,
so decompression always terminates; for truncated input the result is a
prefix of the original data.

The state tuple is destructured once per step and rebuilt, never read twice:
in HVM a second use of the state would duplicate the remaining input list,
which costs time proportional to its length on every step (rule P-16).

## PNG predictors

`Png/rows` processes one row at a time with the previous decoded row as `up`.
`Png/row` keeps queues of the last `bpp` decoded bytes (`left`) and of the
bytes above them (`upleft`). Paeth uses `pa = |b - c|`, `pb = |a - c|`,
`pc = |a + b - 2c|` with ties resolved in the order `a`, `b`, `c`.


## Internal helpers

| Function | Purpose |
|---|---|
| `Inflate/at(xs, i)`, `Inflate/count(xs)` | List element (0 when out of range) and length. |
| `Inflate/emit(o, b)` | Appends one byte to the output state (window and reversed output). |
| `Inflate/copy(o, len, dist)` | Copies `len` bytes from `dist` bytes back. |
| `Inflate/insert_all`, `Inflate/insert` | Insert consecutive canonical codes into the Huffman tree. |
| `Inflate/read3(s, n)` | Reads `n` 3-bit code length code lengths. |
| `Inflate/clen_lengths(vals, hclen, pos)` | Code length code lengths in symbol order. |
| `Inflate/stored(s, o)` | Stored block: aligns, reads `LEN`, skips `NLEN`, copies `LEN` bytes. |
| `Png/paeth(a, b, c)`, `Png/abs_diff(x, y)` | Paeth predictor and absolute difference. |

## Tests

`inflate_fixed`, `inflate_dynamic`, `inflate_stored`, `inflate_truncated`,
`inflate_garbage`, `png_up`, `png_sub` in `test.bend` (streams produced by
Python's `zlib`); the `objstm` and `hybrid`
fixtures exercise FlateDecode with and without predictors.
