# 02 — Platform constraints and coding rules

Bend 0.2.38 and HVM 2.0.22 impose constraints that shape the whole code base.
Each rule below is mandatory for new code.

## 1. Numbers are 24-bit

Bend only has `u24` (plus `i24`/`f24`, unused here). Arithmetic wraps modulo
2^24.

- **Rule P-1.** Byte positions and lengths are `u24`; files must be smaller
  than 16 MiB (NFR-2).
- **Rule P-2.** 32-bit words (SHA-256) are represented as two 16-bit halves
  `(hi, lo)`. Additions carry from `lo` into `hi` with `>> 16`; rotations
  combine shifts of both halves; results are masked with `& 0xFFFF`.
  Intermediate values may exceed 16 bits (shifted bits are discarded by the
  final mask) but never 24 bits.
- **Rule P-3.** Big integers use 12-bit limbs because
  `(2^12-1)^2 + 2·(2^12-1) = 2^24-1`: a limb product plus two carries fits
  exactly in a `u24`.
- **Rule P-4.** Subtraction is written as `(a + 0x1000) - b - borrow` so that
  intermediate values never wrap.

## 2. File input

`IO/FS/read` in the C runtime returns bytes `>= 0x80` sign-extended to 24
bits (`0x93` becomes `0xFFFF93`), and the builtin `IO/FS/read_file` returns
files larger than its 1 MiB chunk size with the chunks in reverse order.

- **Rule P-5.** Every byte list read from a file passes through
  `Bytes/from_io` (masks with `0xFF`) before use.
- **Rule P-5b.** Do not use `IO/FS/read_file`; read with `IO/FS/read` in a
  loop and reverse the list of chunks before joining (`Main/read_file` in
  `sign.bend`, see [10-cli.md](10-cli.md#program-structure)).

## 3. Closed expressions must be data

Bend floats closed sub-expressions (no free variables) into new global
definitions. When HVM must duplicate a reference to such a definition before
it has been evaluated and the definition (transitively) contains duplication
nodes, the runtime aborts with `attempt to clone a non-affine global
reference`. Whether this happens depends on evaluation order, so it can
surface only under some inputs or thread counts.

- **Rule P-6.** Constants are literal data (lists of numbers, strings,
  constructor applications), never calls. Examples: `Cms/ALG_SHA256` is a
  byte literal instead of a call that encodes the AlgorithmIdentifier; `Pdf/lit("3")` instead of
  `Pdf/num(3)`; `Pdf/null` is the literal `PdfObj/Raw([110, 117, 108, 108])`.
- **Rule P-7.** When a value must be computed from constants (for example the
  fixed Huffman tables in `Inflate/fixed_lit`), pass a runtime value into the
  computation (`Inflate/fixed_lit(type - 1)`, which is always 0) so the
  expression is not closed.
- **Rule P-8.** Unit tests receive a runtime `z` (always 0) and build every
  constant through it (`S(z, "...")`, `Lz(z, [...])`, `t_pattern(z + n)`).
- `-Ono-float-combinators` is not an option: it makes recursive definitions
  expand forever under HVM's strict evaluation.

## 4. `object` and imports

- **Rule P-9.** Do not declare `object`s in libraries. A module that
  constructs an `object` and is imported transitively makes the compiler
  panic (`order_kwargs ... no entry found for key`). Use single-constructor
  types: `type RsaKey: New { ... }`, constructed with `RsaKey/New(...)` and
  read with `open RsaKey: key` or `match`.
- **Rule P-10.** `from lib/x import *` does not re-export: every module
  imports the modules whose names it uses.
- **Rule P-11.** Imports resolve relative to the main file. Programs live in
  the repository root.

## 5. I/O programs

- **Rule P-12.** Keep `main` thin: read inputs, call pure functions, write
  outputs. Decisions belong in pure library functions that return a value
  the I/O code only has to match on (`Route`, `Outcome` in
  `lib/service.bend`).
- **Rule P-13.** Use `* <- IO/...` for effects whose result is unused.
- **Rule P-22.** Inside `with IO:` blocks, call only definitions of the
  program file and builtins; reach library functions through wrappers
  defined in the program file (`Main/route` calls `Service/route`).
  Bend 0.2.38 resolves names of the program file and builtins as global
  references, but treats definitions of imported modules as variables
  captured by the bind continuations (also inside the library's own `with`
  blocks). A captured definition used in several later steps is duplicated,
  and duplicating a reference to a definition that itself duplicates values
  makes HVM expand it; for a recursive definition the expansion never ends.
  Two observed failures: file-reading helpers moved into a library and
  called four times from `main` made signing a 2 KB document run until the
  node buffers were full (more than 5 minutes instead of 10 seconds), and a
  response built inside a `with` block with three calls to
  `Bytes/from_string` came out truncated after the first part.
- **Rule P-24.** HVM evaluates every expression whose inputs are known, also
  inside the continuations of a `with IO:` block; I/O actions only
  determine the order of the effects. Work that must happen after an effect
  has to depend on that effect's result: the asynchronous job in
  `server.bend` signs inside a `match` on the result of closing standard
  input, otherwise the signature would be computed before the `202`
  response is sent.
- Files are the only I/O channel besides standard input and output: the
  service reads the time from `/proc/stat` and `/proc/uptime`
  ([modules/clock.md](modules/clock.md)), random bytes from `/dev/urandom`
  and its configuration from a file. Reading standard input must not request
  more bytes than the peer has sent (a read blocks until the requested
  amount or the end of the stream), so the HTTP head is read one byte at a
  time.
- `bend run-rs` does not perform I/O; I/O programs run with `bend run-c` or
  as compiled binaries. Compiled binaries take no arguments, hence the fixed
  file names of the CLI ([10-cli.md](10-cli.md)) and the service's
  `server.conf`.

## 5b. Syntax notes

- String literals accept `\n`, `\r`, `\t`, `\"` and `\\` but not `\xNN`;
  write non-ASCII bytes as list literals (`[0xE2, 0xE3, 0xCF, 0xD3]`).
- A variable assigned in both branches of an `if`/`else` can be used after
  it, but not one assigned in an `if`/`elif`/`else` chain; compute it in a
  helper function instead (`Service/conf_error`).
- List literals may span several lines and end with a comma (`run` in
  `test.bend`).

## 6. Every use of a value is a copy

HVM has no sharing: a variable used twice is duplicated, and duplicating a
data structure copies all of it eagerly (the duplication propagates through
every node), even when one copy is never read; dropping a value erases all of
it. A list traversal that uses both a list and its tail in each step
therefore costs `O(n)` per step and `O(n^2)` overall.

- **Rule P-14.** In a recursive step, use each list exactly once. To look
  ahead, `match` the list and rebuild it (`List/Cons(x.head, x.tail)`) or use
  helpers that return the rest: `Bytes/pop`, `Bytes/split` (take and drop in
  one pass), `Bytes/strip_prefix` (match a keyword and return the rest, or the
  rebuilt input on mismatch), `Bytes/parse_u24`, `Pdf/token`.
- **Rule P-15.** A search traverses the input once and copies at most a
  needle-sized piece of it per position: `Bytes/find` splits off and compares
  `len(needle)` bytes only where the first byte matches, `Bytes/rfind`
  reverses the input once and searches for the reversed needle, and
  `Pdf/find_def` keeps a window of the last `len(pattern) + 1` bytes.
- **Rule P-16.** Loop state tuples are destructured once per step and rebuilt
  (`Inflate/codes`); reading one field and passing the whole tuple on would
  copy every component, including the remaining input.
- **Rule P-23.** A recursion over data that is already known runs ahead of
  an accumulator that is still being computed: HVM unfolds every step and
  keeps each one waiting for its share of the accumulator. When each step is
  large (64 SHA-256 rounds per block), make the step wait for the
  accumulator by branching on one of its values first (`Sha256/ready` in
  `Sha256/process`), so only one step is in flight.
- Duplicating a whole document a bounded number of times (for example
  passing the PDF to several lookups) is acceptable: it is linear.

Violations of P-14 were the cause of an `O(n^2)` behavior found during review:
analyzing a 19 KB signed PDF took 2 637 M interactions, 20 M after the fix.

## 7. Runtime limits

- **Rule P-21.** Build production binaries with `scripts/build.sh`, which
  enlarges the high-priority redex bag, bounds the node buffers and makes
  file output linear (see
  [01-architecture.md](01-architecture.md#5-runtime-and-build)). On the
  unpatched C runtime, programs that drop lists longer than about 32 Ki
  elements hang, and writing a file costs about 0.4 ms per byte.

## 8. Writing fast code for HVM

The dominant cost is traversing and rebuilding data structures, not
arithmetic (one numeric operation costs one or two interactions, one `match`
on a list with free variables costs several).

- **Rule P-17.** Prefer one traversal of one list per step. Pack independent
  small values into one `u24` (`b_j | n_j << 12` in `BigInt/pack`) or into a
  tuple element of a single list (pairs `(t_j, b_j | n_j << 12)` in the
  Montgomery state).
- **Rule P-18.** Pass hot loop state as function arguments rather than tuples
  (`Sha256/rounds` takes 16 halves plus the lists).
- **Rule P-19.** Avoid `cmp`-style full normalizations inside loops; when a
  loop is unavoidable (bit-serial reduction), keep the early-exit comparison.
- **Rule P-20.** Every function definition must stay below HVM C's limit of
  4095 nodes; large literals belong in their own definitions.
