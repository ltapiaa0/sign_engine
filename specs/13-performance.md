# 13 — Performance

## Cost model

HVM work is measured in interactions (`ITRS`, printed by the runtime; the
counter wraps at 2^32, so larger runs print the count modulo 2^32).
Interaction counts are deterministic; times depend on the machine. All
figures below were measured in the development container with the default
build of `scripts/build.sh` (one thread, `MEM_L2=28`, `VARS_L2=29`), where the
C runtime runs at about 20–23 million interactions per second.

| Operation | Interactions | Time | Peak RSS |
|---|---|---|---|
| Sign a 2 KB PDF (`classic` fixture), RSA-1024 | 222 M | 11 s | 2.6 GiB |
| Sign a 2 KB PDF, RSA-2048 | 1 479 M | 73 s | 4.2 GiB |
| Sign a 644 KB, 60-page PDF, RSA-2048 | 2 216 M | 103 s | 4.2 GiB |
| Sign a 3.2 MB, 300-page PDF, RSA-2048 | 5 171 M | 229 s | 4.3 GiB |
| Sign an 8 MB, 750-page PDF, RSA-2048 | 10 713 M | 507 s | 4.4 GiB |
| Read a 644 KB file (`Main/read_file`) | 34 M | 1.4 s | — |
| Find the last `startxref` in a 644 KB file (`Bytes/rfind`) | 8 M | 0.4 s | — |
| SHA-256 of 256 KiB | 169 M (~41 k per 64-byte block) | 8 s | — |
| Montgomery multiplication, 43 limbs | ~133 k (~70 per limb product) | — | — |

The RSA private operation dominates small documents. Each input byte adds
about 1 150 interactions: about 650 for SHA-256 and the rest for reading,
searching, parsing and copying the document. Resident memory reaches 2.5 to
4.5 GiB for any document, because the allocator walks its whole buffers before
reusing slots (see [01-architecture.md](01-architecture.md#5-runtime-and-build)).
With the default service timeout (900 s), documents of about 8 MB are the
practical limit; the service refuses documents above `SIGN_MAX_PDF` (8 MiB)
before running the signer.

## Memory

The node buffer (`2^MEM_L2` slots of 8 bytes) and the variable buffer
(`2^VARS_L2` slots of 4 bytes) bound the live data, 2 GiB each by default.
When either is full the signer stops with `runtime: out of memory`.

Live data, measured with an instrumented runtime (exact counts of live
nodes, and a scan of both buffers when memory ran out), RSA-2048:

| Document and build | Result |
|---|---|
| 1.3 MB, before the `Sha256/ready` gate | 248 M live nodes (192 per input byte) while hashing the signed ranges |
| 1.9 MB and 3.2 MB, before the gate | Out of memory while hashing (3.2 MB also with `MEM_L2=29`) |
| 3.2 MB, with the gate | 84 M live nodes (26 per input byte), during document analysis |
| 8 MB, with the gate, `VARS_L2=28` | Out of memory during analysis: variable buffer full (268 M variables) with 136 M live nodes (four copies of the document) |
| 8 MB, with the gate, `VARS_L2=29` | Signed (table above) |

Each copy of a document costs 4 nodes per byte. Analysis keeps up to about
five copies alive at once: `Pdf/analyze` and the lookups it makes each
receive their own copy (rule P-14 allows a bounded number of copies). Copies
made by duplication use about two variables per node, which is why the
variable buffer has twice as many slots as the node buffer by default.

## File output

Before the readback patches of
[01-architecture.md](01-architecture.md#5-runtime-and-build), writing a file
normalized the whole net once per byte, which cost about 0.2–0.4 ms per byte,
mostly in `sched_yield` system calls:

| Read and write back a random file | Unpatched readback | Patched |
|---|---|---|
| 256 KiB, one thread | 58 s | 0.4 s |
| 2.5 MiB | 584 s | 8 s |

The output was identical to the input (`cmp`) in every case.

## Optimization history

| Change | Effect |
|---|---|
| SHA-256 rounds with flat 16-argument state and inline rotations instead of tuples and generic rotation functions | 170 k → 42 k interactions per block |
| Montgomery `b` and `n` limbs packed into one `u24` per position | 289 k → 202 k per 43-limb multiplication |
| Montgomery state as one list of `(t, b|n)` pairs, one `match` per step | 202 k → 133 k |
| `R^2 mod n` from `2^(bits-1)` plus two Montgomery squarings, and Montgomery-based reductions instead of bit-serial long division | RSA-2048 signature: 2 880 M → 1 511 M interactions |
| Removal of whole-list duplications in searches and in the PDF parser (rules P-14 to P-16) | `Pdf/analyze` of a 19 KB signed PDF: 2 637 M → 20 M interactions; of the 2 KB `classic` fixture: 28.7 M → 2.0 M |
| `Bytes/find` with a first-byte filter and `Bytes/rfind` through one reversal, instead of a sliding window compared at every position | Last `startxref` of a 644 KB file: 484 M → 8 M interactions |
| Huffman tables as trees threaded through the decoder | Inflating 136 KB: 225 M → 211 M interactions |
| Runtime readback patches (one normalization per write, constant definitions resolved directly) | Signing the 644 KB PDF: 3 min 49 s → about 100 s |
| `Sha256/ready` gate: one SHA-256 block in flight (rule P-23) | Peak memory 192 → 26 nodes per input byte |
| Variable buffer twice the node buffer (`VARS_L2`) | Largest document signed with the default build: 1.3 MB → 8 MB |

## Known costs

- Inflating costs about 1 550 interactions per output byte, dominated by the
  32 KiB window (`Map` with 15 levels per byte written or read). Object
  streams are decoded once per object fetched from them.
- Every lookup that receives the whole document (`Pdf/get_obj`, `Pdf/resolve`)
  copies the document list once (linear in time, but each copy alive at the
  same time adds 4 nodes and about 8 variables per byte).
- Reading a file costs about 53 interactions per byte (injection by the
  runtime, `Bytes/from_io`, joining the chunks).

## Further options

- Thread the document through the analysis (each lookup returns the document
  it received, or reads a bounded window of it) so that only one or two
  copies are alive at once; this is the way to approach the 16 MiB format
  limit with the default buffers.
- Fuse two CIOS rows per pass (halves list traversals again).
- Feed `W + K` to the SHA-256 rounds as one list of pairs.
- Replace the inflate window `Map` with a 16-ary trie (4 levels instead of 15)
  and cache decoded object streams during analysis.
- Use several threads with proportionally larger buffers (`TPC_L2`,
  `MEM_L2`, `VARS_L2`): the two CRT exponentiations are independent.
  Untested; see the thread note in
  [01-architecture.md](01-architecture.md#5-runtime-and-build).
