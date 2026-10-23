# Module `lib/mkpdf.bend`

Generates large, deterministic test documents (`mkpdf.bend` reads the page
count from `pages.txt` and writes `large.pdf`).

## Document

- `%PDF-1.4` header and a binary comment line.
- Object 1 catalog, object 2 page tree with all pages as `/Kids`, object 3 a
  Helvetica Type 1 font; for page `i`, object `4 + 2i` is the page (A4
  MediaBox) and `5 + 2i` its uncompressed content stream.
- Each page has 70 lines of 14 words drawn from ten words with the linear
  congruential generator `seed' = (1103·seed + 12345) mod 2^24` (seed 7),
  shown with `Tj` / `T*` operators.
- A classic cross-reference table with 20-byte entries, a trailer with
  `/Size` and `/Root`, `startxref` and `%%EOF`.

Each page takes about 9 KB: 60 pages give about 540 KB and 750 pages about
6.7 MB. `qpdf --check` accepts the output.

## API

| Function | Contract |
|---|---|
| `Mk/document(n)` | The complete file for `n` pages. |
| `Mk/pages_from(text)` | Page count from `pages.txt` (default 60, at most 2000). |
| `Mk/layout(objects, at)` | Concatenates the objects and returns their offsets, measuring each object in the same pass that copies it. |
| `Mk/pages`, `Mk/text`, `Mk/line`, `Mk/word`, `Mk/next` | Page objects and text. |
| `Mk/object`, `Mk/ref`, `Mk/kids`, `Mk/entries` | Serialization helpers. |
| `Mk/LINES`, `Mk/WORDS` | 70 and 14. |

## Program `mkpdf.bend`

Reads up to 64 bytes of `pages.txt` (`Main/read`, `Main/bytes`), builds the
document with `Main/document` and writes `large.pdf`.
