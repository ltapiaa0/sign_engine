# Module `lib/pdf.bend`

Reads the structure of a PDF file (ISO 32000-1) and writes the incremental
update that adds a signature.

## 1. Object model

```
type PdfObj:
  Raw { raw }        numbers, strings, booleans, null, other keywords (original text)
  Name { name }      name without the leading '/' (escapes kept as written)
  Arr { items }      list of PdfObj
  Dict { entries }   list of (key bytes, PdfObj) in file order
  Ref { num, gen }   indirect reference "num gen R"
```

Keeping numbers and strings as their original text makes serialization
lossless for every value the update rewrites.

| Function | Contract |
|---|---|
| `Pdf/null` | `Raw("null")`, a pure literal (rule P-6). |
| `Pdf/is_null(o)`, `Pdf/is_dict(o)` | Predicates. |
| `Pdf/num(n)` / `Pdf/lit(s)` | `Raw` decimal number from a runtime value / from a literal string. |
| `Pdf/name(s)` | `Name` from a literal string. |
| `Pdf/int(o) -> u24` | Leading decimal digits of a `Raw` (0 otherwise). |
| `Pdf/get(dict, key)` | Value of `key` (a literal string) or `Pdf/null`. Non-dictionaries behave as empty. |
| `Pdf/has(dict, key)` | `1` if the key exists with a non-null value. |
| `Pdf/set(dict, key, value)` | Replaces the value in place or appends the entry. |
| `Pdf/name_is(o, s)` | `1` if `o` is the name `s`. |
| `Pdf/entries(o)`, `Pdf/items(o)`, `Pdf/nth(items, i)`, `Pdf/ints(items)` | Accessors with empty/null defaults. |

## 2. Lexer and parser

- White-space: `00 09 0A 0C 0D 20`. Delimiters: `( ) < > [ ] { } / %`.
  Comments (`%` to end of line) are skipped wherever white-space is allowed.
- `Pdf/parse(xs) -> (obj, rest)` reads one object: dictionary `<< >>`,
  hexadecimal string `< >`, literal string `( )` with nested parentheses and
  backslash escapes, array `[ ]`, name `/...`, number or keyword. An integer
  followed by an integer and the keyword `R` (not followed by a regular
  character) is a reference (`Pdf/maybe_ref`).
- Dictionary entries whose key is not a name are skipped; unexpected
  delimiters are consumed one character at a time. Every step consumes input,
  so parsing always terminates.
- Look-ahead never duplicates the input (rule P-14). When the reference test
  fails, `Pdf/maybe_ref` returns the tokens it consumed in front of the rest
  (`Pdf/unread`, separated by single spaces), which is equivalent for the
  parser.
- `Pdf/serialize(o)` writes `<<`/`>>`, `[`/`]`, `/name`, `n g R` and raw text,
  with single spaces as separators.

## 3. Indirect objects and streams

`Pdf/read_indirect(xs) -> (num, obj, data)` reads `num gen obj`, the object
and, when the keyword `stream` follows, the stream data: after `stream` comes
CRLF, LF or (non-conforming) CR; the data length is `/Length` when it is a
direct number, otherwise the data runs until `endstream` minus the end-of-line.

`Pdf/decode_stream(dict, data)` supports no filter and `/FlateDecode`
(alone or as the only element of a filter array), with PNG predictors
(`/Predictor ≥ 10`, `/Columns`, default 1, one byte per pixel). Other filters
return the data unchanged; they never occur in the structures this module
needs to decode (cross-reference streams and object streams).

## 4. Cross-reference data

The object map is a Bend `Map` from object number to `(kind, a, b)`:

| kind | Meaning |
|---|---|
| 0 | free (hides older definitions) |
| 1 | uncompressed object at byte offset `a`, generation `b` |
| 2 | object number `b`-th in the object stream `a` |

`Pdf/startxref` reads the number after the last `startxref`.
`Pdf/load_xref(pdf, offset, depth)` loads one section and, recursively, the
older ones:

- **Classic table** (`xref` keyword): subsections `start count` followed by
  `count` entries `offset gen n|f` (parsed by tokens, so non-standard entry
  widths are accepted; parsing stops early at the end of input). The trailer
  dictionary follows the `trailer` keyword.
- **Cross-reference stream**: an indirect object with `/W [w1 w2 w3]`,
  optional `/Index` (default `[0 Size]`) and the entries as rows of
  `w1 + w2 + w3` big-endian fields; `w1 = 0` means type 1. Parsing stops at
  the end of the data; a stream whose rows have zero width yields no entries
  (otherwise a few bytes could declare millions of entries).
- **Precedence.** Older sections (`/Prev`) are loaded first and newer entries
  override them. In a hybrid section (classic table plus `/XRefStm`) the
  table's free entries are applied first, then the stream's entries, then the
  table's in-use entries: objects that the table omits or marks as free for
  pre-1.5 readers are found in the stream (ISO 32000-1 §7.5.8.4). This matches
  pyHanko; qpdf instead treats a free table entry as deleted, so writers of
  hybrid files should omit compressed objects from the table (as the `hybrid`
  fixture does).
- `depth` (64) bounds the `/Prev` chain, so cycles terminate.
- `Pdf/load_xref` also returns the largest object number seen.

## 5. Object access

`Pdf/get_obj(pdf, xref, num)`:

- kind 1: reads the object at the offset. If the object number found there
  differs from `num` (wrong offsets are common in damaged files), the file is
  searched for the last `num gen obj` preceded by white-space or at the
  start of the file (`Pdf/find_obj`, a one-pass window search in
  `Pdf/find_def`) and that definition is used. The search is textual, so it
  could also match inside an uncompressed stream; it is only a fallback for
  damaged files.
- kind 2: `Pdf/objstm_get` decodes the object stream, reads the header pairs
  `num offset` and parses the object at `/First + offset`.
- otherwise `Pdf/null`.

`Pdf/resolve(pdf, xref, o)` follows one reference.
`Pdf/first_page(pdf, xref, ref, depth)` descends `/Kids[0]` from `/Pages`
until a node without `/Kids` (depth limit 32) and returns `(num, gen, dict)`.

## 6. Analysis

```
type PdfInfo:
  New { len, startxref, xref, trailer, is_stream, size, root_num, root_gen, root, page_num, page_gen, page }
```

`Pdf/analyze(pdf) -> Result(PdfInfo, String)` checks the `%PDF-` header in the
first 1024 bytes, loads the cross-reference data, rejects encrypted files
(`/Encrypt` in the trailer), resolves the catalog, rejects certified documents
that forbid changes, and resolves the first page.

`Pdf/docmdp_p(pdf, xref, root)` returns the DocMDP permission level of a
certified document: the catalog's `/Perms /DocMDP` signature dictionary, its
`/Reference` entry whose `/TransformMethod` is `/DocMDP`, and that entry's
`/TransformParams /P` (2 when absent); 0 when the document is not certified.
Level 1 (no changes) is refused; levels 2 and 3 allow adding a signature.
`size` is the larger of the trailer `/Size` and the largest object number
plus one, so new object numbers never collide with existing ones.
`is_stream` tells whether the newest section is a cross-reference stream.

Errors: `pdf: missing %PDF- header`, `pdf: startxref not found`,
`pdf: encrypted documents are not supported`, `pdf: trailer has no /Root`,
`pdf: catalog (/Root) is not a dictionary`,
`pdf: the document is certified and does not allow changes (DocMDP P=1)`,
`pdf: first page not found`.

Field locks (`/Lock` in existing signature fields) are not evaluated.

## 7. Text strings

`Pdf/text_string(utf8)` encodes UTF-8 text as a PDF text string in UTF-16BE
with byte order mark, written as uppercase hexadecimal: `<FEFF...>`
(`Text/utf8_decode` then `Text/utf16be_encode`). `Pdf/ascii_string(xs)` writes a
literal string escaping `(`, `)` and `\`.

## 8. Incremental update

```
type SigFields:
  New { name, reason, location, contact, time }
```

`SigFields/new(...)` takes UTF-8 byte strings; empty fields are omitted.

New and rewritten objects (`size` is `PdfInfo.size`):

| Object | Number | Content |
|---|---|---|
| Signature dictionary | `size` | `<</Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange [...] /Name /Reason /Location /ContactInfo /M /Contents <...> >>` |
| Signature field + widget | `size + 1` | `<</Type /Annot /Subtype /Widget /FT /Sig /T (Signature<size>) /V size 0 R /F 132 /Rect [0 0 0 0] /P page>>` (invisible, print + locked) |
| Catalog | root | Original catalog with `/AcroForm` = original form dictionary (resolved if indirect) with `/Fields` = original fields (resolved if indirect) plus the new field, and `/SigFlags 3`. |
| First page | page | Original page with `/Annots` = original annotations (resolved if indirect) plus the new widget. |
| Cross-reference | `size + 2` (stream only) | See below. |

The field name `Signature<size>` is unique among fields created by this
engine because `size` is a fresh object number; names of fields created by
other tools are not checked.

An indirect `/AcroForm`, `/Fields` or `/Annots` is written inline in the
rewritten catalog or page, so the update never rewrites objects other than
the catalog and the first page. pyHanko's difference analysis accepts this
(modification level `FORM_FILLING` for earlier signatures, `forms` fixture)
and `pdfsig` validates the result; other validators, such as Adobe Acrobat,
were not tested.

Layout of the update appended to the original bytes:

```
\n
<size> 0 obj\n<<... /ByteRange [0 a b c          ] ... /Contents <hex zeros> >>\nendobj\n
<size+1> 0 obj ... endobj        widget
<root> obj ... endobj            catalog
<page> obj ... endobj            page
xref section and trailer
startxref\n<offset>\n%%EOF\n
```

- If the newest original section is a classic table, the update ends with a
  classic table (one subsection per object, 20-byte entries ending in CRLF)
  and a trailer `<</Size size+2 /Root ... /Prev startxref /Info ... /ID ...>>`
  (`/Info` and `/ID` copied when present).
- If it is a cross-reference stream, the update ends with an uncompressed
  cross-reference stream object `size + 2` with `/W [1 4 2]`, `/Index`
  listing every object of the update (including itself), `/Size size+3`,
  `/Root`, `/Prev`, `/Info`, `/ID`.

### ByteRange

`Pdf/BYTERANGE_PLACEHOLDER` and `Pdf/byterange_text(a, b, c)` are exactly
`Pdf/BYTERANGE_WIDTH` (44) bytes: `[0 a b c` padded with spaces and closed by
`]`. `Pdf/prepare(pdf, info, fields, sig_len)`:

1. builds the update with the placeholder to obtain `cs` (offset of `<` of
   `/Contents`), `ce = cs + 2 + 2·sig_len` and the tail `C`;
2. builds it again with `[0 cs ce total-ce]` (same length);
3. returns `(A, C, pdf ++ A ++ C)`; the third value is exactly the data the
   signature covers.

`Pdf/build_update` returns `(A, C, cs, ce)` where the final file is
`pdf ++ A ++ "<" ++ hex ++ ">" ++ C`.

`Pdf/finish(pdf, A, C, cms, sig_len)` writes the CMS as uppercase hexadecimal
padded with `0` to `2·sig_len` digits, or fails with
`pdf: CMS signature does not fit in the reserved space`.

## 9. Internal helpers

| Function | Purpose |
|---|---|
| `Pdf/is_delim`, `Pdf/is_regular`, `Pdf/skip`, `Pdf/skip_line`, `Pdf/token`, `Pdf/head` | Lexer: delimiter and regular characters, white-space and comment skipping, regular-character tokens, first byte. |
| `Pdf/all_digits`, `Pdf/is_int_token`, `Pdf/ref`, `Pdf/unread` | Integer tokens, reference construction, putting look-ahead tokens back. |
| `Pdf/parse_dict`, `Pdf/parse_array`, `Pdf/hex_string`, `Pdf/lit_string`, `Pdf/rev_entries`, `Pdf/rev_objs` | Parser for compound values and strings; accumulators are reversed at the end. |
| `Pdf/serialize_items`, `Pdf/serialize_entries` | Serialization of array items and dictionary entries. |
| `Pdf/stream_start`, `Pdf/until_endstream`, `Pdf/strip_eol`, `Pdf/is_flate`, `Pdf/first_params` | Stream data boundaries and filter parameters. |
| `Pdf/xref_set`, `Pdf/xref_get`, `Pdf/load_prev`, `Pdf/filter_kind`, `Pdf/max_num`, `Pdf/max` | Object map updates and lookups, `/Prev` chain, entry filtering by kind, largest object number. |
| `Pdf/classic_sections`, `Pdf/classic_entries`, `Pdf/stream_entries`, `Pdf/stream_ranges`, `Pdf/stream_rows` | Classic table and cross-reference stream parsing. |
| `Pdf/objstm_offset`, `Pdf/find_def` | Object stream header lookup; textual search for an object definition. |
| `Pdf/docmdp_ref` | DocMDP entry of a signature's `/Reference` array. |
| `Pdf/escape`, `Pdf/opt_text`, `Pdf/opt_date` | Literal string escaping; optional text and date entries of the signature dictionary. |
| `Pdf/obj_header`, `Pdf/obj_footer`, `Pdf/indirect`, `Pdf/sig_dict_parts` | Indirect object framing; the signature dictionary split around `/Contents`. |
| `Pdf/append_to`, `Pdf/updated_catalog`, `Pdf/updated_page`, `Pdf/copy_trailer_keys` | Rewritten catalog, page and trailer entries. |
| `Pdf/xref_table`, `Pdf/xref_rows`, `Pdf/xref_index`, `Pdf/sort_objs`, `Pdf/insert_obj` | Classic table and cross-reference stream of the update, objects sorted by number. |

## 10. Tests

`pdf_roundtrip`, `pdf_ref`, `pdf_text_utf16`, `pdf_startxref`,
`pdf_byterange_width`, `pdf_byterange_placeholder` in `test.bend`; all
fixtures in `tests/e2e.sh`.
