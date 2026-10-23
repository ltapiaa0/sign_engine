# Module `lib/verify.bend`

Signature validation in Bend, used by the test suite (`verify.bend`,
`tests/validate.sh`) as an independent check of properties that external
tools do not cover. It reuses the PDF reader, SHA-256, DER, X.509 and RSA
modules.

## Entry point

`Verify/run(pdf) -> (ok, report, files)`: `report` has one line per
signature and a summary (`verify: N signature(s), ok|FAIL`); `files` are, for
each signature `k`, `sig<k>.der` (the CMS without the zero padding) and
`content<k>.bin` (the signed byte ranges), so that OpenSSL can verify the
CMS independently.

## Finding signatures

Signatures are the `/V` dictionaries of fields with `/FT /Sig` reachable
from the catalog's `/AcroForm /Fields` (with `/Kids`, up to 8 levels) whose
`/ByteRange` has four numbers (`Verify/fields`). They are sorted by the end
of their signed range (`Verify/sort`), which is revision order.

## Checks per signature (`Verify/signature`)

1. `/ByteRange [o1 l1 o2 l2]`: `o1 = 0`, `l1 < o2`, `o2 + l2 ≤` file length.
2. The excluded gap, bytes `l1..o2`, is exactly the `/Contents` string of
   the dictionary (so nothing but the signature value is left unsigned).
3. `/SubFilter` is `/ETSI.CAdES.detached` or `/adbe.pkcs7.detached`.
4. CMS (`Verify/cms`): `ContentInfo` of type signed-data; the signer
   certificate is found among the certificates by issuer and serial number
   (`Verify/signer`); digest algorithm SHA-256; signed attributes present
   with `contentType` = id-data, `messageDigest` equal to the SHA-256 of the
   signed ranges, and `signingCertificateV2` whose `certHash` is the SHA-256
   of the signer certificate (`Verify/ess_hash`, with or without an explicit
   SHA-256 `hashAlgorithm`); signature algorithm `rsaEncryption` or
   `sha256WithRSAEncryption`; the RSA PKCS#1 v1.5 signature over the DER
   `SET OF` signed attributes verifies with the certificate's key.
5. Later changes (`Verify/updates`), for a signature that does not cover
   the whole file:
   - DocMDP level 1 (`Verify/docmdp`, from `/Reference`) allows none.
   - Otherwise every cross-reference section written after the signed
     revision (`Verify/sections`, following `/Prev` from the last
     `startxref`) may only contain (`Verify/entry`): new signature
     dictionaries, new signature widgets, new cross-reference streams
     (`Verify/added_ok`); the catalog changed only in `/AcroForm`; the
     catalog's previous `/AcroForm` object changed only in `/Fields` and
     `/SigFlags`; pages changed only in `/Annots` (`Verify/same_except`
     compares the serialized dictionaries without that key). Deleted or
     compressed objects fail.

This is the subset of pyHanko's difference analysis that applies to
signature-only updates (pyHanko's `FORM_FILLING` level for added signature
fields).

## Internal helpers

`Verify/word`, `Verify/below`, `Verify/end`, `Verify/insert`, `Verify/each`,
`Verify/append`, `Verify/raw`, `Verify/docmdp.go`, `Verify/attr`,
`Verify/alg_oid`, `Verify/certs`, `Verify/ders`, `Verify/last`,
`Verify/ref_num`, `Verify/section`, `Verify/entries`, `Verify/same_except2`,
`Verify/without`, `Verify/drop_key`, and the OID literals `Verify/OID_DATA`,
`Verify/OID_CONTENT_TYPE`, `Verify/OID_MESSAGE_DIGEST`,
`Verify/OID_SIGNING_CERT_V2`, `Verify/OID_SHA256`, `Verify/OID_RSA`,
`Verify/OID_SHA256_RSA`.

## Program `verify.bend`

Reads `input.pdf` from the working directory (`Main/read_file`,
`Main/read_chunks`, `Main/assemble`, `Main/reverse` as in `sign.bend`),
runs `Verify/run` through the wrapper `Main/run`, writes the extracted files
(`Main/write_all`, names converted with `Main/string`) and prints the
report.

## Tests

`tests/validate.sh` runs it on every end-to-end output. It was also checked
against a flipped byte in a signed range (messageDigest mismatch for both
signatures) and against an appended update that adds `/Lang` to the catalog
(rejected as "object 5 changed outside /AcroForm", while `pdfsig` still
reports both signatures as valid).
