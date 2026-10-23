# Module `lib/cms.bend`

CMS `SignedData` (RFC 5652) for detached signatures with the signed
attributes required by CAdES-BES / PAdES B-B (ETSI EN 319 122-1).

## API

The API has two steps so that the RSA operation can be replaced by an
external signer (HSM, token) without changing the CMS code.

| Function | Contract |
|---|---|
| `Cms/signed_attrs(digest, cert_der) -> List(List(u24))` | The three signed attributes, each DER encoded. |
| `Cms/to_be_signed(attrs)` | DER `SET OF` (tag `31`, elements sorted) of the attributes: the exact bytes whose SHA-256 is signed. |
| `Cms/assemble(cert, chain, attrs, signature)` | DER `ContentInfo` with the `SignedData`. `cert` is the signer `CertInfo`, `chain` a list of DER certificates. |
| `Cms/attribute(oid, value)` | `Attribute ::= SEQUENCE { oid, SET { value } }`. |

## Signed attributes

| Attribute | OID | Value |
|---|---|---|
| contentType | `1.2.840.113549.1.9.3` | `id-data` (`1.2.840.113549.1.7.1`) |
| messageDigest | `1.2.840.113549.1.9.4` | OCTET STRING with the SHA-256 of the signed PDF ranges |
| signingCertificateV2 | `1.2.840.113549.1.9.16.2.47` | `SEQUENCE { SEQUENCE OF { ESSCertIDv2 { certHash } } }`; `hashAlgorithm` is omitted because SHA-256 is the default (RFC 5035) |

`signingTime` is deliberately absent: PAdES carries the claimed signing time
in the signature dictionary (`/M`).

## Structure produced by `Cms/assemble`

```
ContentInfo SEQUENCE {
  contentType  id-signedData (1.2.840.113549.1.7.2)
  [0] SignedData SEQUENCE {
    version                 1
    digestAlgorithms        SET { sha256 + NULL }
    encapContentInfo        SEQUENCE { id-data }              (no eContent: detached)
    [0] IMPLICIT certificates   signer certificate and chain, sorted as a DER SET OF
    signerInfos SET {
      SignerInfo SEQUENCE {
        version             1
        sid                 IssuerAndSerialNumber { issuer, serialNumber }
        digestAlgorithm     sha256 + NULL
        [0] IMPLICIT signedAttrs   same content as Cms/to_be_signed, tag A0
        signatureAlgorithm  rsaEncryption + NULL
        signature           OCTET STRING
      }
    }
  }
}
```

The certificates are sorted by their encodings like any DER `SET OF`
(`Bytes/sort`), so strict DER validators accept the structure; validators find
the signer through `IssuerAndSerialNumber`, not by position.

## Constants

Every constant is a byte literal (rule P-6): `Cms/ALG_SHA256`
(`30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00`), `Cms/ALG_RSA`
(`30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00`), `Cms/ATTR_CONTENT_TYPE`,
`Cms/ENCAP_DATA`, `Cms/INT_1`, and the OID contents
`Cms/OID_SIGNED_DATA`, `Cms/OID_MESSAGE_DIGEST`, `Cms/OID_SIGNING_CERT_V2`.

## Tests

`cms_attrs_sorted` in `test.bend`; the complete structure was verified with
`openssl cms -verify` during development and is validated by pyHanko in every
end-to-end test.
