import sys

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pyhanko.sign.fields import MDPPerm


def main(source, target, key, cert, permission):
    signer = signers.SimpleSigner.load(key, cert)
    meta = signers.PdfSignatureMetadata(field_name="Certification", certify=True,
                                        docmdp_permissions=MDPPerm[permission])
    with open(source, "rb") as src, open(target, "wb") as out:
        signers.sign_pdf(IncrementalPdfFileWriter(src), meta, signer=signer, output=out)


if __name__ == "__main__":
    main(*sys.argv[1:6])
