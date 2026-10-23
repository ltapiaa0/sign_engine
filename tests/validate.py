import shutil
import subprocess
import sys

import pikepdf
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import ModificationLevel
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

ALLOWED_MODIFICATIONS = {ModificationLevel.NONE, ModificationLevel.LTA_UPDATES, ModificationLevel.FORM_FILLING}


def main(path, root_pem, require_trust=True, strict=True):
    with pikepdf.open(path) as pdf:
        n_pages = len(pdf.pages)
    print(f"structure ok ({n_pages} pages)")

    root = load_cert_from_pemder(root_pem)
    vc = ValidationContext(trust_roots=[root], allow_fetching=False)
    ok = True
    with open(path, "rb") as f:
        reader = PdfFileReader(f, strict=strict)
        sigs = reader.embedded_signatures
        if not sigs:
            print("no signatures")
            return 1
        for sig in sigs:
            status = validate_pdf_signature(sig, vc)
            level = status.modification_level
            print(f"[{sig.field_name}] intact={status.intact} valid={status.valid} "
                  f"trusted={status.trusted} coverage={status.coverage.name} "
                  f"modification={level.name if level else None}")
            sd = sig.sig_object
            for key in ("/Name", "/Reason", "/Location", "/M"):
                if key in sd:
                    print(f"    {key} = {sd[key]}")
            docmdp = getattr(status, "docmdp_ok", None)
            if docmdp is not None:
                print(f"    docmdp_ok = {docmdp}")
            ok = (ok and status.intact and status.valid
                  and (status.trusted or not require_trust)
                  and level in ALLOWED_MODIFICATIONS
                  and docmdp is not False)

    if shutil.which("pdfsig"):
        out = subprocess.run(["pdfsig", path], capture_output=True, text=True).stdout
        valid = out.count("Signature is Valid")
        print(f"pdfsig: {valid} valid signature(s)")
        ok = ok and valid == len(sigs)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2], "--no-trust" not in sys.argv[3:], "--allow-hybrid" not in sys.argv[3:]))
