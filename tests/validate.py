"""Valida las firmas de un PDF con pyHanko y pdfsig (si está instalado).

Uso: python3 tests/validate.py firmado.pdf certificado_raiz.pem [--no-trust]
Sale con código 0 sólo si todas las firmas son íntegras y válidas
criptográficamente (con el certificado dado como raíz de confianza).
Con --no-trust no se exige la validación de confianza (p. ej. para llaves
RSA-1024 de prueba, que la política de pyHanko rechaza).
"""
import shutil
import subprocess
import sys

import pikepdf
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext


def main(path, root_pem, require_trust=True):
    # 1. Estructura: el PDF debe abrirse sin reparaciones.
    with pikepdf.open(path) as pdf:
        n_pages = len(pdf.pages)
    print(f"estructura ok ({n_pages} páginas)")

    # 2. Firmas con pyHanko.
    root = load_cert_from_pemder(root_pem)
    vc = ValidationContext(trust_roots=[root], allow_fetching=False)
    ok = True
    with open(path, "rb") as f:
        reader = PdfFileReader(f, strict=True)
        sigs = reader.embedded_signatures
        if not sigs:
            print("sin firmas")
            return 1
        for sig in sigs:
            status = validate_pdf_signature(sig, vc)
            print(f"[{sig.field_name}] intact={status.intact} valid={status.valid} "
                  f"trusted={status.trusted} coverage={status.coverage.name} "
                  f"modification={status.modification_level.name if status.modification_level else None}")
            sd = sig.sig_object
            for key in ("/Name", "/Reason", "/Location", "/M"):
                if key in sd:
                    print(f"    {key} = {sd[key]}")
            ok = ok and status.intact and status.valid and (status.trusted or not require_trust)

    # 3. pdfsig (poppler), si está disponible.
    if shutil.which("pdfsig"):
        out = subprocess.run(["pdfsig", path], capture_output=True, text=True).stdout
        valid = out.count("Signature is Valid")
        print(f"pdfsig: {valid} firma(s) válida(s)")
        ok = ok and valid == len(sigs)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2], "--no-trust" not in sys.argv[3:]))
