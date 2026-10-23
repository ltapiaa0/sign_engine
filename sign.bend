# sign.bend
# Aplicación de línea de comandos: firma un PDF.
#
# Bend no recibe argumentos de línea de comandos, así que el programa
# trabaja sobre archivos con nombres fijos en el directorio actual:
#
#   entrada:  input.pdf, key.pem, cert.pem, params.txt (opcional)
#   salida:   output.pdf  (o error.txt con el mensaje de error)
#
# Uso:  cd <directorio-de-trabajo> && bend run-c /ruta/a/sign.bend
#       (o el binario compilado con scripts/build.sh)

from lib/bytes import *
from lib/signer import *

def read_or_empty(r):
  match r:
    case Result/Ok:
      return Bytes/from_io(r.val)
    case Result/Err:
      return []

def main():
  with IO:
    pdf <- IO/FS/read_file("input.pdf")
    key <- IO/FS/read_file("key.pem")
    cert <- IO/FS/read_file("cert.pem")
    params <- IO/FS/read_file("params.txt")
    match res = Signer/sign_pdf(read_or_empty(pdf), read_or_empty(key), read_or_empty(cert), read_or_empty(params)):
      case Result/Ok:
        * <- IO/FS/write_file("output.pdf", res.val)
        * <- IO/print("ok\n")
        return wrap(0)
      case Result/Err:
        * <- IO/FS/write_file("error.txt", String/encode_utf8(res.val))
        * <- IO/print("error: ")
        * <- IO/print(res.val)
        * <- IO/print("\n")
        return wrap(1)
