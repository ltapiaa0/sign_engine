from lib/bytes import *
from lib/signer import *

def Main/CHUNK() -> u24:
  return 1048576

def Main/reverse(xs, acc):
  match xs:
    case List/Nil:
      return acc
    case List/Cons:
      return Main/reverse(xs.tail, List/Cons(xs.head, acc))

def Main/read_chunks(fd: u24, chunks):
  with IO:
    res <- IO/FS/read(fd, Main/CHUNK)
    match res:
      case Result/Ok:
        match chunk = res.val:
          case List/Nil:
            return wrap(Bytes/from_io(Bytes/join(Main/reverse(chunks, []))))
          case List/Cons:
            return Main/read_chunks(fd, List/Cons(chunk, chunks))
      case Result/Err:
        return wrap([])

def Main/read_file(path: String):
  with IO:
    opened <- IO/FS/open(path, "r")
    match opened:
      case Result/Ok:
        data <- Main/read_chunks(opened.val, [])
        * <- IO/FS/close(opened.val)
        return wrap(data)
      case Result/Err:
        return wrap([])

def main():
  with IO:
    pdf <- Main/read_file("input.pdf")
    key <- Main/read_file("key.pem")
    cert <- Main/read_file("cert.pem")
    params <- Main/read_file("params.txt")
    match res = Signer/sign_pdf(pdf, key, cert, params):
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
