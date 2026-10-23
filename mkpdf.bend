from lib/bytes import *
from lib/mkpdf import *

def Main/document(text: List(u24)) -> List(u24):
  return Mk/document(Mk/pages_from(text))

def Main/read(path: String):
  with IO:
    opened <- IO/FS/open(path, "r")
    match opened:
      case Result/Ok:
        res <- IO/FS/read(opened.val, 64)
        * <- IO/FS/close(opened.val)
        match res:
          case Result/Ok:
            return wrap(Main/bytes(res.val))
          case Result/Err:
            return wrap([])
      case Result/Err:
        return wrap([])

def Main/bytes(xs: List(u24)) -> List(u24):
  return Bytes/from_io(xs)

def main():
  with IO:
    pages <- Main/read("pages.txt")
    * <- IO/FS/write_file("large.pdf", Main/document(pages))
    return wrap(0)
