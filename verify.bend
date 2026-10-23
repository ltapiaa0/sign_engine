from lib/bytes import *
from lib/verify import *

def Main/CHUNK() -> u24:
  return 1048576

def Main/reverse(xs, acc):
  match xs:
    case List/Nil:
      return acc
    case List/Cons:
      return Main/reverse(xs.tail, List/Cons(xs.head, acc))

def Main/assemble(chunks) -> List(u24):
  return Bytes/from_io(Bytes/join(Main/reverse(chunks, [])))

def Main/run(pdf: List(u24)):
  return Verify/run(pdf)

def Main/string(xs: List(u24)) -> String:
  match xs:
    case List/Nil:
      return String/Nil
    case List/Cons:
      return String/Cons(xs.head, Main/string(xs.tail))

def Main/read_chunks(fd: u24, chunks):
  with IO:
    res <- IO/FS/read(fd, Main/CHUNK)
    match res:
      case Result/Ok:
        match chunk = res.val:
          case List/Nil:
            return wrap(Main/assemble(chunks))
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

def Main/write_all(files):
  with IO:
    match files:
      case List/Nil:
        return wrap(0)
      case List/Cons:
        (name, data) = files.head
        * <- IO/FS/write_file(Main/string(name), data)
        * <- Main/write_all(files.tail)
        return wrap(0)

def main():
  with IO:
    pdf <- Main/read_file("input.pdf")
    (*, report, files) = Main/run(pdf)
    * <- Main/write_all(files)
    * <- IO/FS/write(1, report)
    * <- IO/FS/flush(1)
    return wrap(0)
