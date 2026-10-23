import os

import pikepdf
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
os.makedirs(here, exist_ok=True)

classic = os.path.join(here, "classic.pdf")
c = canvas.Canvas(classic, pagesize=A4, invariant=1)
c.setTitle("Test document")
for i in range(2):
    c.drawString(72, 760, f"Test contract - page {i + 1}")
    c.drawString(72, 740, "Digitally signed with sign_engine (Bend).")
    c.showPage()
c.save()

with pikepdf.open(classic) as pdf:
    pdf.save(os.path.join(here, "objstm.pdf"),
             object_stream_mode=pikepdf.ObjectStreamMode.generate,
             compress_streams=True, deterministic_id=True)

with pikepdf.open(classic) as pdf:
    pdf.save(os.path.join(here, "linear.pdf"), linearize=True, deterministic_id=True)

with pikepdf.open(classic) as pdf:
    page = pdf.pages[0]
    text_field = pdf.make_indirect(pikepdf.Dictionary(
        Type=pikepdf.Name.Annot, Subtype=pikepdf.Name.Widget, FT=pikepdf.Name.Tx,
        T=pikepdf.String("Name"), Rect=[72, 700, 300, 720], P=page.obj))
    link = pdf.make_indirect(pikepdf.Dictionary(Type=pikepdf.Name.Annot, Subtype=pikepdf.Name.Link,
                                                Rect=[72, 650, 200, 670], Border=[0, 0, 0]))
    page.obj.Annots = pdf.make_indirect(pikepdf.Array([text_field, link]))
    pdf.Root.AcroForm = pdf.make_indirect(pikepdf.Dictionary(
        Fields=pdf.make_indirect(pikepdf.Array([text_field]))))
    pdf.save(os.path.join(here, "forms.pdf"), deterministic_id=True)


def hybrid_pdf():
    content = b"BT /F1 18 Tf 72 720 Td (Hybrid reference file) Tj ET"
    in_stream = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    }
    header = b""
    body = b""
    for num, obj in in_stream.items():
        header += b"%d %d " % (num, len(body))
        body += obj + b"\n"
    objstm_data = header + body
    out = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}

    def emit(num, data):
        offsets[num] = len(out)
        out.extend(b"%d 0 obj\n" % num + data + b"\nendobj\n")

    emit(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> >>")
    emit(4, b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream")
    emit(5, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    emit(6, b"<< /Type /ObjStm /N 2 /First %d /Length %d >>\nstream\n" % (len(header), len(objstm_data))
         + objstm_data + b"\nendstream")
    rows = bytes([2, 0, 6, 0, 2, 0, 6, 1])
    emit(7, b"<< /Type /XRef /Size 8 /W [1 2 1] /Index [1 2] /Length %d >>\nstream\n" % len(rows)
         + rows + b"\nendstream")
    xref_at = len(out)
    out.extend(b"xref\n0 1\n0000000000 65535 f\r\n3 5\n")
    for num in range(3, 8):
        out.extend(b"%010d 00000 n\r\n" % offsets[num])
    out.extend(b"trailer\n<< /Size 8 /Root 1 0 R /XRefStm %d >>\nstartxref\n%d\n%%%%EOF\n"
               % (offsets[7], xref_at))
    return bytes(out)


with open(os.path.join(here, "hybrid.pdf"), "wb") as f:
    f.write(hybrid_pdf())

print("ok")
