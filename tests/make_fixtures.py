"""Genera los PDFs de prueba en tests/fixtures/.

- classic.pdf : tabla xref clásica (reportlab)
- objstm.pdf  : xref stream + object streams comprimidos (pikepdf)
- linear.pdf  : PDF linealizado (dos secciones xref + hint stream)
- forms.pdf   : /AcroForm y /Annots como objetos indirectos, con un campo
                de texto y una anotación existentes
"""
import os
import pikepdf
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
os.makedirs(here, exist_ok=True)

classic = os.path.join(here, "classic.pdf")
c = canvas.Canvas(classic, pagesize=A4, invariant=1)
c.setTitle("Documento de prueba")
for i in range(2):
    c.drawString(72, 760, f"Contrato de prueba - pagina {i + 1}")
    c.drawString(72, 740, "Firmado digitalmente con sign_engine (Bend).")
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
        T=pikepdf.String("Nombre"), Rect=[72, 700, 300, 720], P=page.obj))
    link = pikepdf.Dictionary(Type=pikepdf.Name.Annot, Subtype=pikepdf.Name.Link,
                              Rect=[72, 650, 200, 670], Border=[0, 0, 0])
    page.obj.Annots = pdf.make_indirect(pikepdf.Array([text_field, link]))
    pdf.Root.AcroForm = pdf.make_indirect(pikepdf.Dictionary(
        Fields=pdf.make_indirect(pikepdf.Array([text_field]))))
    pdf.save(os.path.join(here, "forms.pdf"), deterministic_id=True)
print("ok")
