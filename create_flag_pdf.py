from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

flag1 = "b00c990848610833c0dd9a6288ce32bcbe48631e"  # 替换为你的flag1
c = canvas.Canvas("flag.pdf", pagesize=letter)
c.drawString(100, 750, "This is a secret flag: " + flag1)
c.save()