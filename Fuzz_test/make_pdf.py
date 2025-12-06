# Fuzz_test/make_pdf.py
with open("Test.pdf", "wb") as f:
    f.write(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n")
print("Created Test.pdf")
