import pytest
from server.src.add_after_eof import AddAfterEOF
from conftest import make_pdf_bytes


def test_build_payload_and_roundtrip():
    m = AddAfterEOF()
    pdf = make_pdf_bytes()
    out = m.add_watermark(pdf, "secret123", "key456", position="eof")
    assert out.startswith(b"%PDF-")
    assert b"%%CUSTOM-WM-START" in out
    got = m.read_secret(out, "key456")
    assert got == "secret123"


def test_add_watermark_requires_secret_key():
    m = AddAfterEOF()
    with pytest.raises(ValueError):
        m.add_watermark(make_pdf_bytes(), secret=None, key="k")  # type: ignore
    with pytest.raises(ValueError):
        m.add_watermark(make_pdf_bytes(), secret="s", key=None)  # type: ignore


def test_add_watermark_rejects_non_pdf():
    m = AddAfterEOF()
    with pytest.raises(ValueError):
        m.add_watermark(b"notpdf", "s", "k")


def test_add_watermark_only_eof_position():
    m = AddAfterEOF()
    with pytest.raises(ValueError):
        m.add_watermark(make_pdf_bytes(), "s", "k", position="page")


def test_read_secret_errors():
    m = AddAfterEOF()
    pdf = make_pdf_bytes()
    with pytest.raises(ValueError):
        m.read_secret(pdf, "k")  # no marker

    out = m.add_watermark(pdf, "s", "k")
    with pytest.raises(ValueError):
        m.read_secret(out, "wrongk")


def test_is_applicable():
    m = AddAfterEOF()
    assert m.is_watermark_applicable(make_pdf_bytes(), position="eof")
    assert not m.is_watermark_applicable(make_pdf_bytes(), position="page")
    assert not m.is_watermark_applicable(b"nope")
