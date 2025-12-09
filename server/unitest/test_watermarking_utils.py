import sys, types
import pytest
from conftest import make_pdf_bytes

# 防止 visible_text import fitz 失败
if "fitz" not in sys.modules:
    fake_fitz = types.SimpleNamespace(
        open=lambda stream, filetype="pdf": types.SimpleNamespace(
            page_count=0,
            __iter__=lambda self: iter([]),
            tobytes=lambda: stream,
            close=lambda: None,
            xref_length=lambda: 0,
        ),
        Rect=lambda *a, **k: None
    )
    sys.modules["fitz"] = fake_fitz

import server.src.watermarking_utils as wu


def test_get_method_and_aliases():
    assert wu.get_method("toy-eof").name == "trailer-hmac"
    assert wu.get_method("visible-text").name == "visible-text-redundant"
    with pytest.raises(KeyError):
        wu.get_method("nope")


def test_apply_and_read_trailer_hmac_roundtrip():
    pdf = make_pdf_bytes()
    out = wu.apply_watermark("trailer-hmac", pdf, "sec", "key", position="eof")
    assert b"%%CUSTOM-WM-START" in out
    assert wu.read_watermark("trailer-hmac", out, "key") == "sec"


def test_is_watermarking_applicable_calls_method():
    pdf = make_pdf_bytes()
    assert wu.is_watermarking_applicable("trailer-hmac", pdf, position="eof")
    assert not wu.is_watermarking_applicable("trailer-hmac", pdf, position="page")


def test_explore_pdf_fallback():
    sys.modules.pop("fitz", None)  # 强制走 regex fallback
    pdf = make_pdf_bytes(b" 1 0 obj\n<< /Type /Page >>\nendobj\n")
    tree = wu.explore_pdf(pdf)
    assert tree["type"] == "Document"
    assert any(c["id"].startswith("obj:") for c in tree["children"])
