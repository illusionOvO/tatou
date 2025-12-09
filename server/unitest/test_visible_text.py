import types
import server.src.visible_text as vt
from conftest import make_pdf_bytes


def test_add_visible_overlay_with_fake_fitz(monkeypatch):
    calls = {"insert": 0, "saved": False}

    class FakePage:
        def __init__(self):
            self.rect = types.SimpleNamespace(x0=0, y0=0, x1=200, y1=200)

        def insert_textbox(self, box, text, **kwargs):
            calls["insert"] += 1
            assert text == "SECRET"
            return True

    class FakeDoc:
        def __init__(self):
            self._pages = [FakePage(), FakePage()]  # 2 页

        def __iter__(self):
            return iter(self._pages)

        def tobytes(self):
            calls["saved"] = True
            return make_pdf_bytes(b"visible")

        def close(self):
            pass

    fake_fitz = types.SimpleNamespace(
        open=lambda stream, filetype="pdf": FakeDoc(),
        Rect=lambda *a, **k: object(),
    )

    monkeypatch.setattr(vt, "fitz", fake_fitz)

    m = vt.VisibleTextWatermark()
    out = m._add_visible_overlay(make_pdf_bytes(), "SECRET")

    assert out.startswith(b"%PDF-")
    assert calls["insert"] == 2
    assert calls["saved"] is True


def test_visible_text_add_watermark_roundtrip(monkeypatch):
    # 让可见部分走 fake，不测试 fitz 本体
    monkeypatch.setattr(
        vt.VisibleTextWatermark,
        "_add_visible_overlay",
        lambda self, pdf_bytes, text: pdf_bytes + b"\n%VISIBLE\n"
    )

    m = vt.VisibleTextWatermark()
    pdf = make_pdf_bytes()
    out = m.add_watermark(pdf, "sec", "key", position="page")

    # visible overlay + eof watermark
    assert b"%VISIBLE" in out
    assert b"%%CUSTOM-WM-START" in out
    assert m.read_secret(out, "key") == "sec"
