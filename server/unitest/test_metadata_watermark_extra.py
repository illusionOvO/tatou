import types
import server.src.metadata_watermark as mw
from conftest import make_pdf_bytes

def test_pikepdf_open_metadata_fails_fallback_to_raw_stream(monkeypatch):
    monkeypatch.setattr(mw, "_HAS_PIKEPDF", True)
    monkeypatch.setattr(mw, "_HAS_FITZ", False)

    class FakePdf:
        def __init__(self, bio):
            self.bio = bio
            self.Root = types.SimpleNamespace(Metadata=None)
        def open_metadata(self):
            raise RuntimeError("boom")   # 触发 except
        def make_stream(self, b):
            return b
        def save(self, out):
            out.write(self.bio.getvalue())
        def __enter__(self): return self
        def __exit__(self,*a): return False

    fake_pikepdf = types.SimpleNamespace(
        Pdf=types.SimpleNamespace(open=lambda bio: FakePdf(bio))
    )
    monkeypatch.setattr(mw, "pikepdf", fake_pikepdf, raising=False)

    m = mw.MetadataWatermark()
    out = m.add_watermark(make_pdf_bytes(), "sec", "key")
    assert out.startswith(b"%PDF-")

import types
import server.src.metadata_watermark as mw
from conftest import make_pdf_bytes

def test_pikepdf_outer_open_fails_then_use_fitz(monkeypatch):
    monkeypatch.setattr(mw, "_HAS_PIKEPDF", True)
    monkeypatch.setattr(mw, "_HAS_FITZ", True)

    # pikepdf 外层 open 直接炸
    fake_pikepdf = types.SimpleNamespace(
        Pdf=types.SimpleNamespace(open=lambda bio: (_ for _ in ()).throw(RuntimeError("boom")))
    )
    monkeypatch.setattr(mw, "pikepdf", fake_pikepdf, raising=False)

    # fitz 正常写 keywords
    class FakeDoc:
        def __init__(self):
            self.metadata = {}
        def set_metadata(self, m): self.metadata = m
        def tobytes(self): return make_pdf_bytes(b"fitz")
        def close(self): pass

    fake_fitz = types.SimpleNamespace(open=lambda stream, filetype="pdf": FakeDoc())
    monkeypatch.setattr(mw, "fitz", fake_fitz)

    m = mw.MetadataWatermark()
    out = m.add_watermark(make_pdf_bytes(), "sec", "key")
    assert b"fitz" in out

import types, pytest
import server.src.metadata_watermark as mw
from conftest import make_pdf_bytes

def test_read_secret_raw_metadata_and_json_fail(monkeypatch):
    monkeypatch.setattr(mw, "_HAS_PIKEPDF", True)
    monkeypatch.setattr(mw, "_HAS_FITZ", False)

    class FakeMetaStream:
        def read_bytes(self):
            return b"not-json-payload"  # json.loads 会炸

    class FakePdf:
        def __init__(self, bio):
            self.bio = bio
            self.Root = types.SimpleNamespace(Metadata=FakeMetaStream())
        def open_metadata(self):
            return {}   # 没有 "/xmp:WatermarkPayload" -> payload None
        def __enter__(self): return self
        def __exit__(self,*a): return False

    fake_pikepdf = types.SimpleNamespace(
        Pdf=types.SimpleNamespace(open=lambda bio: FakePdf(bio))
    )
    monkeypatch.setattr(mw, "pikepdf", fake_pikepdf, raising=False)

    m = mw.MetadataWatermark()
    with pytest.raises(Exception):
        m.read_secret(make_pdf_bytes(), "key")
