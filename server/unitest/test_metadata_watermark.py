import types
import pytest
import server.src.metadata_watermark as mw
from conftest import make_pdf_bytes


def test_build_payload_validation():
    with pytest.raises(ValueError):
        mw._build_payload("", "k")
    with pytest.raises(ValueError):
        mw._build_payload("s", "")


def test_add_and_read_with_fake_pikepdf(monkeypatch):
    last_payload = {"value": None}  # 用来跨 open/save 传递 payload

    class FakeMeta(dict):
        pass

    class FakePdf:
        def __init__(self, bio, for_read=False):
            self.bio = bio
            self.Root = types.SimpleNamespace(Metadata=None)
            self._meta = FakeMeta()
            if for_read and last_payload["value"] is not None:
                # read_secret() 时能读到
                self._meta["/xmp:WatermarkPayload"] = last_payload["value"]

        def open_metadata(self):
            return self._meta

        def make_stream(self, b):
            return b

        def save(self, out):
            # add_watermark() save 时把 meta 里的 payload 记下来
            last_payload["value"] = self._meta.get("/xmp:WatermarkPayload")
            out.write(self.bio.getvalue() + b"\n%fake-saved")

        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_open(bio):
        # 如果 bytes 里出现 fake-saved，就认为是 read 流程
        data = bio.getvalue()
        for_read = b"%fake-saved" in data
        return FakePdf(bio, for_read=for_read)

    fake_pikepdf = types.SimpleNamespace(
        Pdf=types.SimpleNamespace(open=fake_open)
    )

    monkeypatch.setattr(mw, "pikepdf", fake_pikepdf, raising=False)
    monkeypatch.setattr(mw, "_HAS_PIKEPDF", True)
    monkeypatch.setattr(mw, "_HAS_FITZ", False)

    m = mw.MetadataWatermark()
    out = m.add_watermark(make_pdf_bytes(), "sec", "key")
    assert out.startswith(b"%PDF-")
    assert m.read_secret(out, "key") == "sec"


def test_add_watermark_no_libs(monkeypatch):
    monkeypatch.setattr(mw, "_HAS_PIKEPDF", False)
    monkeypatch.setattr(mw, "_HAS_FITZ", False)
    m = mw.MetadataWatermark()
    with pytest.raises(RuntimeError):
        m.add_watermark(make_pdf_bytes(), "s", "k")


def test_is_applicable_depends_on_libs(monkeypatch):
    monkeypatch.setattr(mw, "_HAS_PIKEPDF", False)
    monkeypatch.setattr(mw, "_HAS_FITZ", False)
    m = mw.MetadataWatermark()
    assert not m.is_watermark_applicable(make_pdf_bytes())

    monkeypatch.setattr(mw, "_HAS_PIKEPDF", True)
    assert m.is_watermark_applicable(make_pdf_bytes())
