import json
import base64
import types
import pytest
import server.src.metadata_watermark as mw
from conftest import make_pdf_bytes


def test_read_secret_fitz_branch_success(monkeypatch):
    # 强制走 fitz 分支
    monkeypatch.setattr(mw, "_HAS_PIKEPDF", False)
    monkeypatch.setattr(mw, "_HAS_FITZ", True)

    secret = "hello"
    key = "k"
    payload = mw._build_payload(secret, key)

    class FakeDoc:
        metadata = {"keywords": payload}
        def close(self): pass

    fake_fitz = types.SimpleNamespace(
        open=lambda stream, filetype="pdf": FakeDoc()
    )
    monkeypatch.setattr(mw, "fitz", fake_fitz)

    m = mw.MetadataWatermark()
    assert m.read_secret(make_pdf_bytes(), key) == secret


def test_read_secret_mac_mismatch(monkeypatch):
    monkeypatch.setattr(mw, "_HAS_PIKEPDF", False)
    monkeypatch.setattr(mw, "_HAS_FITZ", True)

    # 构造一个 payload，但用错误 key 来读 -> MAC mismatch
    secret = "hello"
    payload = mw._build_payload(secret, "right_key")

    class FakeDoc:
        metadata = {"keywords": payload}
        def close(self): pass

    fake_fitz = types.SimpleNamespace(
        open=lambda stream, filetype="pdf": FakeDoc()
    )
    monkeypatch.setattr(mw, "fitz", fake_fitz)

    m = mw.MetadataWatermark()
    with pytest.raises(ValueError):
        m.read_secret(make_pdf_bytes(), "wrong_key")
