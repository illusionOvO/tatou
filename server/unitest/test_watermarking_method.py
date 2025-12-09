import io
import pytest
from server.src.watermarking_method import load_pdf_bytes, is_pdf_bytes, WatermarkingMethod
from conftest import make_pdf_bytes


def test_is_pdf_bytes():
    assert is_pdf_bytes(make_pdf_bytes())
    assert not is_pdf_bytes(b"hello")


def test_load_pdf_bytes_from_bytes_and_file_and_path(tmp_path):
    b = make_pdf_bytes()
    assert load_pdf_bytes(b) == b

    f = io.BytesIO(b)
    assert load_pdf_bytes(f) == b

    p = tmp_path / "a.pdf"
    p.write_bytes(b)
    assert load_pdf_bytes(str(p)) == b


def test_load_pdf_bytes_rejects_non_pdf(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"nope")
    with pytest.raises(ValueError):
        load_pdf_bytes(str(p))
    with pytest.raises(TypeError):
        load_pdf_bytes(123)  # type: ignore


def test_abstract_cannot_instantiate():
    with pytest.raises(TypeError):
        WatermarkingMethod()  # type: ignore
