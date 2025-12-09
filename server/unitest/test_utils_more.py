import pytest
import server.src.watermarking_utils as wu
from conftest import make_pdf_bytes


def test_methods_and_aliases_exist():
    assert "trailer-hmac" in wu.METHODS
    assert "toy-eof" in wu.ALIASES
    assert wu.get_method("toy-eof").name == "trailer-hmac"


def test_apply_unknown_method_raises():
    with pytest.raises(KeyError):
        wu.apply_watermark("nope", make_pdf_bytes(), "s", "k")
