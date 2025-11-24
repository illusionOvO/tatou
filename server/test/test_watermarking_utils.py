# server/test/test_watermarking_utils.py

import json
from pathlib import Path
import pytest

import server.src.watermarking_utils as wm

@pytest.fixture
def sample_pdf(tmp_path):
    pdf = tmp_path / "sample.pdf"
    pdf.write_bytes(b"%PDF-1.4\n% Test PDF\n%%EOF\n")
    return pdf

def test_list_methods_contains_all_methods():
    # 修正：使用正确的方法获取方法列表
    methods = list(wm.METHODS.keys())
    assert isinstance(methods, list)
    assert "trailer-hmac" in methods
    assert "metadata-xmp" in methods
    assert "visible-text-redundant" in methods

def test_apply_and_read_roundtrip(sample_pdf):
    out_bytes = wm.apply_watermark(
        method="trailer-hmac",  # 修正参数顺序
        pdf=sample_pdf,         # 修正参数名
        secret="hello",
        key="mykey",
        position=None,
    )
    assert isinstance(out_bytes, bytes)
    assert out_bytes.startswith(b"%PDF-")

    # 写入文件再读取
    out_pdf = sample_pdf.parent / "out.pdf"
    out_pdf.write_bytes(out_bytes)

    extracted = wm.read_watermark(
        method="trailer-hmac",
        pdf=out_pdf,
        key="mykey",
    )
    assert extracted == "hello"

def test_apply_watermark_rejects_unknown_method(sample_pdf):
    with pytest.raises(KeyError):  # 修正异常类型
        wm.apply_watermark(
            method="BAD-METHOD",
            pdf=sample_pdf,
            secret="x",
            key="k",
        )

def test_is_watermarking_applicable_true_for_all_methods(sample_pdf):
    for m in wm.METHODS:
        # 使用正确的函数名和参数
        applicable = wm.is_watermarking_applicable(
            method=m,
            pdf=sample_pdf,
            position=None
        )
        assert applicable is True

def test_explore_pdf_returns_dict(sample_pdf):
    # 测试 explore_pdf 函数
    data = wm.explore_pdf(sample_pdf)
    assert isinstance(data, dict)
    assert "id" in data
    assert "type" in data
    assert data["type"] == "Document"