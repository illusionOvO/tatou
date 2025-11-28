from __future__ import annotations
import inspect
from pathlib import Path
import pytest

# 直接导入你自己的三种方法
from server.src.add_after_eof import AddAfterEOF
from server.src.visible_text import VisibleTextWatermark
from server.src.metadata_watermark import MetadataWatermark 

# --------- 明确列出要测试的方法 ----------

CASES: list[tuple[str, object]] = [
    ("trailer-hmac", AddAfterEOF),
    ("visible-text-redundant", VisibleTextWatermark),
    ("metadata-xmp", MetadataWatermark),   
]

# --------- fixtures ----------

# (注意：这里没有任何 sample_pdf_path 的定义，这正是我们想要的！)

@pytest.fixture(scope="session")
def secret() -> str:
    return "unit-test-secret"

@pytest.fixture(scope="session")
def key() -> str:
    return "unit-test-key"

def _as_instance(impl: object) -> object:
    if inspect.isclass(impl):
        return impl() 
    return impl

# --------- parameterization over all methods ----------

@pytest.mark.parametrize("method_name,impl", CASES, ids=[n for n, _ in CASES])
class TestAllWatermarkingMethods:
    def test_is_watermark_applicable(
        self, method_name: str, impl: object, sample_pdf_path: Path
    ):
        wm_impl = _as_instance(impl)
        ok = wm_impl.is_watermark_applicable(sample_pdf_path, position=None)
        assert isinstance(ok, bool), f"{method_name}: is_watermark_applicable must return bool"
        if not ok:
            pytest.skip(f"{method_name}: not applicable to the sample PDF")

    def test_add_watermark_and_shape(
        self,
        method_name: str,
        impl: object,
        sample_pdf_path: Path,
        secret: str,
        key: str,
    ):
        wm_impl = _as_instance(impl)
        if not wm_impl.is_watermark_applicable(sample_pdf_path, position=None):
            pytest.skip(f"{method_name}: not applicable to the sample PDF")

        original = sample_pdf_path.read_bytes()
        out_bytes = wm_impl.add_watermark(
            sample_pdf_path,
            secret=secret,
            key=key,
            position=None,
        )
        
        assert isinstance(
            out_bytes, (bytes, bytearray)
        ), f"{method_name}: add_watermark must return bytes"

        # 对大多数方法，水印后字节数应该不小于原文件
        if method_name != "metadata-xmp":
            assert len(out_bytes) >= len(
                original
            ), f"{method_name}: watermarked bytes should not be smaller than input"

        assert out_bytes.startswith(
            b"%PDF-"
        ), f"{method_name}: output should still look like a PDF"


    def test_read_secret_roundtrip(
        self,
        method_name: str,
        impl: object,
        sample_pdf_path: Path,
        secret: str,
        key: str,
        tmp_path: Path,
    ):
        wm_impl = _as_instance(impl)
        if not wm_impl.is_watermark_applicable(sample_pdf_path, position=None):
            pytest.skip(f"{method_name}: not applicable to the sample PDF")

        out_pdf = tmp_path / f"{method_name}_watermarked.pdf"
        out_pdf.write_bytes(
            wm_impl.add_watermark(
                sample_pdf_path,
                secret=secret,
                key=key,
                position=None,
            )
        )
        extracted = wm_impl.read_secret(out_pdf, key=key)
        assert isinstance(extracted, str), f"{method_name}: read_secret must return str"
        assert extracted == secret, (
            f"{method_name}: read_secret should return the exact embedded secret"
        )