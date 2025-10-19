# server/src/visible_text.py
from __future__ import annotations
from typing import Optional, Union

import fitz  # PyMuPDF (>=1.24)

from .watermarking_method import WatermarkingMethod, load_pdf_bytes
from .add_after_eof import AddAfterEOF

BytesLike = Union[bytes, bytearray, memoryview]
PdfInput = Union[str, BytesLike]


class VisibleTextWatermark(WatermarkingMethod):
    """
    最简实现（新版 PyMuPDF）：
    - 可见：每页居中叠加 `secret` 文字；
    - 机读：仅使用 EOF trailer 作为单一路径（AddAfterEOF）。
    """
    name = "visible-text-redundant"
    _CONTEXT: bytes = b"wm:vtext:minimal:v1:"

    @staticmethod
    def get_usage() -> str:
        return "Adds centered visible text on each page, and stores an HMACed payload in EOF trailer."


    def _add_visible_overlay(self, pdf_bytes: bytes, text: str) -> bytes:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        ALIGN_CENTER = 1  # 0=left, 1=center, 2=right, 3=justify
        for page in doc:
            rect = page.rect
            # 适度留白，避免贴边
            margin = 36
            box = fitz.Rect(rect.x0 + margin, rect.y0 + margin, rect.x1 - margin, rect.y1 - margin)
            page.insert_textbox(
                box,
                text,
                fontsize=48,
                align=ALIGN_CENTER,
                rotate=0,
                color=(0.6, 0.6, 0.6),
                overlay=True,
            )
        try:
            return doc.tobytes()
        finally:
            doc.close()

    # ------- main API -------
    def add_watermark(
        self,
        pdf: bytes | str,
        secret: str,
        key: str,
        position: Optional[str] = None,  # 保留签名兼容
    ) -> bytes:
        data = load_pdf_bytes(pdf)
        # 1) 可见水印（最新版 PyMuPDF）
        visible_pdf = self._add_visible_overlay(data, secret)
        # 2) 机读通道：仅 EOF trailer（最简 & 稳定）
        # payload = self._build_payload(secret, key)
        final_pdf = AddAfterEOF().add_watermark(pdf=visible_pdf, secret=secret, key=key, position="eof")
        return final_pdf

    def is_watermark_applicable(self, pdf: bytes | str, position: Optional[str] = None) -> bool:
        return True

    def read_secret(self, pdf: bytes | str, key: str) -> str:
        # 仅从 EOF trailer 读取（与 AddAfterEOF 的实现一致）
        return AddAfterEOF().read_secret(pdf=pdf, key=key)
