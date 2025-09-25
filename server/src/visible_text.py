"""visible_text.py

Visible text watermarking method.

This method adds a visible text overlay onto each page of the PDF document.
The text is rendered with a configurable opacity and rotation.

"""
from __future__ import annotations

import fitz  # PyMuPDF

from .watermarking_method import (
    WatermarkingMethod,
    load_pdf_bytes,
)


class VisibleTextWatermark(WatermarkingMethod):
    """Adds a visible text watermark to each page."""

    name = "visible-text"

    @staticmethod
    def get_usage() -> str:
        return "Adds a visible text watermark. The secret is used as the watermark text. Position is ignored."

    def add_watermark(
        self,
        pdf: bytes | str,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Adds a visible text watermark to each page of the PDF."""
        pdf_bytes = load_pdf_bytes(pdf)
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")

        text = secret

        for page in doc:
            # Add the watermark text
            page.insert_text(
                page.rect / 2,  # Position in the center of the page
                text,
                fontsize=50,
                rotate=45,
                color=(0.5, 0.5, 0.5),
                opacity=0.5,
                overlay=True,
            )

        return doc.tobytes()

    def is_watermark_applicable(
        self,
        pdf: bytes | str,
        position: str | None = None,
    ) -> bool:
        return True

    def read_secret(self, pdf: bytes | str, key: str) -> str:
        """This method does not support reading secrets."""
        return "Visible watermarks are not meant to be read by this tool."

__all__ = ["VisibleTextWatermark"]
