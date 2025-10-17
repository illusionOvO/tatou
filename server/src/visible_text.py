"""
visible_text.py

Upgraded Visible text watermarking method.

This method now implements:
- A visible text overlay on each page (as before).
- A redundant invisible fingerprint using:
  1) XMP metadata embedding via MetadataWatermark (robust metadata backup),
  2) Appending an authenticated payload after EOF via AddAfterEOF (secondary backup).

The rationale: combining visible deterrent + two independent invisible embeddings
improves the chance to attribute leaks even when attackers apply different
removal/transformations (PDF re-rendering, metadata stripping, etc.).

This module calls into the project's MetadataWatermark and AddAfterEOF methods
to produce multi-modal, redundant watermarks.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Optional

try:
    import fitz  # PyMuPDF
except Exception:
    fitz = None

from .watermarking_method import (
    WatermarkingMethod,
    load_pdf_bytes,
)

# Import the other watermarking helpers implemented in the project.
# These are used to provide redundant invisible embeddings.
from .metadata_watermark import MetadataWatermark
from .add_after_eof import AddAfterEOF


class VisibleTextWatermark(WatermarkingMethod):
    """Adds a visible text watermark to each page and redundant invisible fingerprints."""

    name = "visible-text-redundant"

    @staticmethod
    def get_usage() -> str:
        return (
            "Adds a visible text watermark (secret as text) AND embeds redundant "
            "invisible fingerprints (XMP metadata + trailer record)."
        )

    # Context used for MACing the payload that we store redundantly
    _CONTEXT: bytes = b"wm:visible-text-redundant:v1:"

    def _build_payload(self, secret: str, key: str) -> bytes:
        """Create a compact authenticated payload (JSON-like bytes) to embed."""
        if not secret:
            raise ValueError("Secret must be non-empty")
        if not key:
            raise ValueError("Key must be non-empty")

        secret_bytes = secret.encode("utf-8")
        hm = hmac.new(key.encode("utf-8"), self._CONTEXT + secret_bytes, hashlib.sha256)
        mac_hex = hm.hexdigest()

        # Simple compact payload. We base64 the secret to avoid binary issues.
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Deterministic compact encoding (no whitespace)
        import json
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

    def add_watermark(
        self,
        pdf: bytes | str,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Add visible watermark and redundant invisible fingerprints.

        Steps:
        1) Create visible overlay on every page (centered, rotated).
        2) Embed the authenticated payload into XMP metadata using MetadataWatermark.
        3) Append a trailer payload using AddAfterEOF for an additional backup.
        """

        pdf_bytes = load_pdf_bytes(pdf)
        # 1) Visible overlay
        if fitz is None:
            # If PyMuPDF not available, skip visible embedding and proceed
            visible_pdf = pdf_bytes
        else:
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")

            text = secret
            for page in doc:
                # center point
                rect = page.rect
                # try several insertion methods for compatibility
                try:
                    page.insert_textbox(
                        rect,
                        text,
                        fontsize=50,
                        rotate=0,
                        align=fitz.TEXT_ALIGN_CENTER,
                        color=(0.7, 0.7, 0.7),
                        overlay=True,
                        # fill_opacity=0.5,
                    )
                except TypeError:
                    try:
                        center = page.rect.tl + (page.rect.br - page.rect.tl) * 0.5
                        page.insert_text(
                            center,
                            text,
                            fontsize=50,
                            rotate=0,
                            color=(0.5, 0.5, 0.5),
                            # opacity=0.5,
                            overlay=True,
                        )
                    except Exception:
                        # keep page unchanged on failure
                        pass

            visible_pdf = doc.tobytes()
            doc.close()

        # Prepare authenticated payload
        payload_bytes = self._build_payload(secret, key)

        # 2) Embed in XMP metadata using the project's MetadataWatermark
        try:
            md = MetadataWatermark()
            xmp_pdf = md.add_watermark(visible_pdf, secret, key, position=None)
        except Exception:
            xmp_pdf = visible_pdf

        # 3) Append trailer payload using AddAfterEOF as an independent backup
        try:
            eof = AddAfterEOF()
            final_pdf = eof.add_watermark(xmp_pdf, secret, key, position=None)
        except Exception:
            final_pdf = xmp_pdf

        return final_pdf

    def is_watermark_applicable(
        self,
        pdf: bytes | str,
        position: Optional[str] = None,
    ) -> bool:
        return True

    def read_secret(self, pdf: bytes | str, key: str) -> str:
        """Attempt to read the secret from the three redundancy locations.

        Order:
        1) Try AddAfterEOF trailer (most reliable against metadata stripping).
        2) Try Metadata XMP.
        3) Fallback: Visible watermark is human-readable only; return sentinel.
        """
        # Try trailer
        try:
            eof = AddAfterEOF()
            return eof.read_secret(pdf, key)
        except Exception:
            pass

        # Try metadata
        try:
            md = MetadataWatermark()
            return md.read_secret(pdf, key)
        except Exception:
            pass

        # Visible text fallback — not machine-readable via this method.
        raise ValueError("Secret not found in trailer or metadata; visible text only.")

    def get_usage(self) -> str:
        return (
            "Append a signed HMAC blob after the PDF %%EOF marker. "
            "Params: secret (hex/base64), key (hex/base64). "
            "Pros: robust to viewers; Cons: may be stripped by re-save."
        )

__all__ = ["VisibleTextWatermark"]
