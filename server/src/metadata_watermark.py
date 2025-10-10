"""
metadata_watermark.py

Embed an authenticated payload into PDF XMP metadata (redundant invisible watermark).
Uses pikepdf when available (preferred XMP handling), falls back to PyMuPDF metadata.

Payload format: JSON (compact) base64(secret) + HMAC-SHA256 over context.
"""

from __future__ import annotations
import json
import base64
import hashlib
import hmac
from typing import Optional

# try pikepdf first (better XMP support)
try:
    import pikepdf
    _HAS_PIKEPDF = True
except Exception:
    _HAS_PIKEPDF = False

try:
    import fitz  # PyMuPDF
    _HAS_FITZ = True
except Exception:
    _HAS_FITZ = False

import io

CONTEXT = b"wm:metadata:v1:"

def _build_payload(secret: str, key: str) -> str:
    if not secret:
        raise ValueError("secret required")
    if not key:
        raise ValueError("key required")
    secret_b = secret.encode("utf-8")
    mac = hmac.new(key.encode("utf-8"), CONTEXT + secret_b, hashlib.sha256).hexdigest()
    obj = {"v": 1, "alg": "HMAC-SHA256", "mac": mac, "secret": base64.b64encode(secret_b).decode("ascii")}
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True)

class MetadataWatermark:
    name = "metadata-xmp"

    def add_watermark(self, pdf_bytes: bytes | str, secret: str, key: str, position: Optional[str]=None) -> bytes:
        """Embed payload into XMP metadata. Returns new PDF bytes."""
        payload = _build_payload(secret, key)
        # prefer pikepdf for robust XMP handling
        if _HAS_PIKEPDF:
            try:
                with pikepdf.Pdf.open(io.BytesIO(pdf_bytes)) as pdf:
                    # Use Metadata object via pikepdf
                    try:
                        xmp = pdf.open_metadata()
                        # Put our compact payload into a dedicated property in xmp meta
                        # Use a custom property name
                        xmp["/xmp:WatermarkPayload"] = payload
                        pdf.save(io.BytesIO())  # ensure metadata is set
                    except Exception:
                        # fallback: set a raw Metadata stream
                        try:
                            pdf.Root.Metadata = pdf.make_stream(payload.encode("utf-8"))
                        except Exception:
                            pass
                    out = io.BytesIO()
                    pdf.save(out)
                    return out.getvalue()
            except Exception:
                # fallback to next method
                pass

        if _HAS_FITZ:
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            m = doc.metadata
            # set a custom metadata field
            m["watermark_payload"] = payload
            doc.set_metadata(m)
            out = doc.tobytes()
            doc.close()
            return out

        # If no library available, raise
        raise RuntimeError("No PDF library available to write metadata (install pikepdf or pymupdf)")

    def read_secret(self, pdf_bytes: bytes | str, key: str) -> str:
        """Try to read and verify payload from XMP/metadata."""
        # try pikepdf
        try:
            if _HAS_PIKEPDF:
                with pikepdf.Pdf.open(io.BytesIO(pdf_bytes)) as pdf:
                    try:
                        md = pdf.open_metadata()
                        payload = None
                        # try several property names
                        for prop in ("watermark_payload", "/xmp:WatermarkPayload", "/xmp:watermark_payload"):
                            try:
                                payload = md.get(prop)
                                if payload:
                                    break
                            except Exception:
                                pass
                        if not payload:
                            # try raw Metadata stream
                            try:
                                raw = pdf.Root.Metadata.read_bytes()
                                payload = raw.decode("utf-8", errors="ignore")
                            except Exception:
                                payload = None
                        if not payload:
                            raise ValueError("No metadata payload found")
                    except Exception:
                        raise
                obj = json.loads(payload)
            elif _HAS_FITZ:
                doc = fitz.open(stream=pdf_bytes, filetype="pdf")
                m = doc.metadata
                doc.close()
                payload = m.get("watermark_payload")
                if not payload:
                    raise ValueError("No metadata payload found")
                obj = json.loads(payload)
            else:
                raise RuntimeError("No PDF library available to read metadata")
            # verify mac
            secret_b = base64.b64decode(obj["secret"].encode("ascii"))
            mac_expected = obj["mac"]
            mac_calc = hmac.new(key.encode("utf-8"), CONTEXT + secret_b, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac_calc, mac_expected):
                raise ValueError("MAC mismatch")
            return secret_b.decode("utf-8")
        except Exception as e:
            raise

__all__ = ["MetadataWatermark"]
