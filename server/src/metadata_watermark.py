"""metadata_watermark.py

Robust invisible watermarking method using PDF metadata.

This method embeds the secret into the PDF's XMP metadata. The payload is
authenticated using HMAC-SHA256 to ensure integrity.

"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

import fitz  # PyMuPDF

from .watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class MetadataWatermark(WatermarkingMethod):
    """Embeds a secret in the PDF's XMP metadata."""

    name = "metadata"

    _CONTEXT: bytes = b"wm:metadata:v1:"

    @staticmethod
    def get_usage() -> str:
        return "Embeds a secret in the PDF's XMP metadata. Position is ignored."

    def add_watermark(
        self,
        pdf: bytes | str,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Embeds the secret into the PDF's metadata."""
        pdf_bytes = load_pdf_bytes(pdf)
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")

        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not key:
            raise ValueError("Key must be a non-empty string")

        secret_bytes = secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)

        payload = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }

        # Embed the payload in a custom XMP namespace
        xmp_data = doc.xmp_metadata or ""
        # A simple way to add a custom property. For production, a proper XMP library would be better.
        # This is a simplistic approach for demonstration.
        watermark_tag = f"<pdfwm:watermark>{base64.b64encode(json.dumps(payload).encode('utf-8')).decode('ascii')}</pdfwm:watermark>"
        if "<rdf:RDF" in xmp_data:
            # A crude way to inject into existing XMP
            xmp_data = xmp_data.replace("</rdf:Description>", f"{watermark_tag}</rdf:Description>")
        else:
            xmp_data = f"""<?xpacket begin='\ufeff' id='W5M0MpCehiHzreSzNTczkc9d'?>
<x:xmpmeta xmlns:x='adobe:ns:meta/'>
<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>
  <rdf:Description rdf:about='' xmlns:pdfwm='http://ns.example.com/pdfwm/1.0/'>
    {watermark_tag}
  </rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end='w'?>"""

        doc.set_xmp_metadata(xmp_data)
        return doc.tobytes()

    def is_watermark_applicable(
        self,
        pdf: bytes | str,
        position: str | None = None,
    ) -> bool:
        return True

    def read_secret(self, pdf: bytes | str, key: str) -> str:
        """Reads the secret from the PDF's metadata."""
        pdf_bytes = load_pdf_bytes(pdf)
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")

        xmp = doc.xmp_metadata
        if not xmp:
            raise SecretNotFoundError("No XMP metadata found in PDF")

        # A crude way to find our tag
        start_tag = "<pdfwm:watermark>"
        end_tag = "</pdfwm:watermark>"
        start_index = xmp.find(start_tag)
        if start_index == -1:
            raise SecretNotFoundError("Watermark tag not found in XMP metadata")

        end_index = xmp.find(end_tag, start_index)
        if end_index == -1:
            raise SecretNotFoundError("Malformed watermark tag in XMP metadata")

        b64_payload = xmp[start_index + len(start_tag):end_index]

        try:
            payload_json = base64.b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")

        try:
            mac_hex = str(payload["mac"])
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")

    def _mac_hex(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("utf-8"), self._CONTEXT + secret_bytes, hashlib.sha256)
        return hm.hexdigest()

__all__ = ["MetadataWatermark"]
