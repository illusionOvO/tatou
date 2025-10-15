"""
add_after_eof.py

Append a clearly-delimited, authenticated JSON trailer after the PDF EOF.
This is intended as a robust backup that survives some metadata stripping,
and is easy to detect programmatically.

Format appended:
\n%%CUSTOM-WM-START\n<base64(json_payload)>\n%%CUSTOM-WM-END\n

Where json_payload = {"v":1,"mac":HMAC,"secret":base64(secret)}
"""

from __future__ import annotations
import json, base64, hmac, hashlib
from typing import Optional

CONTEXT = b"wm:trailer:v1:"

class AddAfterEOF:
    name = "trailer-hmac"

    def _build_payload(self, secret: str, key: str) -> str:
        sb = secret.encode("utf-8")
        mac = hmac.new(key.encode("utf-8"), CONTEXT + sb, hashlib.sha256).hexdigest()
        obj = {"v":1, "alg":"HMAC-SHA256", "mac":mac, "secret": base64.b64encode(sb).decode("ascii")}
        return base64.b64encode(json.dumps(obj, separators=(",",":")).encode("utf-8")).decode("ascii")

    def add_watermark(self, pdf_bytes: bytes | str, secret: str, key: str, position: Optional[str]=None) -> bytes:
        if isinstance(pdf_bytes, str):
            pdf_bytes = pdf_bytes.encode("utf-8")
        payload_b64 = self._build_payload(secret, key).encode("ascii")
        marker_start = b"\n%%CUSTOM-WM-START\n"
        marker_end = b"\n%%CUSTOM-WM-END\n"
        return pdf_bytes + marker_start + payload_b64 + marker_end

    def read_secret(self, pdf_bytes: bytes | str, key: str) -> str:
        if isinstance(pdf_bytes, str):
            pdf_bytes = pdf_bytes.encode("utf-8")
        idx = pdf_bytes.rfind(b"%%CUSTOM-WM-START")
        if idx < 0:
            raise ValueError("Trailer watermark not found")
        start = pdf_bytes.find(b"\n", idx) + 1
        end = pdf_bytes.find(b"\n%%CUSTOM-WM-END", start)
        if end < 0:
            raise ValueError("Trailer end marker missing")
        payload_b64 = pdf_bytes[start:end].strip()
        try:
            decoded = base64.b64decode(payload_b64)
            obj = json.loads(decoded.decode("utf-8"))
        except Exception:
            raise ValueError("Invalid trailer payload")
        mac_expected = obj["mac"]
        secret_b = base64.b64decode(obj["secret"].encode("ascii"))
        mac_calc = hmac.new(key.encode("utf-8"), CONTEXT + secret_b, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac_calc, mac_expected):
            raise ValueError("Trailer MAC mismatch")
        return secret_b.decode("utf-8")

__all__ = ["AddAfterEOF"]
