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
from .watermarking_method import load_pdf_bytes, is_pdf_bytes

CONTEXT = b"wm:trailer:v1:"

class AddAfterEOF:
    # 与后端注册的名字保持一致
    name = "trailer-hmac"

    def _build_payload(self, secret: str, key: str) -> str:
        sb = secret.encode("utf-8")
        mac = hmac.new(key.encode("utf-8"), CONTEXT + sb, hashlib.sha256).hexdigest()
        obj = {"v": 1, "alg": "HMAC-SHA256", "mac": mac,
               "secret": base64.b64encode(sb).decode("ascii")}
        return base64.b64encode(
            json.dumps(obj, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")

    # 关键点1：接受关键字 pdf；其余冗余参数用 **kwargs 吃掉，避免报 unexpected kw
    # # 关键点2：统一用 load_pdf_bytes 解析各种输入
    # def add_watermark(
    #     self, *, pdf, secret: str, key: str, position: Optional[str] = None, **kwargs
    # ) -> bytes:
    #     data = load_pdf_bytes(pdf)
    #     if not is_pdf_bytes(data):
    #         raise ValueError("Not a PDF")

    #     # 仅接受 eof（与 is_watermark_applicable 一致）
    #     if position is not None and position.lower() != "eof":
    #         raise ValueError("position must be 'eof' for trailer-hmac")

    #     # 可选：确保 EOF 后有换行，更稳
    #     if not data.endswith(b"\n") and not data.endswith(b"\r"):
    #         data += b"\n"

    #     payload_b64 = self._build_payload(secret, key).encode("ascii")
    #     marker_start = b"%%CUSTOM-WM-START\n"
    #     marker_end = b"\n%%CUSTOM-WM-END\n"
    #     return data + marker_start + payload_b64 + marker_end

    def add_watermark(self, *args, **kwargs) -> bytes:
        # 位置参数解析
        pdf = secret = key = None
        position = None
        if args:
            # 按当前 utils 的调用顺序：pdf_bytes, secret, key, position
            if len(args) >= 1: pdf = args[0]
            if len(args) >= 2: secret = args[1]
            if len(args) >= 3: key = args[2]
            if len(args) >= 4: position = args[3]

        # 覆盖/补全关键字参数
        pdf = kwargs.get("pdf", kwargs.get("pdf_bytes", pdf))
        secret = kwargs.get("secret", secret)
        key = kwargs.get("key", key)
        position = kwargs.get("position", position)

        # 校验
        if secret is None or key is None:
            raise ValueError("secret and key are required")
        data = load_pdf_bytes(pdf)
        if not is_pdf_bytes(data):
            raise ValueError("not a PDF")

        # 仅接受 EOF 位置
        if position is not None and str(position).lower() != "eof":
            raise ValueError("position must be 'eof' for trailer-hmac")

        # 确保末尾换行，便于追加
        if not data.endswith((b"\n", b"\r")):
            data += b"\n"

        payload_b64 = self._build_payload(secret, key).encode("ascii")
        marker_start = b"%%CUSTOM-WM-START\n"
        marker_end = b"\n%%CUSTOM-WM-END\n"
        return data + marker_start + payload_b64 + marker_end


    # 同理：read_secret 也接受关键字 pdf，并吞掉多余关键字
    # def read_secret(self, *, pdf, key: str, **kwargs) -> str:
    # def read_secret(self, *, pdf=None, pdf_bytes=None, key: str, **kwargs) -> str:
    #     # data = load_pdf_bytes(pdf)
    #     data = pdf_bytes if pdf_bytes is not None else load_pdf_bytes(pdf)
    #     if not is_pdf_bytes(data):
    #         raise ValueError("Not a PDF")

    #     idx = data.rfind(b"%%CUSTOM-WM-START")
    #     if idx < 0:
    #         raise ValueError("Trailer watermark not found")
    #     start = data.find(b"\n", idx) + 1
    #     end = data.find(b"\n%%CUSTOM-WM-END", start)
    #     if end < 0:
    #         raise ValueError("Trailer end marker missing")

    #     payload_b64 = data[start:end].strip()
    #     try:
    #         decoded = base64.b64decode(payload_b64)
    #         obj = json.loads(decoded.decode("utf-8"))
    #     except Exception:
    #         raise ValueError("Invalid trailer payload")

    #     mac_expected = obj["mac"]
    #     secret_b = base64.b64decode(obj["secret"].encode("ascii"))
    #     mac_calc = hmac.new(key.encode("utf-8"), CONTEXT + secret_b, hashlib.sha256).hexdigest()
    #     if not hmac.compare_digest(mac_calc, mac_expected):
    #         raise ValueError("Trailer MAC mismatch")
    #     return secret_b.decode("utf-8")
    
    def read_secret(self, *args, **kwargs) -> str:
        pdf = key = None
        if args:
            if len(args) >= 1: pdf = args[0]
            if len(args) >= 2: key = args[1]
        pdf = kwargs.get("pdf", kwargs.get("pdf_bytes", pdf))
        key = kwargs.get("key", key)
        if key is None:
            raise ValueError("key is required")

        data = load_pdf_bytes(pdf)
        if not is_pdf_bytes(data):
            raise ValueError("not a PDF")

        # 解析 trailer（与 _build_payload 对应）
        try:
            start = data.rindex(b"%%CUSTOM-WM-START\n")
            end = data.index(b"\n%%CUSTOM-WM-END\n", start)
        except ValueError:
            raise ValueError("watermark not found")

        payload_b64 = data[start + len(b"%%CUSTOM-WM-START\n"):end]
        obj = json.loads(base64.b64decode(payload_b64))
        mac_expected = hmac.new(key.encode("utf-8"),
                                CONTEXT + base64.b64decode(obj["secret"]),
                                hashlib.sha256).hexdigest()
        if obj.get("mac") != mac_expected:
            raise ValueError("MAC verification failed")
        return base64.b64decode(obj["secret"]).decode("utf-8")

    # 也改一下签名：接受 pdf 关键字（或位置参数），其余丢给 **kwargs
    def is_watermark_applicable(self, pdf, position: str | None = None, **kwargs) -> bool:
        try:
            data = load_pdf_bytes(pdf)
        except Exception:
            return False
        if not is_pdf_bytes(data):
            return False
        if position is not None and position.lower() != "eof":
            return False
        return True



__all__ = ["AddAfterEOF"]
