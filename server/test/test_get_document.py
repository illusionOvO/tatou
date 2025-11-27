# server/test/test_get_document.py

import io
import uuid
import os
import sys
from pathlib import Path

# 1. 把 tatou/server 加到 sys.path，保证可以 import src.server
ROOT = Path(__file__).resolve().parents[1]   # .../tatou/server
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# from src.server import app  # 这里拿到 Flask app 实例


def _sample_pdf_bytes() -> bytes:
    # 一个最小 “看起来像 PDF” 的内容，足够通过 upload 的校验
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<<>>\nendobj\n"
        b"xref\n0 2\n0000000000 65535 f \n0000000010 00000 n \n"
        b"trailer\n<<>>\nstartxref\n20\n%%EOF"
    )


def _signup_and_login(client):
    """注册一个随机用户并登录，返回带 Authorization 的 headers"""
    email = f"getdoc-{uuid.uuid4().hex}@example.com"
    login = f"getdoc_{uuid.uuid4().hex[:8]}"
    password = "Passw0rd!"

    # 注册
    r = client.post(
        "/api/create-user",
        json={"email": email, "login": login, "password": password},
    )
    assert r.status_code in (201, 409)

    # 登录
    r = client.post(
        "/api/login",
        json={"email": email, "password": password},
    )
    assert r.status_code == 200
    token = r.get_json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_get_document_roundtrip(client):
    # client = app.test_client()
    headers = _signup_and_login(client)

    # 1. 先上传一个 PDF
    resp = client.post(
        "/api/upload-document",
        data={"file": (io.BytesIO(_sample_pdf_bytes()), "getdoc_test.pdf")},
        headers=headers,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 201
    doc_id = resp.get_json()["id"]

    # 2. 用 get-document 取回来
    resp = client.get(f"/api/get-document/{doc_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.mimetype == "application/pdf"

    # 3. 简单检查内容格式
    body = resp.data
    assert body.startswith(b"%PDF")
