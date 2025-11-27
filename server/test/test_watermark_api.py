# server/test/test_watermark_api.py

import io
import uuid
import os
import sys

# 把 tatou/server 加到 sys.path，保证可以 import src.server
THIS_DIR = os.path.dirname(__file__)
SERVER_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))
if SERVER_ROOT not in sys.path:
    sys.path.insert(0, SERVER_ROOT)

# from src.server import app

def _sample_pdf_bytes() -> bytes:
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"trailer\n<< >>\n"
        b"%%EOF\n"
    )

def _signup_and_login(client):
    """注册一个随机用户并登录，返回带 Authorization 的 headers"""
    email = f"wm-{uuid.uuid4().hex}@example.com"
    login = f"wm_{uuid.uuid4().hex[:8]}"
    password = "Passw0rd!"

    # 注册
    resp = client.post(
        "/api/create-user",
        json={"email": email, "login": login, "password": password},
    )
    # assert resp.status_code in (201, 409)
    assert resp.status_code == 201
    # 登录
    resp = client.post(
        "/api/login",
        json={"email": email, "password": password},
    )
    # assert resp.status_code == 200
    assert resp.status_code == 200
    token = resp.get_json()["token"]
    return {"Authorization": f"Bearer {token}"}

def test_create_and_read_watermark_roundtrip(client):
    # client = app.test_client()
    headers = _signup_and_login(client)

    # 1. 上传一个 PDF 文档
    data = {
        "file": (io.BytesIO(_sample_pdf_bytes()), "watermark_test.pdf"),
    }
    resp = client.post(
        "/api/upload-document",
        data=data,
        headers=headers,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 201
    doc_id = resp.get_json()["id"]

    # 2. 从 API 拿一个可用的水印方法名
    resp = client.get("/api/get-watermarking-methods")  # 修正端点名称
    assert resp.status_code == 200
    methods = resp.get_json()["methods"]
    assert methods
    method_name = methods[0]["name"]

    # 3. 调用 create-watermark 创建一个水印版本
    secret = "unit-test-secret"
    key = "unit-test-key"

    resp = client.post(
        f"/api/create-watermark/{doc_id}",
        json={
            "method": method_name,
            "intended_for": "pytest",
            "secret": secret,
            "key": key,
            "position": None,
        },
        headers=headers,
    )
    # 注意：根据你的 server.py，create-watermark 在成功时返回 201，不是 500
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["documentid"] == doc_id
    assert "id" in body
    assert "link" in body

    # 4. 再用 read-watermark 把 secret 读回来
    resp = client.post(
        f"/api/read-watermark/{doc_id}",
        json={
            "method": method_name,
            "key": key,
            "position": None,
        },
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["documentid"] == doc_id
    assert data["secret"] == secret