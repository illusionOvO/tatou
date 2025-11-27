import io
import uuid
import os
import sys
from pathlib import Path

# 让 Python 能找到 src/server
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
    email = f"listall-{uuid.uuid4().hex}@example.com"
    login = f"la_{uuid.uuid4().hex[:8]}"
    password = "Passw0rd!"

    # create-user
    r = client.post(
        "/api/create-user",
        json={"email": email, "login": login, "password": password},
    )
    assert r.status_code in (201, 409)

    # login
    r = client.post(
        "/api/login",
        json={"email": email, "password": password},
    )
    assert r.status_code == 200
    token = r.get_json()["token"]
    return {"Authorization": f"Bearer {token}"}


def _upload_pdf(client, headers, name: str) -> int:
    data = {
        "file": (io.BytesIO(_sample_pdf_bytes()), f"{name}.pdf"),
        "name": name,
    }
    r = client.post("/api/upload-document", headers=headers, data=data)
    assert r.status_code == 201
    return r.get_json()["id"]


def _create_watermark(client, headers, docid: int, method_name: str, key: str, secret: str):
    r = client.post(
        f"/api/create-watermark/{docid}",
        headers=headers,
        json={
            "method": method_name,
            "intended_for": "pytest",
            "secret": secret,
            "key": key,
            "position": None,
        },
    )
    assert r.status_code == 201


def test_list_all_versions_roundtrip(client):
    # client = app.test_client()
    headers = _signup_and_login(client)

    # ---------- 0. 拿一个合法 watermark 方法 ----------
    r = client.get("/api/get-watermarking-methods")
    assert r.status_code == 200
    methods = r.get_json()["methods"]
    assert methods
    method_name = methods[0]["name"]
    key = "unit-test-key"

    # ---------- 1. 上传两个文档 ----------
    docid1 = _upload_pdf(client, headers, "docA")
    docid2 = _upload_pdf(client, headers, "docB")

    # ---------- 2. 各创建一个版本 ----------
    _create_watermark(client, headers, docid1, method_name, key, "secret-1")
    _create_watermark(client, headers, docid2, method_name, key, "secret-2")

    # ---------- 3. list-all-versions ----------
    r = client.get("/api/list-all-versions", headers=headers)
    assert r.status_code == 200

    data = r.get_json()
    # 你的后端大概率是 {"versions": [...]}，兼容两种写法
    if isinstance(data, dict) and "versions" in data:
        versions = data["versions"]
    else:
        versions = data

    assert isinstance(versions, list)
    assert len(versions) >= 2

    # 实际返回字段（根据 server 实际行为来）
    required_keys = {"id", "documentid", "method", "link", "intended_for"}

    for v in versions:
        assert required_keys.issubset(v.keys())
        assert v["documentid"] in (docid1, docid2)
        # assert v["secret"].startswith("secret-")
        assert "secret" not in v.keys()