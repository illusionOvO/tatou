import io
import uuid
import sys
from pathlib import Path
import os

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
    email = f"listvers-{uuid.uuid4().hex}@example.com"
    login = f"lv_{uuid.uuid4().hex[:8]}"
    password = "Passw0rd!"

    r = client.post("/api/create-user",
                    json={"email": email, "login": login, "password": password})
    assert r.status_code in (201, 409)

    r = client.post("/api/login",
                    json={"email": email, "password": password})
    assert r.status_code == 200
    token = r.get_json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_list_versions_roundtrip(client):
    # client = app.test_client()
    headers = _signup_and_login(client)

    # 1. upload document
    data = {
        "file": (io.BytesIO(_sample_pdf_bytes()), "test.pdf"),
        "name": "mydoc"
    }
    r = client.post("/api/upload-document", headers=headers, data=data)
    assert r.status_code == 201
    docid = r.get_json()["id"]

    # 2. get a valid watermark method
    r = client.get("/api/get-watermarking-methods")
    assert r.status_code == 200
    method_name = r.get_json()["methods"][0]["name"]

    key = "unit-test-key"
    secret1 = "unit-test-secret-1"
    secret2 = "unit-test-secret-2"

    # version 1
    r = client.post(f"/api/create-watermark/{docid}",
                    headers=headers,
                    json={
                        "method": method_name,
                        "intended_for": "pytest",
                        "secret": secret1,
                        "key": key,
                        "position": None,
                    })
    assert r.status_code == 201

    # version 2
    r = client.post(f"/api/create-watermark/{docid}",
                    headers=headers,
                    json={
                        "method": method_name,
                        "intended_for": "pytest",
                        "secret": secret2,
                        "key": key,
                        "position": None,
                    })
    assert r.status_code == 201

    # list-versions
    r = client.get(f"/api/list-versions/{docid}", headers=headers)
    assert r.status_code == 200

    # >>>>> 修正点：正确取 versions 列表 <<<<<<
    versions = r.get_json()["versions"]

    assert isinstance(versions, list)
    assert len(versions) >= 2

    required_keys = {"id", "documentid", "method", "secret", "link", "intended_for"}

    for v in versions:
        assert required_keys.issubset(v.keys())
        assert v["documentid"] == docid

    # check sorted
    ids = [v["id"] for v in versions]
    assert ids == sorted(ids)
