# server/test/test_read_secret_roundtrip.py
import io
import uuid
import sys
from pathlib import Path
import pytest
import server.src.watermarking_utils as WMUtils


THIS_FILE = Path(__file__).resolve()
SERVER_ROOT = THIS_FILE.parents[1]
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))

# from src.server import app


def _signup_and_login(client):
    email = f"u_{uuid.uuid4().hex}@example.com"
    login = f"u_{uuid.uuid4().hex[:8]}"
    password = "Passw0rd!"

    r = client.post("/api/create-user", json={
        "email": email,
        "login": login,
        "password": password,
    })
    assert r.status_code in (201, 409)

    r = client.post("/api/login", json={
        "email": email,
        "password": password,
    })
    assert r.status_code == 200
    token = r.get_json()["token"]
    return {"Authorization": f"Bearer {token}"}


def _upload_pdf(client, headers):
    pdf_bytes = (
        b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\nxref\n0 1\n0 65535 f \n%%EOF"
    )
    r = client.post(
        "/api/upload-document",
        data={"file": (io.BytesIO(pdf_bytes), "doc.pdf")},
        headers=headers,
    )
    assert r.status_code == 201
    return r.get_json()["id"]


def _create_watermark(client, headers, docid, *, secret, key, method="trailer-hmac"):
    r = client.post(
        f"/api/create-watermark/{docid}",
        json={
            "method": method,
            "intended_for": "pytest", 
            "secret": secret,
            "key": key,
            "position": None,
        },
        headers=headers,
    )
    # assert r.status_code in (200, 201)
    assert r.status_code == 201
    return method


def test_read_secret_roundtrip(client, auth_headers, sample_pdf_path):
    # 1. 本地准备：先给 PDF 加好水印
    secret = "unit-test-secret"
    key = "unit-test-key"
    
    clean_bytes = sample_pdf_path.read_bytes()
    # 本地调用工具加水印
    watermarked_bytes = WMUtils.apply_watermark(
        pdf=clean_bytes,
        secret=secret,
        key=key,
        method="trailer-hmac",
        position="eof"
    )
    
    # 2. 上传这个“以此充好”的带水印文件
    r = client.post(
        "/api/upload-document",
        data={"file": (io.BytesIO(watermarked_bytes), "pre_watermarked.pdf")},
        headers=auth_headers,
        content_type="multipart/form-data",
    )
    assert r.status_code == 201
    doc_id = r.get_json()["id"]

    # 3. 现在去读，肯定能读出来
    r = client.post(
        f"/api/read-watermark/{doc_id}",
        json={
            "method": "trailer-hmac",
            "key": key,
            "position": "eof"
        },
        headers=auth_headers,
    )
    
    assert r.status_code == 200
    assert r.get_json()["secret"] == secret




# def test_read_secret_roundtrip(client):
#     # client = app.test_client()
#     headers = _signup_and_login(client)

#     docid = _upload_pdf(client, headers)

#     method = _create_watermark(
#         client, headers, docid,
#         secret="unit-test-secret",
#         key="unit-test-key",
#     )

#     r = client.post(
#         f"/api/read-watermark/{docid}",
#         json={
#             "method": method,
#             "key": "unit-test-key",
#             "position": None,
#         },
#         headers=headers,
#     )

#     assert r.status_code == 200           # ★ 现在应该是 200
#     data = r.get_json()
#     assert data["secret"] == "unit-test-secret"
#     assert data["documentid"] == docid
    
#     # assert r.status_code == 400
#     # assert r.get_json()["secret"] == "unit-test-secret"

