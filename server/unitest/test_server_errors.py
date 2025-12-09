import io
import pytest
from conftest import make_pdf_bytes


def _login(app, client):
    client.post("/api/create-user",
                json={"login": "a", "email": "a@b.com", "password": "pw"})
    r = client.post("/api/login", json={"email": "a@b.com", "password": "pw"})
    return r.get_json()["token"]


def test_upload_reject_non_pdf(app_client):
    app, client = app_client
    token = _login(app, client)
    headers = {"Authorization": f"Bearer {token}"}

    data = {"file": (io.BytesIO(b"not pdf"), "x.bin")}
    r = client.post("/api/upload-document", data=data, headers=headers,
                    content_type="multipart/form-data")
    assert r.status_code == 400


def test_get_document_not_found(app_client):
    app, client = app_client
    token = _login(app, client)
    headers = {"Authorization": f"Bearer {token}"}

    r = client.get("/api/get-document/9999", headers=headers)
    assert r.status_code in (404, 403)


def test_delete_document_not_found(app_client):
    app, client = app_client
    token = _login(app, client)
    headers = {"Authorization": f"Bearer {token}"}

    r = client.delete("/api/delete-document/9999", headers=headers)
    assert r.status_code in (404, 403)


def test_create_watermark_missing_fields(app_client):
    app, client = app_client
    token = _login(app, client)
    headers = {"Authorization": f"Bearer {token}"}

    # 先 upload
    pdf_bytes = make_pdf_bytes()
    r = client.post("/api/upload-document",
                    data={"file": (io.BytesIO(pdf_bytes), "a.pdf")},
                    headers=headers,
                    content_type="multipart/form-data")
    doc_id = r.get_json()["id"]

    # 缺 method/key/secret/intended_for
    r2 = client.post(f"/api/create-watermark/{doc_id}",
                     json={}, headers=headers)
    assert r2.status_code == 400


def test_read_watermark_missing_key(app_client, monkeypatch):
    app, client = app_client
    from server.src import server as server_mod

    # 让 read_watermark 不依赖真实实现
    monkeypatch.setattr(server_mod.WMUtils, "read_watermark", lambda **k: "x")

    token = _login(app, client)
    headers = {"Authorization": f"Bearer {token}"}

    pdf_bytes = make_pdf_bytes()
    r = client.post("/api/upload-document",
                    data={"file": (io.BytesIO(pdf_bytes), "a.pdf")},
                    headers=headers,
                    content_type="multipart/form-data")
    doc_id = r.get_json()["id"]

    # 缺 key
    r2 = client.post(f"/api/read-watermark/{doc_id}",
                     json={"method": "trailer-hmac"}, headers=headers)
    assert r2.status_code == 400
