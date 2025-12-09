import io
from conftest import make_pdf_bytes
from server.src import server as server_mod


def _create_user_and_login(app, client, login="u1",
                           email="u1@example.com", password="pw"):
    r = client.post("/api/create-user",
                    json={"login": login, "email": email, "password": password})
    assert r.status_code == 201
    r2 = client.post("/api/login", json={"email": email, "password": password})
    assert r2.status_code == 200
    return r2.get_json()["token"]


def test_healthz_no_auth(app_client):
    app, client = app_client
    r = client.get("/healthz")
    assert r.status_code == 200
    assert "message" in r.get_json()


def test_create_user_validation_and_duplicate(app_client):
    app, client = app_client
    assert client.post("/api/create-user", json={}).status_code == 400

    ok = client.post("/api/create-user",
                     json={"login": "a", "email": "a@b.com", "password": "pw"})
    assert ok.status_code == 201

    dup = client.post("/api/create-user",
                      json={"login": "a2", "email": "a@b.com", "password": "pw"})
    assert dup.status_code == 409


def test_login_validation_and_invalid_credentials(app_client):
    app, client = app_client
    client.post("/api/create-user",
                json={"login": "a", "email": "a@b.com", "password": "pw"})
    assert client.post("/api/login", json={}).status_code == 400
    assert client.post("/api/login",
                       json={"email": "a@b.com", "password": "wrong"}).status_code == 401


def test_upload_list_get_delete_document_flow(app_client):
    app, client = app_client
    token = _create_user_and_login(app, client)
    headers = {"Authorization": f"Bearer {token}"}

    pdf_bytes = make_pdf_bytes()
    data = {"file": (io.BytesIO(pdf_bytes), "test.pdf"), "name": "mydoc.pdf"}
    r = client.post("/api/upload-document", data=data, headers=headers,
                    content_type="multipart/form-data")
    assert r.status_code == 201
    doc_id = r.get_json()["id"]

    rlist = client.get("/api/list-documents", headers=headers)
    assert rlist.status_code == 200
    assert len(rlist.get_json()["documents"]) == 1

    rget = client.get(f"/api/get-document/{doc_id}", headers=headers)
    assert rget.status_code == 200
    assert rget.data.startswith(b"%PDF-")

    rdel = client.delete(f"/api/delete-document/{doc_id}", headers=headers)
    assert rdel.status_code == 200
    assert rdel.get_json()["deleted"] is True


def test_create_and_read_watermark(app_client, monkeypatch):
    app, client = app_client
    from server.src import server as server_mod
    from pathlib import Path

    # 1) applicability 永远 True
    monkeypatch.setattr(
        server_mod.WMUtils,
        "is_watermarking_applicable",
        lambda **k: True
    )

    # 2) apply_watermark：pdf 可能是路径(str)也可能是 bytes
    def fake_apply_watermark(**k):
        pdf = k["pdf"]
        if isinstance(pdf, (bytes, bytearray)):
            pdf_bytes = bytes(pdf)
        else:
            # 真实 server 传的是路径字符串
            pdf_bytes = Path(pdf).read_bytes()
        return pdf_bytes + b"\n%%FAKE-WM\n"

    monkeypatch.setattr(server_mod.WMUtils, "apply_watermark", fake_apply_watermark)

    # 3) read_watermark：同样可能是路径 or bytes，这里直接返回固定 secret
    monkeypatch.setattr(
        server_mod.WMUtils,
        "read_watermark",
        lambda **k: "s3"
    )

    # login
    token = _create_user_and_login(app, client)
    headers = {"Authorization": f"Bearer {token}"}

    # upload
    pdf_bytes = make_pdf_bytes()
    r = client.post(
        "/api/upload-document",
        data={"file": (io.BytesIO(pdf_bytes), "a.pdf")},
        headers=headers,
        content_type="multipart/form-data",
    )
    assert r.status_code == 201
    doc_id = r.get_json()["id"]

    # create watermark
    payload = {
        "method": "trailer-hmac",
        "position": "eof",
        "key": "k",
        "secret": "s3",
        "intended_for": "bob",
    }
    rwm = client.post(f"/api/create-watermark/{doc_id}",
                      json=payload, headers=headers)
    assert rwm.status_code == 201
    link = rwm.get_json()["link"]

    # list versions
    rv = client.get(f"/api/list-versions/{doc_id}", headers=headers)
    assert rv.status_code == 200
    assert len(rv.get_json()["versions"]) == 1

    # read watermark
    rread = client.post(
        f"/api/read-watermark/{doc_id}",
        json={"method": "trailer-hmac", "key": "k"},
        headers=headers,
    )
    assert rread.status_code == 200
    assert rread.get_json()["secret"] == "s3"

    # get-version (public)
    rver = client.get(f"/api/get-version/{link}")
    assert rver.status_code == 200
    assert rver.data.startswith(b"%PDF-")
