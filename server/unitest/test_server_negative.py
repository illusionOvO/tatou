import io
import pytest
from pathlib import Path
from conftest import make_pdf_bytes


# -----------------------
# Helpers (robust)
# -----------------------

def _create_user(client, login="u1", email="u1@e.com", password="pw"):
    return client.post(
        "/api/create-user",
        json={"login": login, "email": email, "password": password},
    )

def _login(client, email="u1@e.com", password="pw"):
    return client.post("/api/login", json={"email": email, "password": password})

def _extract_token(resp):
    """
    兼容不同 token 命名：
    - {"token": ...}
    - {"access_token": ...}
    - {"data": {"token": ...}}
    - 或者返回 {"token_type":"bearer","token":...}
    """
    js = resp.get_json(silent=True) or {}
    if "token" in js:
        return js["token"]
    if "access_token" in js:
        return js["access_token"]
    if "data" in js and isinstance(js["data"], dict):
        if "token" in js["data"]:
            return js["data"]["token"]
        if "access_token" in js["data"]:
            return js["data"]["access_token"]
    return None

def _get_token(client, email="u1@e.com", password="pw"):
    r = _login(client, email=email, password=password)
    assert r.status_code == 200, f"login failed: {r.status_code}, {r.get_json(silent=True)}"
    token = _extract_token(r)
    assert token, f"no token field in login response: {r.get_json(silent=True)}"
    return token

def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}

def _upload_pdf(client, headers, pdf_bytes=None, filename="a.pdf"):
    if pdf_bytes is None:
        pdf_bytes = make_pdf_bytes()
    return client.post(
        "/api/upload-document",
        data={"file": (io.BytesIO(pdf_bytes), filename)},
        headers=headers,
        content_type="multipart/form-data",
    )


# -----------------------
# Negative tests
# -----------------------

def test_create_user_missing_fields(app_client):
    app, client = app_client

    r = client.post("/api/create-user", json={})
    assert r.status_code == 400

    r = client.post("/api/create-user", json={"login": "a"})
    assert r.status_code == 400

    r = client.post("/api/create-user", json={"email": "a@b.com"})
    assert r.status_code == 400


def test_create_user_duplicate_conflict(app_client):
    app, client = app_client

    r1 = _create_user(client, login="dup", email="dup@e.com", password="pw")
    assert r1.status_code in (200, 201)

    r2 = _create_user(client, login="dup", email="dup@e.com", password="pw")
    assert r2.status_code in (409, 400)


def test_login_missing_or_bad_type(app_client):
    app, client = app_client

    r = client.post("/api/login", json={})
    assert r.status_code == 400

    r = client.post("/api/login", json={"email": "a@b.com"})
    assert r.status_code == 400

    r = client.post("/api/login", json={"email": "a@b.com", "password": 123})
    assert r.status_code == 400


def test_login_invalid_credentials(app_client):
    app, client = app_client

    _create_user(client, login="a", email="a@b.com", password="pw")

    r = _login(client, email="a@b.com", password="wrong")
    assert r.status_code == 401


def test_login_database_error_returns_503(app_client, monkeypatch):
    app, client = app_client
    from server.src import server as server_mod

    class BadEngine:
        def connect(self):
            raise RuntimeError("db down")

    monkeypatch.setattr(server_mod, "get_engine", lambda app: BadEngine())

    r = _login(client, email="x@y.com", password="pw")
    assert r.status_code == 503


def test_require_auth_missing_token(app_client):
    app, client = app_client
    r = client.get("/api/list-documents")
    assert r.status_code == 401


def test_require_auth_bad_token(app_client):
    app, client = app_client
    r = client.get("/api/list-documents", headers={"Authorization": "Bearer BAD"})
    assert r.status_code == 401


def test_upload_document_missing_file_or_empty_name(app_client):
    app, client = app_client

    _create_user(client, login="a", email="a@b.com", password="pw")
    token = _get_token(client, email="a@b.com", password="pw")
    headers = _auth_header(token)

    r = client.post(
        "/api/upload-document",
        data={},
        headers=headers,
        content_type="multipart/form-data",
    )
    assert r.status_code == 400

    r = client.post(
        "/api/upload-document",
        data={"file": (io.BytesIO(make_pdf_bytes()), "")},
        headers=headers,
        content_type="multipart/form-data",
    )
    assert r.status_code == 400


def test_upload_document_reject_non_pdf(app_client):
    app, client = app_client

    _create_user(client, login="a", email="a@b.com", password="pw")
    token = _get_token(client, email="a@b.com", password="pw")
    headers = _auth_header(token)

    r = _upload_pdf(client, headers, pdf_bytes=b"NOTPDF", filename="x.pdf")
    assert r.status_code == 400


def test_get_document_not_found(app_client):
    app, client = app_client

    _create_user(client, login="a", email="a@b.com", password="pw")
    token = _get_token(client, email="a@b.com", password="pw")
    headers = _auth_header(token)

    r = client.get("/api/get-document/9999", headers=headers)
    assert r.status_code in (404, 403)


def test_delete_document_not_found(app_client):
    app, client = app_client

    _create_user(client, login="a", email="a@b.com", password="pw")
    token = _get_token(client, email="a@b.com", password="pw")
    headers = _auth_header(token)

    r = client.delete("/api/delete-document/9999", headers=headers)
    assert r.status_code in (404, 403)


def test_create_watermark_missing_fields(app_client):
    app, client = app_client

    _create_user(client, login="a", email="a@b.com", password="pw")
    token = _get_token(client, email="a@b.com", password="pw")
    headers = _auth_header(token)

    up = _upload_pdf(client, headers)
    assert up.status_code in (200, 201)
    doc_id = up.get_json()["id"]

    r = client.post(f"/api/create-watermark/{doc_id}", json={}, headers=headers)
    assert r.status_code == 400

    r = client.post(
        f"/api/create-watermark/{doc_id}",
        json={"method": "trailer-hmac"},
        headers=headers,
    )
    assert r.status_code == 400


def test_create_watermark_invalid_method_or_position(app_client):
    app, client = app_client

    _create_user(client, login="a", email="a@b.com", password="pw")
    token = _get_token(client, email="a@b.com", password="pw")
    headers = _auth_header(token)

    up = _upload_pdf(client, headers)
    doc_id = up.get_json()["id"]

    r = client.post(
        f"/api/create-watermark/{doc_id}",
        json={
            "method": "nope",
            "key": "k",
            "secret": "s",
            "intended_for": "bob",
            "position": "eof",
        },
        headers=headers,
    )
    assert r.status_code in (400, 404)

    r = client.post(
        f"/api/create-watermark/{doc_id}",
        json={
            "method": "trailer-hmac",
            "key": "k",
            "secret": "s",
            "intended_for": "bob",
            "position": "weird",
        },
        headers=headers,
    )
    assert r.status_code == 400


def test_read_watermark_missing_fields(app_client, monkeypatch):
    app, client = app_client
    from server.src import server as server_mod

    monkeypatch.setattr(server_mod.WMUtils, "read_watermark", lambda **k: "x")

    _create_user(client, login="a", email="a@b.com", password="pw")
    token = _get_token(client, email="a@b.com", password="pw")
    headers = _auth_header(token)

    up = _upload_pdf(client, headers)
    doc_id = up.get_json()["id"]

    r = client.post(
        f"/api/read-watermark/{doc_id}",
        json={"key": "k"},
        headers=headers,
    )
    assert r.status_code == 400

    r = client.post(
        f"/api/read-watermark/{doc_id}",
        json={"method": "trailer-hmac"},
        headers=headers,
    )
    assert r.status_code == 400


def test_get_version_not_found(app_client):
    app, client = app_client
    r = client.get("/api/get-version/not-exist-link")
    assert r.status_code in (404, 400)


def test_load_plugin_file_missing(app_client):
    app, client = app_client

    _create_user(client, login="a", email="a@b.com", password="pw")
    token = _get_token(client, email="a@b.com", password="pw")
    headers = _auth_header(token)

    r = client.post("/api/load-plugin", json={"filename": "no.pkl"}, headers=headers)
    assert r.status_code in (400, 404)
