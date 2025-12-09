from pathlib import Path
from sqlalchemy import text


def _auth_headers(app):
    """
    Build Authorization header using server-side serializer,
    so we don't need to call /api/login in unit tests.
    """
    from server.src.server import _serializer
    token = _serializer(app).dumps({
        "uid": 1,
        "login": "testuser",
        "email": "test@example.com",
    })
    return {"Authorization": f"Bearer {token}"}


def _ensure_doc_in_storage(app, doc_id):
    """
    Ensure Documents.path points to an existing PDF inside STORAGE_DIR.
    Many read/create routes validate that the file is under STORAGE_DIR.
    """
    storage_root = Path(app.config["STORAGE_DIR"]).resolve()
    pdf_rel_path = "test.pdf"
    pdf_abs_path = storage_root / pdf_rel_path

    # Create a minimal valid PDF file
    pdf_abs_path.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n")

    # Update DB path to a relative path inside STORAGE_DIR
    engine = app.config["_ENGINE"]
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE Documents SET path=:p WHERE id=:id"),
            {"p": pdf_rel_path, "id": doc_id},
        )


# 400 case #1: document id exists but is not an integer
def test_read_watermark_bad_document_id_returns_400(app_client):
    app, client = app_client
    headers = _auth_headers(app)

    # Use /api/read-watermark without <int:id> so we enter the function,
    # then pass a non-numeric id to trigger int(...) ValueError branch.
    resp = client.post(
        "/api/read-watermark",
        headers=headers,
        json={
            "id": "not-a-number",
            "method": "dummy",
            "key": "k",
        },
    )

    assert resp.status_code == 400


# 400 case #2: missing method or invalid key type
def test_read_watermark_missing_method_or_key_returns_400(app_client, seed_basic_user_doc):
    app, client = app_client
    headers = _auth_headers(app)
    doc_id = seed_basic_user_doc["document_id"]

    _ensure_doc_in_storage(app, doc_id)

    # Deliberately omit "method" to hit:
    # if not method or not isinstance(key, str): return 400
    resp = client.post(
        f"/api/read-watermark/{doc_id}",
        headers=headers,
        json={
            "key": "k",
        },
    )

    assert resp.status_code == 400


# 400 case #3: watermarking backend throws exception
def test_read_watermark_internal_error_returns_400(app_client, seed_basic_user_doc, monkeypatch):
    app, client = app_client
    headers = _auth_headers(app)
    doc_id = seed_basic_user_doc["document_id"]

    _ensure_doc_in_storage(app, doc_id)

    from server.src import watermarking_utils as WMUtils

    def boom(**kwargs):
        raise RuntimeError("mock read failure")

    # Force watermark reading to crash, matching the internal 400 branch
    monkeypatch.setattr(WMUtils, "read_watermark", boom)

    resp = client.post(
        f"/api/read-watermark/{doc_id}",
        headers=headers,
        json={
            "method": "dummy",
            "key": "k",
        },
    )

    assert resp.status_code == 400
