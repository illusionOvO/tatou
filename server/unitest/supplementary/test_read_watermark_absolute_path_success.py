from pathlib import Path
from sqlalchemy import text


def test_read_watermark_with_absolute_path_success(app_client, seed_basic_user_doc, monkeypatch):
    app, client = app_client
    doc_id = seed_basic_user_doc["document_id"]

    # --- Auth headers ---
    from server.src.server import _serializer
    token = _serializer(app).dumps({
        "uid": 1,
        "login": "testuser",
        "email": "test@example.com",
    })
    headers = {"Authorization": f"Bearer {token}"}

    # --- Create a real PDF under STORAGE_DIR ---
    storage_root = Path(app.config["STORAGE_DIR"]).resolve()
    abs_pdf_path = (storage_root / "abs.pdf").resolve()
    abs_pdf_path.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n")

    # --- Update Documents.path to an ABSOLUTE path ---
    engine = app.config["_ENGINE"]
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE Documents SET path=:p WHERE id=:id"),
            {"p": str(abs_pdf_path), "id": doc_id},
        )

    # --- Mock watermark reading to avoid real algorithms ---
    from server.src import watermarking_utils as WMUtils
    monkeypatch.setattr(WMUtils, "read_watermark", lambda **kwargs: "DUMMY_SECRET")

    # --- Call API ---
    resp = client.post(
        f"/api/read-watermark/{doc_id}",
        headers=headers,
        json={
            "method": "dummy",
            "key": "k",
        },
    )

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["documentid"] == doc_id
    assert data["secret"] == "DUMMY_SECRET"
