from pathlib import Path
from sqlalchemy import text


def test_read_watermark_success(app_client, seed_basic_user_doc, monkeypatch):
    app, client = app_client
    doc_id = seed_basic_user_doc["document_id"]

    storage_root = Path(app.config["STORAGE_DIR"]).resolve()
    pdf_rel_path = "test.pdf"
    pdf_abs_path = storage_root / pdf_rel_path
    pdf_abs_path.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n")

    engine = app.config["_ENGINE"]
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE Documents SET path=:p WHERE id=:id"),
            {"p": pdf_rel_path, "id": doc_id},
        )

    from server.src.server import _serializer
    token = _serializer(app).dumps({
        "uid": 1,
        "login": "testuser",
        "email": "test@example.com",
    })
    headers = {"Authorization": f"Bearer {token}"}

    from server.src import watermarking_utils as WMUtils
    monkeypatch.setattr(WMUtils, "read_watermark", lambda **kwargs: "DUMMY_SECRET")

    resp = client.post(
        f"/api/read-watermark/{doc_id}",
        headers=headers,
        json={"method": "dummy", "key": "k"},
    )

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["documentid"] == doc_id
    assert data["secret"] == "DUMMY_SECRET"
    assert data["method"] == "dummy"
