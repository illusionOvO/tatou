from pathlib import Path
from sqlalchemy import text


def test_read_watermark_invalid_storage_path_returns_500(app_client, seed_basic_user_doc):
    app, client = app_client
    doc_id = seed_basic_user_doc["document_id"]

    # Auth headers
    from server.src.server import _serializer
    token = _serializer(app).dumps({
        "uid": 1,
        "login": "testuser",
        "email": "test@example.com",
    })
    headers = {"Authorization": f"Bearer {token}"}

    # Set an absolute path OUTSIDE STORAGE_DIR to trigger relative_to(ValueError)
    outside_abs_path = Path("/tmp/outside.pdf").resolve()

    engine = app.config["_ENGINE"]
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE Documents SET path=:p WHERE id=:id"),
            {"p": str(outside_abs_path), "id": doc_id},
        )

    resp = client.post(
        f"/api/read-watermark/{doc_id}",
        headers=headers,
        json={"method": "dummy", "key": "k"},
    )

    assert resp.status_code == 500
