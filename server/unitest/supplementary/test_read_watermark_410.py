from pathlib import Path
from sqlalchemy import text


def test_read_watermark_file_missing_returns_410(app_client, seed_basic_user_doc):
    app, client = app_client
    doc_id = seed_basic_user_doc["document_id"]

    # token
    from server.src.server import _serializer
    token = _serializer(app).dumps({
        "uid": 1,
        "login": "testuser",
        "email": "test@example.com",
    })
    headers = {"Authorization": f"Bearer {token}"}

    # --- 关键：把 Documents.path 设成“位于 STORAGE_DIR 内但不存在”的文件 ---
    storage_root = Path(app.config["STORAGE_DIR"]).resolve()
    missing_rel_path = "missing.pdf"   # 我们不创建它
    missing_abs_path = storage_root / missing_rel_path
    if missing_abs_path.exists():
        missing_abs_path.unlink()     # 万一之前残留，确保不存在

    engine = app.config["_ENGINE"]
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE Documents SET path=:p WHERE id=:id"),
            {"p": missing_rel_path, "id": doc_id},
        )

    # 调用 read-watermark（会在 file_path.exists() 处返回 410）
    resp = client.post(
        f"/api/read-watermark/{doc_id}",
        headers=headers,
        json={
            "method": "dummy",
            "key": "k",
        },
    )

    assert resp.status_code == 410
