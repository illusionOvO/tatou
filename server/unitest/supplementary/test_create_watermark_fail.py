from pathlib import Path
from sqlalchemy import text


def test_create_watermark_internal_error_returns_500(app_client, seed_basic_user_doc, monkeypatch):
    app, client = app_client
    doc_id = seed_basic_user_doc["document_id"]

    # --- 0) 修好 path + 创建 pdf（和成功测试一样）---
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

    # --- ① token ---
    from server.src.server import _serializer
    token = _serializer(app).dumps({
        "uid": 1,
        "login": "testuser",
        "email": "test@example.com",
    })
    headers = {"Authorization": f"Bearer {token}"}

    # --- ② 全 mock，但让 apply_watermark 抛异常 ---
    from server.src import watermarking_utils as WMUtils

    class DummyMethod:
        name = "dummy"
        description = "dummy test method"

    monkeypatch.setattr(WMUtils, "METHODS", {"dummy": DummyMethod()}, raising=False)
    monkeypatch.setattr(WMUtils, "is_watermarking_applicable", lambda **kwargs: True)

    def boom(**kwargs):
        raise RuntimeError("mock watermark failure")

    monkeypatch.setattr(WMUtils, "apply_watermark", boom)

    # --- ③ 调用 ---
    resp = client.post(
        f"/api/create-watermark/{doc_id}",
        headers=headers,
        json={
            "method": "dummy",
            "position": "bottom-right",
            "key": "k",
            "secret": "TOP_SECRET",
            "intended_for": "junchen@example.com",
        },
    )

    # --- ④ 断言 500 ---
    assert resp.status_code == 500
