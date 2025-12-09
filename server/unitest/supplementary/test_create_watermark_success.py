from pathlib import Path
from sqlalchemy import text


def test_create_watermark_success(app_client, seed_basic_user_doc, monkeypatch):
    app, client = app_client
    doc_id = seed_basic_user_doc["document_id"]

    # --- 0) 让 document.path 指向 STORAGE_DIR 里的真实文件 ---
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

    # --- ① 生成合法 token ---
    from server.src.server import _serializer
    token = _serializer(app).dumps({
        "uid": 1,
        "login": "testuser",
        "email": "test@example.com",
    })
    headers = {"Authorization": f"Bearer {token}"}

    # --- ② 全 mock watermarking：METHODS + 关键函数 ---
    from server.src import watermarking_utils as WMUtils

    class DummyMethod:
        name = "dummy"
        description = "dummy test method"

        def create(self, document, position, key, secret):
            return b"DUMMY_BYTES"

        def read(self, document, position, key):
            return "DUMMY_SECRET"

    # 关键：替换 METHODS，使 method 校验通过且不使用真实算法
    monkeypatch.setattr(
        WMUtils,
        "METHODS",
        {"dummy": DummyMethod()},
        raising=False,
    )

    # 再把执行入口也 mock 成可控分支
    monkeypatch.setattr(WMUtils, "is_watermarking_applicable",
                        lambda **kwargs: True)
    monkeypatch.setattr(WMUtils, "apply_watermark",
                        lambda **kwargs: b"DUMMY_BYTES")

    # --- ③ 调用 create-watermark API ---
    resp = client.post(
        f"/api/create-watermark/{doc_id}",
        headers=headers,
        json={
            "method": "dummy",   # 现在 dummy 是我们 mock 的 METHODS 里的合法方法
            "position": "bottom-right",
            "key": "k",
            "secret": "TOP_SECRET",
            "intended_for": "alice@example.com",
        },
    )

    # --- ④ 断言成功 ---
    assert resp.status_code in (200, 201)
    data = resp.get_json()
    assert data["documentid"] == doc_id
    assert data["method"] == "dummy"
    assert data["position"] == "bottom-right"
