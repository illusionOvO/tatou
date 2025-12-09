def test_create_watermark_database_error_returns_503(app_client, seed_basic_user_doc, monkeypatch):
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

    # 关键：让 get_engine(app) 在 connect 时抛异常 → 触发 503 分支
    import server.src.server as server_mod

    class BoomEngine:
        def connect(self):
            raise RuntimeError("mock db down")

    monkeypatch.setattr(server_mod, "get_engine", lambda app: BoomEngine())

    # 调用（payload 给齐，让它走到 DB 查询那一步）
    resp = client.post(
        f"/api/create-watermark/{doc_id}",
        headers=headers,
        json={
            "method": "dummy",
            "position": "bottom-right",
            "key": "k",
            "secret": "TOP_SECRET",
            "intended_for": "alice@example.com",
        },
    )

    assert resp.status_code == 503
