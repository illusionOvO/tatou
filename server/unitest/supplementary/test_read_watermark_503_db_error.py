def test_read_watermark_database_error_returns_503(app_client, monkeypatch):
    app, client = app_client

    # Auth headers
    from server.src.server import _serializer
    token = _serializer(app).dumps({
        "uid": 1,
        "login": "testuser",
        "email": "test@example.com",
    })
    headers = {"Authorization": f"Bearer {token}"}

    # Force get_engine(app).connect() to raise -> hit 503 branch
    import server.src.server as server_mod

    class BoomEngine:
        def connect(self):
            raise RuntimeError("mock db down")

    monkeypatch.setattr(server_mod, "get_engine", lambda app: BoomEngine())

    resp = client.post(
        "/api/read-watermark/1",
        headers=headers,
        json={"method": "dummy", "key": "k"},
    )

    assert resp.status_code == 503
