def test_create_watermark_document_not_found_returns_404(app_client, monkeypatch):
    app, client = app_client

    # token
    from server.src.server import _serializer
    token = _serializer(app).dumps({
        "uid": 1,
        "login": "testuser",
        "email": "test@example.com",
    })
    headers = {"Authorization": f"Bearer {token}"}

    # 用一个肯定不存在的 id（比如 9999）
    missing_doc_id = 9999

    resp = client.post(
        f"/api/create-watermark/{missing_doc_id}",
        headers=headers,
        json={
            "method": "dummy",
            "position": "bottom-right",
            "key": "k",
            "secret": "TOP_SECRET",
            "intended_for": "alice@example.com",
        },
    )

    assert resp.status_code == 404
