def test_create_watermark_missing_field_returns_400(app_client, seed_basic_user_doc):
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

    # 故意缺 secret
    resp = client.post(
        f"/api/create-watermark/{doc_id}",
        headers=headers,
        json={
            "method": "dummy",
            "position": "bottom-right",
            "key": "k",
            # "secret" 缺失
            "intended_for": "alice@example.com",
        },
    )

    assert resp.status_code == 400

