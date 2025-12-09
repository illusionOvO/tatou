def test_read_watermark_document_not_found_returns_404(app_client):
    app, client = app_client

    # token
    from server.src.server import _serializer
    token = _serializer(app).dumps({
        "uid": 1,
        "login": "testuser",
        "email": "test@example.com",
    })
    headers = {"Authorization": f"Bearer {token}"}

    missing_doc_id = 9999

    resp = client.post(
        f"/api/read-watermark/{missing_doc_id}",
        headers=headers,
        json={
            "method": "dummy",
            "key": "k",
        },
    )

    assert resp.status_code == 404
