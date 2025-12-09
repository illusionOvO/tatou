from pathlib import Path
from sqlalchemy import text


def _auth_headers(app):
    from server.src.server import _serializer
    token = _serializer(app).dumps({
        "uid": 1, "login": "testuser", "email": "test@example.com",
    })
    return {"Authorization": f"Bearer {token}"}


def _ensure_doc_in_storage(app, doc_id, filename="test.pdf"):
    storage_root = Path(app.config["STORAGE_DIR"]).resolve()
    rel_path = filename
    abs_path = storage_root / rel_path
    abs_path.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n")

    engine = app.config["_ENGINE"]
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE Documents SET path=:p WHERE id=:id"),
            {"p": rel_path, "id": doc_id},
        )
    return rel_path


def test_create_watermark_not_applicable_returns_400(app_client, seed_basic_user_doc, monkeypatch):
    app, client = app_client
    doc_id = seed_basic_user_doc["document_id"]
    _ensure_doc_in_storage(app, doc_id)
    headers = _auth_headers(app)

    from server.src import watermarking_utils as WMUtils

    class DummyMethod:
        name = "dummy"
        description = "dummy"

    monkeypatch.setattr(WMUtils, "METHODS", {"dummy": DummyMethod()}, raising=False)
    monkeypatch.setattr(WMUtils, "is_watermarking_applicable", lambda **kwargs: False)

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
    assert resp.status_code == 400


def test_create_watermark_applicability_check_raises_returns_400(app_client, seed_basic_user_doc, monkeypatch):
    app, client = app_client
    doc_id = seed_basic_user_doc["document_id"]
    _ensure_doc_in_storage(app, doc_id, filename="appr.pdf")
    headers = _auth_headers(app)

    from server.src import watermarking_utils as WMUtils

    class DummyMethod:
        name = "dummy"
        description = "dummy"

    monkeypatch.setattr(WMUtils, "METHODS", {"dummy": DummyMethod()}, raising=False)

    def boom(**kwargs):
        raise RuntimeError("mock applicability crash")

    monkeypatch.setattr(WMUtils, "is_watermarking_applicable", boom)

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
    assert resp.status_code == 400


def test_create_watermark_empty_output_returns_500(app_client, seed_basic_user_doc, monkeypatch):
    app, client = app_client
    doc_id = seed_basic_user_doc["document_id"]
    _ensure_doc_in_storage(app, doc_id, filename="empty.pdf")
    headers = _auth_headers(app)

    from server.src import watermarking_utils as WMUtils

    class DummyMethod:
        name = "dummy"
        description = "dummy"

    monkeypatch.setattr(WMUtils, "METHODS", {"dummy": DummyMethod()}, raising=False)
    monkeypatch.setattr(WMUtils, "is_watermarking_applicable", lambda **kwargs: True)

    # Return empty bytes to hit "produced no output"
    monkeypatch.setattr(WMUtils, "apply_watermark", lambda **kwargs: b"")

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
    assert resp.status_code == 500


def test_create_watermark_apply_raises_returns_500(app_client, seed_basic_user_doc, monkeypatch):
    app, client = app_client
    doc_id = seed_basic_user_doc["document_id"]
    _ensure_doc_in_storage(app, doc_id, filename="boom.pdf")
    headers = _auth_headers(app)

    from server.src import watermarking_utils as WMUtils

    class DummyMethod:
        name = "dummy"
        description = "dummy"

    monkeypatch.setattr(WMUtils, "METHODS", {"dummy": DummyMethod()}, raising=False)
    monkeypatch.setattr(WMUtils, "is_watermarking_applicable", lambda **kwargs: True)

    def boom(**kwargs):
        raise RuntimeError("mock apply crash")

    monkeypatch.setattr(WMUtils, "apply_watermark", boom)

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
    assert resp.status_code == 500


def test_create_watermark_write_file_raises_returns_500(app_client, seed_basic_user_doc, monkeypatch):
    app, client = app_client
    doc_id = seed_basic_user_doc["document_id"]
    _ensure_doc_in_storage(app, doc_id, filename="writefail.pdf")
    headers = _auth_headers(app)

    from server.src import watermarking_utils as WMUtils

    class DummyMethod:
        name = "dummy"
        description = "dummy"

    monkeypatch.setattr(WMUtils, "METHODS", {"dummy": DummyMethod()}, raising=False)
    monkeypatch.setattr(WMUtils, "is_watermarking_applicable", lambda **kwargs: True)
    monkeypatch.setattr(WMUtils, "apply_watermark", lambda **kwargs: b"DUMMY_BYTES")

    # Force any Path.open("wb") to fail inside create_watermark
    from pathlib import Path as PathCls
    real_open = PathCls.open

    def boom_open(self, *args, **kwargs):
        if args and "b" in args[0]:
            raise OSError("mock disk write failure")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(PathCls, "open", boom_open, raising=True)

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
    assert resp.status_code == 500


# 400 case: document_id missing or not convertible to int
def test_create_watermark_bad_document_id_returns_400(app_client):
    app, client = app_client
    headers = _auth_headers(app)

    # Call the route WITHOUT <int:id> so server reads id from JSON,
    # then pass a non-numeric id to trigger int(...) ValueError branch.
    resp = client.post(
        "/api/create-watermark",
        headers=headers,
        json={
            "id": "not-a-number",
            "method": "dummy",
            "position": "bottom-right",
            "key": "k",
            "secret": "TOP_SECRET",
            "intended_for": "alice@example.com",
        },
    )

    assert resp.status_code == 400


# Cover the "document_id is taken from args" path (not from URL)
def test_create_watermark_document_id_from_query_args_success(app_client, seed_basic_user_doc, monkeypatch):
    app, client = app_client
    doc_id = seed_basic_user_doc["document_id"]

    _ensure_doc_in_storage(app, doc_id, filename="args.pdf")
    headers = _auth_headers(app)

    from server.src import watermarking_utils as WMUtils
    class DummyMethod:
        name = "dummy"
        description = "dummy"
    monkeypatch.setattr(WMUtils, "METHODS", {"dummy": DummyMethod()}, raising=False)
    monkeypatch.setattr(WMUtils, "is_watermarking_applicable", lambda **kwargs: True)
    monkeypatch.setattr(WMUtils, "apply_watermark", lambda **kwargs: b"DUMMY_BYTES")

    # Provide document id via query string so the "if not document_id:" block runs
    resp = client.post(
        f"/api/create-watermark?id={doc_id}",
        headers=headers,
        json={
            "method": "dummy",
            "position": "bottom-right",
            "key": "k",
            "secret": "TOP_SECRET",
            "intended_for": "alice@example.com",
        },
    )

    assert resp.status_code in (200, 201)


# Cover absolute-path branch: file_path.is_absolute() == True
def test_create_watermark_with_absolute_path_success(app_client, seed_basic_user_doc, monkeypatch):
    app, client = app_client
    doc_id = seed_basic_user_doc["document_id"]
    headers = _auth_headers(app)

    # Create a PDF under STORAGE_DIR but store ABSOLUTE path in DB
    storage_root = Path(app.config["STORAGE_DIR"]).resolve()
    abs_pdf_path = (storage_root / "abs_create.pdf").resolve()
    abs_pdf_path.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n")

    engine = app.config["_ENGINE"]
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE Documents SET path=:p WHERE id=:id"),
            {"p": str(abs_pdf_path), "id": doc_id},
        )

    from server.src import watermarking_utils as WMUtils
    class DummyMethod:
        name = "dummy"
        description = "dummy"
    monkeypatch.setattr(WMUtils, "METHODS", {"dummy": DummyMethod()}, raising=False)
    monkeypatch.setattr(WMUtils, "is_watermarking_applicable", lambda **kwargs: True)
    monkeypatch.setattr(WMUtils, "apply_watermark", lambda **kwargs: b"DUMMY_BYTES")

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

    assert resp.status_code in (200, 201)


# 500 case: document path is outside STORAGE_DIR -> relative_to() raises ValueError
def test_create_watermark_invalid_storage_path_returns_500(app_client, seed_basic_user_doc, monkeypatch):
    app, client = app_client
    doc_id = seed_basic_user_doc["document_id"]
    headers = _auth_headers(app)

    # Set an absolute path OUTSIDE STORAGE_DIR to trigger ValueError at relative_to()
    outside_abs_path = Path("/tmp/outside_create.pdf").resolve()

    engine = app.config["_ENGINE"]
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE Documents SET path=:p WHERE id=:id"),
            {"p": str(outside_abs_path), "id": doc_id},
        )

    # Mock watermarking to avoid real work (should not be reached anyway)
    from server.src import watermarking_utils as WMUtils
    class DummyMethod:
        name = "dummy"
        description = "dummy"
    monkeypatch.setattr(WMUtils, "METHODS", {"dummy": DummyMethod()}, raising=False)

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

    assert resp.status_code == 500
