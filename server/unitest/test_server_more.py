import io
import pickle
import pytest
from pathlib import Path

from conftest import make_pdf_bytes
from server.src.watermarking_method import WatermarkingMethod


# ---- 顶层定义，可被 pickle ----
class DummyPlugin(WatermarkingMethod):
    name = "dummy"

    def add_watermark(self, pdf, secret, key, position=None):
        return b"%PDF-1.4\n%%EOF"

    def read_secret(self, pdf, key):
        return "x"

    def is_watermark_applicable(self, pdf, position=None):
        return True

    def get_usage(self):
        return "dummy"


def _login(app, client):
    client.post("/api/create-user",
                json={"login": "a", "email": "a@b.com", "password": "pw"})
    r = client.post("/api/login", json={"email": "a@b.com", "password": "pw"})
    return r.get_json()["token"]


def test_require_auth_missing_header(app_client):
    app, client = app_client
    r = client.get("/api/list-documents")
    assert r.status_code == 401


def test_require_auth_bad_token(app_client):
    app, client = app_client
    r = client.get("/api/list-documents", headers={"Authorization": "Bearer BAD"})
    assert r.status_code == 401


def test_safe_resolve_under_storage_escape(app_client):
    from server.src.server import _safe_resolve_under_storage
    root = Path("/tmp/root")
    with pytest.raises(RuntimeError):
        _safe_resolve_under_storage("../escape.pdf", root)


def test_load_plugin_malformed_file(app_client):
    """
    真实 API：POST JSON，server 从 STORAGE_DIR/files/plugins/<filename> 读文件并反序列化。
    """
    app, client = app_client
    token = _login(app, client)
    headers = {"Authorization": f"Bearer {token}"}

    storage_root = Path(app.config["STORAGE_DIR"])
    plugins_dir = storage_root / "files" / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)

    # 写一个坏的 pkl
    bad_path = plugins_dir / "bad.pkl"
    bad_path.write_bytes(b"not a pickle")

    r = client.post(
        "/api/load-plugin",
        json={"filename": "bad.pkl"},
        headers=headers
    )
    assert r.status_code == 400


def test_load_plugin_success_class(app_client):
    """
    成功路径：先把 DummyPlugin 的 pickle 写入 plugins 目录，再 POST JSON filename
    """
    app, client = app_client
    token = _login(app, client)
    headers = {"Authorization": f"Bearer {token}"}

    storage_root = Path(app.config["STORAGE_DIR"])
    plugins_dir = storage_root / "files" / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)

    good_path = plugins_dir / "good.pkl"
    good_path.write_bytes(pickle.dumps(DummyPlugin))

    r = client.post(
        "/api/load-plugin",
        json={"filename": "good.pkl"},
        headers=headers
    )

    # 真实实现成功返回 201
    assert r.status_code == 201
    body = r.get_json()
    assert body["loaded"] is True
    assert body["registered_as"] == "dummy"
