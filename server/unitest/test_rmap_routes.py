import sys, types, importlib
from pathlib import Path
import pytest
from conftest import make_pdf_bytes



def import_rmap_routes(tmp_path, monkeypatch):
    # 准备 env & key files，避免 import-time RuntimeError
    keys_dir = tmp_path / "clients"
    keys_dir.mkdir()
    (keys_dir / "Group_16.asc").write_text("pubkey")  # 只有一个 Group_*.asc
    server_priv = tmp_path / "server_priv.asc"; server_priv.write_text("priv")
    server_pub  = tmp_path / "server_pub.asc";  server_pub.write_text("pub")
    in_pdf = tmp_path / "in.pdf"; in_pdf.write_bytes(make_pdf_bytes())

    monkeypatch.setenv("RMAP_KEYS_DIR", str(keys_dir))
    monkeypatch.setenv("RMAP_SERVER_PRIV", str(server_priv))
    monkeypatch.setenv("RMAP_SERVER_PUB", str(server_pub))
    monkeypatch.setenv("RMAP_INPUT_PDF", str(in_pdf))
    monkeypatch.setenv("WATERMARK_HMAC_KEY", "k")

    # fake rmap library
    fake_im_cls = lambda *a, **k: object()

    class FakeRMAP:
        def __init__(self, im): pass
        def handle_message1(self, incoming):
            if incoming.get("bad"):
                return {"error": "bad"}
            return {"payload": "ok"}
        def handle_message2(self, incoming):
            if incoming.get("bad"):
                return {"error": "bad"}
            return {"result": "deadbeef"*4}

    mod_identity = types.ModuleType("rmap.identity_manager")
    mod_identity.IdentityManager = fake_im_cls
    mod_rmap = types.ModuleType("rmap.rmap")
    mod_rmap.RMAP = FakeRMAP

    sys.modules["rmap"] = types.ModuleType("rmap")
    sys.modules["rmap.identity_manager"] = mod_identity
    sys.modules["rmap.rmap"] = mod_rmap

    # ---- 关键：强制 reload，避免用到旧的 CLIENT_KEYS_DIR ----
    sys.modules.pop("server.src.rmap_routes", None)

    rr = importlib.import_module("server.src.rmap_routes")

    # ---- 关键：显式把 CLIENT_KEYS_DIR 指向临时 keys_dir ----
    rr.CLIENT_KEYS_DIR = keys_dir

    return rr


def test_guess_identity(tmp_path, monkeypatch):
    rr = import_rmap_routes(tmp_path, monkeypatch)

    # identity 有效且文件存在 -> 直接返回
    assert rr._guess_identity({"identity": "Group_16"}) == "Group_16"
    # identity 无效 -> 因为只有一个 Group_*.asc -> 返回 Group_16
    assert rr._guess_identity({"identity": "nope"}) == "Group_16"


def test_rmap_endpoints(tmp_path, monkeypatch):
    rr = import_rmap_routes(tmp_path, monkeypatch)

    class VT:
        def add_watermark(self, pdf_bytes, secret, key, position="page"):
            return pdf_bytes

    class XMP:
        def add_watermark(self, pdf_bytes, secret, key, position="metadata"):
            return pdf_bytes

    monkeypatch.setattr(rr, "VisibleTextWatermark", VT)
    monkeypatch.setattr(rr, "MetadataWatermark", XMP)

    from flask import Flask
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["STORAGE_DIR"] = tmp_path
    app.register_blueprint(rr.bp, url_prefix="/api")
    client = app.test_client()

    r1 = client.post("/api/rmap-initiate",
                     json={"identity": "Group_16", "payload": "x"})
    assert r1.status_code == 200

    r1b = client.post("/api/rmap-initiate", json={"bad": True})
    assert r1b.status_code == 400

    r2 = client.post("/api/rmap-get-link", json={"payload": "x"})
    assert r2.status_code == 200
    assert "result" in r2.get_json()



