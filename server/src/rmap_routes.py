# server/src/rmap_routes.py
# -*- coding: utf-8 -*-
"""
RMAP endpoints:
  POST /api/rmap-initiate  -> {"payload": base64(pgp)} -> {"payload": base64(pgp)}
  POST /api/rmap-get-link  -> {"payload": base64(pgp)} -> {"result": "<32-hex>"}

Implements handshake using IdentityManager/RMAP.
Generates a watermarked PDF with the team's "best technique" (visible text + XMP + EOF trailer).
Saves to STORAGE_DIR/watermarks/<secret>.pdf and inserts a row in Versions.

Spec note: "watermarked with your best watermarking technique" (singular) — combining
methods into one robust technique is acceptable and documented in the report.
"""


from __future__ import annotations
# 标准库
import os 
from pathlib import Path
from typing import  Optional
# 三方库

from flask import Blueprint, request, jsonify, current_app
from sqlalchemy import create_engine, text
# 本地模块
from rmap.identity_manager import IdentityManager
from rmap.rmap import RMAP
from .visible_text import VisibleTextWatermark
from .metadata_watermark import MetadataWatermark

# ---------- helpers ----------
def _expand(p: Optional[str]) -> Optional[str]:
    if p is None:
        return None
    return os.path.expandvars(os.path.expanduser(p))


def _require_file(path: str, label: str) -> None:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"{label} not found at: {path}")



# ---------- env ----------
RMAP_KEYS_DIR    = _expand(os.getenv("RMAP_KEYS_DIR", "server/keys/clients"))
RMAP_SERVER_PRIV = _expand(os.getenv("RMAP_SERVER_PRIV", "server/keys/server_priv.asc"))
RMAP_SERVER_PUB  = _expand(os.getenv("RMAP_SERVER_PUB",  "server/keys/server_pub.asc"))
RMAP_INPUT_PDF   = _expand(os.getenv("RMAP_INPUT_PDF", "server/test.pdf"))
WATERMARK_HMAC_KEY = os.getenv("WATERMARK_HMAC_KEY", "dev-key-change-me")

if not (RMAP_KEYS_DIR and os.path.isdir(RMAP_KEYS_DIR)):
    raise RuntimeError(f"RMAP_KEYS_DIR not found or not a directory: {RMAP_KEYS_DIR}")
_require_file(RMAP_SERVER_PRIV, "RMAP_SERVER_PRIV")
_require_file(RMAP_SERVER_PUB,  "RMAP_SERVER_PUB")
# if not RMAP_INPUT_PDF:
#     raise RuntimeError("RMAP_INPUT_PDF is not set")


# ---------- RMAP wiring ----------
im = IdentityManager(
    RMAP_KEYS_DIR,
    RMAP_SERVER_PUB,
    RMAP_SERVER_PRIV,
)
rmap = RMAP(im)

bp = Blueprint("rmap", __name__)

# ---------- DB ----------
def _db_url_from_config() -> str:
    c = current_app.config
    return (
        f"mysql+pymysql://{c['DB_USER']}:{c['DB_PASSWORD']}"
        f"@{c['DB_HOST']}:{c['DB_PORT']}/{c['DB_NAME']}?charset=utf8mb4"
    )

def _get_engine():
    eng = current_app.config.get("_ENGINE")
    if eng is None:
        eng = create_engine(_db_url_from_config(), pool_pre_ping=True, future=True)
        current_app.config["_ENGINE"] = eng
    return eng


CLIENT_KEYS_DIR = Path(RMAP_KEYS_DIR)

def _guess_identity(incoming: dict) -> str:
    ident = (incoming.get("identity") or "").strip()
    if ident and (CLIENT_KEYS_DIR / f"{ident}.asc").exists():
        return ident
    group_files = list(CLIENT_KEYS_DIR.glob("Group_*.asc"))
    if len(group_files) == 1:
        return group_files[0].stem
    return "rmap"

# rmap-initiate

@bp.post("/rmap-initiate")
@bp.post("/api/rmap-initiate")
def rmap_initiate():
    try:
        incoming = request.get_json(force=True) or {}

        current_app.config["LAST_RMAP_IDENTITY"] = _guess_identity(incoming)

        result = rmap.handle_message1(incoming)
        if "error" in result:
            return jsonify(result), 400
        return jsonify(result), 200
    
    except Exception as e:
        current_app.logger.exception("rmap-initiate failed")
        return jsonify({"error": str(e)}), 400
    



# rmap-get-link

@bp.post("/rmap-get-link")
@bp.post("/api/rmap-get-link")
def rmap_get_link():
    try:

        #rmap 2.0
        incoming = request.get_json(force=True) or {}

        ident = _guess_identity(incoming) or current_app.config.get("LAST_RMAP_IDENTITY", "rmap")

        result = rmap.handle_message2(incoming)
        if "error" in result:
            return jsonify(result), 400

        #get secret
        secret = result["result"]

        # create PDF
        if not RMAP_INPUT_PDF:
            return jsonify({"error": "RMAP_INPUT_PDF not set"}), 500

        src_fp = Path(RMAP_INPUT_PDF).expanduser().resolve()
        if not src_fp.is_file():
            return jsonify({"error": f"input pdf not found: {src_fp}"}), 500
        pdf_bytes = src_fp.read_bytes()

        # --- 水印流水线：先可见文字，再叠加 XMP Metadata ---
        vt = VisibleTextWatermark()
        out_bytes = vt.add_watermark(pdf_bytes, secret, WATERMARK_HMAC_KEY)

        xmp = MetadataWatermark()
        out_bytes = xmp.add_watermark(out_bytes, secret, WATERMARK_HMAC_KEY)      

        out_dir = Path(current_app.config.get("STORAGE_DIR", "/app/storage")) / "watermarks"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_fp = out_dir / f"{secret}.pdf"
        out_fp.write_bytes(out_bytes)

        try:
            eng = _get_engine()
            with eng.begin()as conn:
                conn.execute(
                    text("""
                        INSERT INTO Versions (link, path, intended_for, method)
                        VALUES (:link, :path, :intended_for, :method)
                    """),
                    {
                        "link": secret,
                        "path": str(out_fp),
                        "intended_for": ident,
                        "method": "visible+metadata",
                    },
                )
        except Exception as db_e:
            current_app.logger.warning(f"Versions insert failed: {db_e}")

        return jsonify({"result": secret}), 200

    except Exception:
        current_app.logger.exception("rmap-get-link failed")
        return jsonify({"error": "rmap-get-link failed"}), 400
    

#download PDF
@bp.get("/get-version/<secret>")
def get_version(secret):
    from flask import send_file
    pdf_path = Path("/app/storage/watermarks") / f"{secret}.pdf"
    if not pdf_path.exists():
        return jsonify({"error": "document not found"}), 404
    return send_file(pdf_path, mimetype="application/pdf")