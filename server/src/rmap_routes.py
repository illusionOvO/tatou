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
import os, time, base64, hashlib
from pathlib import Path
from typing import Dict, Tuple, Optional
# 三方库
import json
from pgpy import PGPKey, PGPMessage
from flask import Blueprint, request, jsonify, current_app
from sqlalchemy import create_engine, text
# 本地模块
from rmap.identity_manager import IdentityManager
from rmap.rmap import RMAP
from .visible_text import VisibleTextWatermark



# Our composite "best" watermark (visible text + metadata + EOF trailer)
from .visible_text import VisibleTextWatermark

# ---------- helpers ----------
def _expand(p: Optional[str]) -> Optional[str]:
    if p is None:
        return None
    return os.path.expandvars(os.path.expanduser(p))

def _require_file(path: str, label: str) -> None:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"{label} not found at: {path}")

def _cfg(key: str, default=None):
    return (current_app.config.get(key) or os.getenv(key) or default)

# ---------- env ----------
RMAP_KEYS_DIR    = _expand(os.getenv("RMAP_KEYS_DIR", "/app/server/keys/clients"))
RMAP_SERVER_PRIV = _expand(os.getenv("RMAP_SERVER_PRIV", "/app/server/keys/server_priv.asc"))
RMAP_SERVER_PUB  = _expand(os.getenv("RMAP_SERVER_PUB",  "/app/server/keys/server_pub.asc"))
RMAP_INPUT_PDF   = _expand(os.getenv("RMAP_INPUT_PDF"))
WATERMARK_HMAC_KEY = os.getenv("WATERMARK_HMAC_KEY", "dev-key-change-me")

if not (RMAP_KEYS_DIR and os.path.isdir(RMAP_KEYS_DIR)):
    raise RuntimeError(f"RMAP_KEYS_DIR not found or not a directory: {RMAP_KEYS_DIR}")
_require_file(RMAP_SERVER_PRIV, "RMAP_SERVER_PRIV")
_require_file(RMAP_SERVER_PUB,  "RMAP_SERVER_PUB")
if not RMAP_INPUT_PDF:
    raise RuntimeError("RMAP_INPUT_PDF is not set")

# ---------- RMAP wiring ----------
im = IdentityManager(
    RMAP_KEYS_DIR,
    RMAP_SERVER_PRIV,
    RMAP_SERVER_PUB
)
rmap = RMAP(im)

# Sessions:
#   key   -> (identity, nonceClient)
#   value -> {"nonceServer": int, "ts": float}
_SESSION_TTL = 300  # seconds
_sessions: Dict[Tuple[str, int], Dict[str, float | int]] = {}




# 尝试把 base64 解出来的密文字节 -> 解密 -> JSON对象。  失败则抛异常。
def _coerce_to_json_from_enc(enc_bytes: bytes) -> dict:
    armored = enc_bytes.decode("ascii", "strict")
    priv, _ = PGPKey.from_file(RMAP_SERVER_PRIV)
    msg = PGPMessage.from_blob(armored)
    pt = priv.decrypt(msg).message
    pt_text = pt.decode("utf-8") if isinstance(pt, (bytes, bytearray)) else pt
    return json.loads(pt_text)




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

def _find_session_by_nonce_server(identity: str, nonce_server: int) -> Optional[Tuple[int, Dict[str, float | int]]]:
    """Return (nonce_client, session) matching identity & nonce_server, else None."""
    for (idn, ncli), sess in _sessions.items():
        if idn == identity and sess.get("nonceServer") == nonce_server:
            return ncli, sess
    return None

# ---------- endpoints ----------
@bp.post("/rmap-initiate")
def rmap_initiate():
    try:
        data = request.get_json(silent=True) or {}
        payload_b64 = data.get("payload") or ""
        if not payload_b64:
            return jsonify({"error": "missing payload"}), 400

        enc = base64.b64decode(payload_b64)           # 密文字节（ASCII-armored PGP 的 b64）
        msg1 = rmap.receive_message1(enc)  
        

        identity     = msg1["identity"]
        nonce_client = msg1["nonceClient"]

        nonce_server, response1 = rmap.generate_response1(identity, nonce_client)
        _sessions[identity] = {
            "nonceClient": nonce_client,
            "nonceServer": nonce_server,
            "ts": time.time(),
        }

        return jsonify({"payload": base64.b64encode(response1).decode()}), 200
    except Exception as e:
        current_app.logger.exception("rmap-initiate failed")
        return jsonify({"error": f"rmap-initiate failed: {e}"}), 400





@bp.post("/rmap-get-link")
def rmap_get_link():
    try:
        # 1) 读取请求体
        data = request.get_json(silent=True) or {}
        payload_b64 = data.get("payload") or ""
        if not payload_b64:
            return jsonify({"error": "missing payload"}), 400

        # 2) base64 → 密文字节，交给 RMAP 解析 message2
        enc = base64.b64decode(payload_b64)

        # 使用 rmap.receive_message2：返回 dict，包含 identity + nonceServer
        msg2 = rmap.receive_message2(enc)
        # 兜底校验，避免库返回异常结构
        if not isinstance(msg2, dict) or not {"identity", "nonceServer"} <= set(msg2.keys()):
            current_app.logger.warning("handle_message2 returned unexpected: %r", msg2)
            return jsonify({"error": "bad message2"}), 400

        identity     = msg2["identity"]
        nonce_server = msg2["nonceServer"]

        # 3) 用 (identity, nonce_server) 反查会话，拿到 nonce_client + sess
        found = _find_session_by_nonce_server(identity, nonce_server)
        if not found:
            return jsonify({"error": "Invalid session or nonce"}), 403
        nonce_client, sess = found

        # 4) 会话校验 + TTL
        if sess.get("nonceServer") != nonce_server:
            return jsonify({"error": "Invalid session or nonce"}), 403
        if time.time() - sess["ts"] > _SESSION_TTL:
            return jsonify({"error": "Session expired"}), 403

        # 5) 计算会话 secret（用于水印内容/命名）
        secret = hashlib.sha256(
            f"{int(nonce_client)}{int(nonce_server)}".encode("utf-8")
        ).hexdigest()

        # 6) 读取输入 PDF（由环境变量 RMAP_INPUT_PDF 指定）
        src_fp = Path(RMAP_INPUT_PDF).resolve()
        if not src_fp.is_file():
            current_app.logger.error("RMAP_INPUT_PDF not found: %s", src_fp)
            return jsonify({"error": "input pdf not found"}), 500
        pdf_bytes = src_fp.read_bytes()

        # 7) 生成水印 PDF（用你现有的 VisibleTextWatermark 实现）
        wm = VisibleTextWatermark()
        try:
            out_bytes = wm.add_watermark(pdf_bytes, secret, WATERMARK_HMAC_KEY)
        except Exception as e:
            current_app.logger.exception("watermarking failed")
            return jsonify({"error": f"watermarking failed: {e}"}), 500

        # 8) 落盘到 /app/storage/watermarks/<secret>.pdf
        out_dir = Path(current_app.config.get("STORAGE_DIR", "/app/storage")) / "watermarks"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_fp = out_dir / f"{secret}.pdf"
        out_fp.write_bytes(out_bytes)

        # 9) （可选）写 DB：如果你之前的表和连接都可用，保留这段；否则可以整段删掉
        try:
            eng = _get_engine()
            with eng.begin() as conn:
                row = conn.execute(
                    text("SELECT id FROM Documents WHERE path = :path LIMIT 1"),
                    {"path": str(src_fp)}
                ).fetchone()
                if row:
                    docid = row[0]
                    conn.execute(
                        text("""INSERT INTO Versions
                                (documentid, link, intended_for, secret, method, position, path)
                                VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)"""),
                        {
                            "documentid": docid,
                            "link": out_fp.name,
                            "intended_for": identity,
                            "secret": secret,
                            "method": "visible+metadata+eof",  # 你报告里定义的“最佳”组合
                            "position": "footer",
                            "path": str(out_fp)
                        }
                    )
                else:
                    current_app.logger.warning("Document not found in DB for path: %s", src_fp)
        except Exception:
            # DB 失败不阻断整体流程（已经生成了水印 PDF）
            current_app.logger.exception("DB insert failed (non-fatal)")

        # 10) 返回结果（按你当前前后端约定返回 secret）
        return jsonify({"result": secret}), 200

    except Exception:
        current_app.logger.exception("rmap-get-link failed")
        return jsonify({"error": "internal server error"}), 500



