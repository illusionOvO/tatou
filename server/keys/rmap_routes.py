# server/src/rmap_routes.py
# -*- coding: utf-8 -*-
from __future__ import annotations

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

import os, time, base64, hashlib
from pathlib import Path
from typing import Dict, Tuple, Optional
from flask import Blueprint, request, jsonify, current_app
from sqlalchemy import create_engine, text
from rmap.identity_manager import IdentityManager
from rmap.rmap import RMAP

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

def _looks_ascii_armored(s: str) -> bool:
    s = s.lstrip()
    return s.startswith("-----BEGIN PGP")

def _extract_payload_bytes() -> bytes:
    """
    Accepts:
      - JSON: {"payload": "<base64>"}  (current)
      - JSON: {"payload": "-----BEGIN PGP MESSAGE----- ..."} (ASCII-armored)
      - Raw body: application/octet-stream / text/plain / application/pgp-encrypted
      - (Optional) hex string as payload
    Returns raw pgp bytes for rmap.handle_messageX(...)
    """
    # 1) Try JSON first
    data = request.get_json(silent=True)
    if isinstance(data, dict) and "payload" in data:
        val = data.get("payload") or ""
        if isinstance(val, (bytes, bytearray)):
            return bytes(val)

        if not isinstance(val, str):
            raise ValueError("payload must be string or bytes")

        # ASCII-armored?
        if _looks_ascii_armored(val):
            return val.encode("utf-8")

        # Try base64
        try:
            return base64.b64decode(val, validate=True)
        except Exception:
            pass

        # Try hex
        hexchars = set("0123456789abcdefABCDEF")
        if val and all(c in hexchars for c in val.replace(" ", "")):
            try:
                return bytes.fromhex(val.replace(" ", ""))
            except Exception:
                pass

        # Fallback: treat as raw bytes from string
        return val.encode("utf-8")

    # 2) Not JSON or no 'payload' -> use raw body if present
    raw = request.get_data(cache=False, as_text=False) or b""
    if raw:
        # If looks like text, check ASCII-armored
        try:
            text = raw.decode("utf-8", errors="ignore")
            if _looks_ascii_armored(text):
                return text.encode("utf-8")
        except Exception:
            pass
        return raw

    raise ValueError("missing payload")


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
im = IdentityManager(RMAP_KEYS_DIR, RMAP_SERVER_PRIV, RMAP_SERVER_PUB)
rmap = RMAP(im)

# Sessions:
#   key   -> (identity, nonceClient)
#   value -> {"nonceServer": int, "ts": float}
_SESSION_TTL = 300  # seconds
_sessions: Dict[Tuple[str, int], Dict[str, float | int]] = {}

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
        try:
            enc = _extract_payload_bytes()
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        # rmap.handle_message1 returns a dict including identity, nonceClient, nonceServer, response
        msg1 = rmap.handle_message1(enc)
        identity     = msg1["identity"]
        nonce_client = msg1["nonceClient"]
        nonce_server = msg1["nonceServer"]

        _sessions[(identity, nonce_client)] = {"nonceServer": nonce_server, "ts": time.time()}

        return jsonify({"payload": base64.b64encode(msg1["response"]).decode()}), 200
    except Exception:
        current_app.logger.exception("rmap-initiate failed")
        return jsonify({"error": "internal server error"}), 500

@bp.post("/rmap-get-link")
def rmap_get_link():
    try:
        try:
            enc = _extract_payload_bytes()
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        # rmap.handle_message2 returns a dict including identity, nonceServer (and maybe nonceClient depending on version)
        msg2 = rmap.handle_message2(enc)
        identity     = msg2["identity"]
        nonce_server = msg2["nonceServer"]
        nonce_client = msg2.get("nonceClient")  # may be absent in some lib versions

        if nonce_client is not None:
            sess = _sessions.get((identity, nonce_client))
        else:
            found = _find_session_by_nonce_server(identity, nonce_server)
            if not found:
                return jsonify({"error": "Invalid session or nonce"}), 403
            nonce_client, sess = found

        if not sess or sess.get("nonceServer") != nonce_server:
            return jsonify({"error": "Invalid session or nonce"}), 403
        if time.time() - sess["ts"] > _SESSION_TTL:
            return jsonify({"error": "Session expired"}), 403

        # Session secret = sha256( str(nonceClient) || str(nonceServer) )
        secret = hashlib.sha256(f"{int(nonce_client)}{int(nonce_server)}".encode()).hexdigest()

        # --- Generate watermarked PDF (composite "best" technique) ---
        src_fp = Path(RMAP_INPUT_PDF).resolve()
        pdf_bytes = src_fp.read_bytes()

        wm = VisibleTextWatermark()
        out_bytes = wm.add_watermark(pdf_bytes, secret, WATERMARK_HMAC_KEY)

        # Save to storage
        out_dir = Path(current_app.config.get("STORAGE_DIR", "/app/storage")) / "watermarks"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_fp = out_dir / f"{secret}.pdf"
        out_fp.write_bytes(out_bytes)

        # Insert DB row (auto-resolve documentid via Documents.path == RMAP_INPUT_PDF)
        try:
            eng = _get_engine()
            with eng.begin() as conn:
                row = conn.execute(
                    text("SELECT id FROM Documents WHERE path = :path LIMIT 1"),
                    {"path": str(src_fp)}
                ).fetchone()
                if not row:
                    raise RuntimeError(f"Document not found in DB for path: {src_fp}")
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
                        "method": "visible+metadata+eof",  # our "best" composite technique
                        "position": "footer",              # adjust to your actual render position
                        "path": str(out_fp)
                    }
                )
        except Exception:
            current_app.logger.exception("DB insert failed")
            return jsonify({"error": "internal server error"}), 500

        return jsonify({"result": secret}), 200
    except Exception:
        current_app.logger.exception("rmap-get-link failed")
        return jsonify({"error": "internal server error"}), 500
