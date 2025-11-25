# server_merged.py (FINAL VERSION)
import os
import re
import io
import hashlib
import datetime as dt
from pathlib import Path
from functools import wraps

from sqlalchemy.exc import IntegrityError 

from flask import Flask, jsonify, request, g, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

import pickle as _std_pickle
try:
    import dill as _pickle  # allows loading classes not importable by module path
except Exception:
    _pickle = _std_pickle

# Keep the blueprint import as in original files.
# If your runtime package path differs, adjust this import target accordingly.
from .rmap_routes import bp as rmap_bp  # unified import

from . import watermarking_utils as WMUtils
from .watermarking_method import WatermarkingMethod

# ---------------------------------------------------------------------------
# 1. 通用工具函数（与 Flask 无关）
# ---------------------------------------------------------------------------

def _sha256_file(path: Path) -> str:
    """计算文件的 SHA256（原来在 create_app 里面的 _sha256_file）。"""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

# Helper: resolve path safely under STORAGE_DIR (handles absolute/relative)
def _safe_resolve_under_storage(p: str | Path, storage_root: Path) -> Path:
    """安全地把用户传的路径限制在 STORAGE_DIR 下面。"""
    storage_root = storage_root.resolve()
    fp = Path(p)
    if not fp.is_absolute():
        fp = storage_root / fp
    fp = fp.resolve()
    try:
        fp.relative_to(storage_root)
    except ValueError:
        raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
    return fp


# ---------------------------------------------------------------------------
# 2. Flask app 工厂
# ---------------------------------------------------------------------------

# --- DB engine only (no Table metadata) ---
def db_url(app) -> str:

    # 检查是否配置了通用的 SQLAlchemy URI (这是 pytest 设置的)
    if 'SQLALCHEMY_DATABASE_URI' in app.config:
        return app.config['SQLALCHEMY_DATABASE_URI']
    
    # 如果没有配置通用 URI (默认情况)，则退回到 MySQL 配置
    return (
        f"mysql+pymysql://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}"
        f"@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_NAME']}?charset=utf8mb4"
    )

def get_engine(app):
    eng = app.config.get("_ENGINE")
    if eng is None:
        eng = create_engine(db_url(app), pool_pre_ping=True, future=True)
        app.config["_ENGINE"] = eng
    return eng

def _serializer(app):
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")


def create_app():
    app = Flask(__name__)

    # --- Config ---
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["STORAGE_DIR"] = Path(os.environ.get("STORAGE_DIR", "./storage")).resolve()
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))
    # --- RMAP ---
    app.config["RMAP_KEYS_DIR"]    = os.getenv("RMAP_KEYS_DIR", "server/keys/clients")
    app.config["RMAP_SERVER_PUB"]  = os.getenv("RMAP_SERVER_PUB", "server/keys/server_pub.asc")
    app.config["RMAP_SERVER_PRIV"] = os.getenv("RMAP_SERVER_PRIV", "server/keys/server_priv.asc")
    # 注册 RMAP blueprint
    app.register_blueprint(rmap_bp, url_prefix="/api")
    # --- DB ---
    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "tatou")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")

    # 存储目录
    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)



# ---------------------------------------------------------------------------
# 3. DB 与鉴权相关帮助函数
# ---------------------------------------------------------------------------

    # --- Helpers ---

    def _auth_error(msg: str, code: int = 401):
        return jsonify({"error": msg}), code

    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return _auth_error("Missing or invalid Authorization header")
            token = auth.split(" ", 1)[1].strip()
            try:
                data = _serializer(app).loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
            except SignatureExpired:
                return _auth_error("Token expired")
            except BadSignature:
                return _auth_error("Invalid token")
            g.user = {"id": int(data["uid"]), "login": data["login"], "email": data.get("email")}
            return f(*args, **kwargs)
        return wrapper


    # --- Routes ---

    # -----------------------------------------------------------------------
    # 4. 静态文件 & 基础健康检查
    # -----------------------------------------------------------------------
    @app.route("/<path:filename>")
    def static_files(filename):
        return app.send_static_file(filename)

    @app.route("/")
    def home():
        return app.send_static_file("index.html")
    
    # 3.1 健康检查
    @app.get("/healthz")
    def healthz():
        try:
            with get_engine(app).connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify({"message": "The server is up and running.", "db_connected": db_ok}), 200


    # -----------------------------------------------------------------------
    # 5. 用户相关 API：create-user / login / password
    # -----------------------------------------------------------------------    
    @app.post("/api/create-user")
    def create_user():
        payload = request.get_json(silent=True) or {}
        email = str(payload.get("email") or "").strip().lower()
        login = str(payload.get("login") or "").strip()
        password = payload.get("password") # KEEP IT AS IS TO CHECK TYPE LATER

        # --- [FIXED: Fuzz Bug 1 & 2 - Length and Type Check] ---
        if not email or not login or not password:
            return jsonify({"error": "email, login, and password are required"}), 400
        
        # 确保密码是字符串，防止 500 (Bug 2)
        if not isinstance(password, str):
            return jsonify({"error": "Password must be a string"}), 400
        
        # 限制 login 长度，防止 503 (Bug 1 - 数据库溢出)
        if len(login) > 255: # Assuming max DB length of 255
            return jsonify({"error": "Login too long"}), 400
        # --------------------------------------------------------

        hpw = generate_password_hash(password)

        try:
            with get_engine(app).begin() as conn:
                res = conn.execute(
                    text("INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)"),
                    {"email": email, "hpw": hpw, "login": login},
                )
                uid = int(res.lastrowid)
                row = conn.execute(
                    text("SELECT id, email, login FROM Users WHERE id = :id"),
                    {"id": uid},
                ).one()
        except IntegrityError:
            return jsonify({"error": "email or login already exists"}), 409
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    # POST /api/login {email, password}
    @app.post("/api/login")
    def login():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip()
        password = payload.get("password") # KEEP IT AS IS TO CHECK TYPE LATER
        
        # --- [FIXED: Fuzz Bug 3 - Type Check] ---
        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400
            
        if not isinstance(password, str):
            return jsonify({"error": "Password must be a string"}), 400
        # ----------------------------------------

        try:
            with get_engine(app).connect() as conn:
                row = conn.execute(
                    text("SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"),
                    {"email": email},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {e}"}), 503

        if not row or not check_password_hash(row.hpassword, password):
            return jsonify({"error": "invalid credentials"}), 401

        token = _serializer(app).dumps({"uid": int(row.id), "login": row.login, "email": row.email})
        return jsonify({"token": token, "token_type": "bearer", "expires_in": app.config["TOKEN_TTL_SECONDS"]}), 200


    # -----------------------------------------------------------------------
    # 6. 文档相关 API：upload / list / get / delete / versions
    # -----------------------------------------------------------------------
    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
        if "file" not in request.files:
            return jsonify({"error": "file is required (multipart/form-data)"}), 400
        file = request.files["file"]
        if not file or file.filename == "":
            return jsonify({"error": "empty filename"}), 400

        fname = secure_filename(file.filename)
        if not fname.lower().endswith(".pdf"):
            return jsonify({"error": "only PDF files are allowed"}), 400

        # MIME check; if mismatch, verify header starts with %PDF
        if file.mimetype != "application/pdf":
            header = file.stream.read(4)
            file.stream.seek(0)
            if header != b"%PDF":
                return jsonify({"error": "file is not a valid PDF"}), 400

        user_dir = app.config["STORAGE_DIR"] / "files" / g.user["login"]
        user_dir.mkdir(parents=True, exist_ok=True)

        ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
        final_name = request.form.get("name") or fname
        stored_name = f"{ts}__{fname}"
        stored_path = user_dir / stored_name
        file.save(stored_path)

        sha_hex = _sha256_file(stored_path)
        size = stored_path.stat().st_size

        try:
            with get_engine(app).begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Documents (name, path, ownerid, sha256, size)
                        VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
                    """),
                    {
                        "name": final_name,
                        "path": str(stored_path),
                        "ownerid": int(g.user["id"]),
                        "sha256hex": sha_hex,
                        "size": int(size),
                    },
                )
                did = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
                row = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id
                    """),
                    {"id": did},
                ).one()
        except Exception as e:
            return jsonify({"error": f"database error: {e}"}), 503

        return jsonify({
            "id": int(row.id),
            "name": row.name,
            "creation": row.creation.isoformat() if hasattr(row.creation, "isoformat") else str(row.creation),
            "sha256": row.sha256_hex,
            "size": int(row.size),
        }), 201

    # GET /api/list-documents
    @app.get("/api/list-documents")
    @require_auth
    def list_documents():
        try:
            with get_engine(app).connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE ownerid = :uid
                        ORDER BY creation DESC
                    """),
                    {"uid": int(g.user["id"])},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {e}"}), 503

        docs = [{
            "id": int(r.id),
            "name": r.name,
            "creation": r.creation.isoformat() if hasattr(r.creation, "isoformat") else str(r.creation),
            "sha256": r.sha256_hex,
            "size": int(r.size),
        } for r in rows]
        return jsonify({"documents": docs}), 200

    # GET /api/list-versions[/<document_id>]
    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<int:document_id>")
    @require_auth
    def list_versions(document_id: int | None = None):
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        try:
            with get_engine(app).connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.secret, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.login = :glogin AND d.id = :did
                    """),
                    {"glogin": str(g.user["login"]), "did": document_id},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {e}"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "secret": r.secret,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200

    # GET /api/list-all-versions
    @app.get("/api/list-all-versions")
    @require_auth
    def list_all_versions():
        try:
            with get_engine(app).connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.login = :glogin
                    """),
                    {"glogin": str(g.user["login"])},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {e}"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200

    # GET /api/get-document[/<id>]
    @app.get("/api/get-document")
    @app.get("/api/get-document/<int:document_id>")
    @require_auth
    def get_document(document_id: int | None = None):
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        try:
            with get_engine(app).connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": document_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {e}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.name if str(row.name).lower().endswith(".pdf") else f"{row.name}.pdf",
            conditional=True,
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )
        if isinstance(row.sha256_hex, str) and row.sha256_hex:
            resp.set_etag(row.sha256_hex.lower())

        resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        return resp

    # GET /api/get-version/<link>
    @app.get("/api/get-version/<link>")
    def get_version(link: str):
        try:
            with get_engine(app).connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT *
                        FROM Versions
                        WHERE link = :link
                        LIMIT 1
                    """),
                    {"link": link},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {e}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.link if str(row.link).lower().endswith(".pdf") else f"{row.link}.pdf",
            conditional=True,
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )
        resp.headers["Cache-Control"] = "private, max-age=0"
        return resp

    # DELETE /api/delete-document (支持 DELETE/POST)
    @app.route("/api/delete-document", methods=["DELETE", "POST"])
    @app.route("/api/delete-document/<document_id>", methods=["DELETE"])
    @require_auth
    def delete_document(document_id: int | None = None):
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = int(document_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        try:
            with get_engine(app).connect() as conn:
                row = conn.execute(
                    text("SELECT id, path FROM Documents WHERE id = :id AND ownerid = :uid"),
                    {"id": doc_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {e}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        storage_root = Path(app.config["STORAGE_DIR"])
        file_deleted = False
        file_missing = False
        try:
            fp = _safe_resolve_under_storage(row.path, storage_root)
            if fp.exists():
                fp.unlink()
                file_deleted = True
            else:
                file_missing = True
        except Exception as e:
            app.logger.error("Path safety check failed for doc id=%s: %s", row.id, e)

        try:
            with get_engine(app).begin() as conn:
                conn.execute(
                    text("DELETE FROM Documents WHERE id = :id AND ownerid = :uid"),
                    {"id": doc_id, "uid": int(g.user["id"])},
                )
        except Exception as e:
            return jsonify({"error": f"database error during delete: {e}"}), 503

        return jsonify({
            "deleted": True,
            "id": doc_id,
            "file_deleted": file_deleted,
            "file_missing": file_missing,
        }), 200
    


    # -----------------------------------------------------------------------
    # 7. 水印相关 API：get-methods / create-watermark / read-watermark
    # -----------------------------------------------------------------------
    # POST /api/create-watermark[/<id>]
    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<int:document_id>")
    @require_auth
    def create_watermark(document_id: int | None = None):
        # 接收 id（path、query 或 JSON）
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = int(document_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document id required and must be integer"}), 400
        
        # 2. 解析 JSON 参数
        payload = request.get_json(silent=True) or {}
        method = payload.get("method")
        intended_for = payload.get("intended_for")
        position = payload.get("position") or None
        secret = payload.get("secret")
        key = payload.get("key")
        if not method or not intended_for or not isinstance(secret, str) or not isinstance(key, str):
            return jsonify({"error": "method, intended_for, secret, and key are required"}), 400

        # ① 严格所有权检查
        try:
            with get_engine(app).connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id AND ownerid = :ownerid
                        LIMIT 1
                    """),
                    {"id": doc_id, "ownerid": int(g.user["id"])},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {e}"}), 503
        if not row:
            return jsonify({"error": "document not found"}), 404

        # 路径校验
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # 检查水印方法是否适用
        try:
            applicable = WMUtils.is_watermarking_applicable(
                method=method, pdf=str(file_path), position=position
            )
            if applicable is False:
                return jsonify({"error": "watermarking method not applicable"}), 400
        except Exception as e:
            return jsonify({"error": f"watermark applicability check failed: {e}"}), 400

        # 执行水印
        try:
            wm_bytes: bytes = WMUtils.apply_watermark(
                pdf=str(file_path), secret=secret, key=key, method=method, position=position
            )
            if not isinstance(wm_bytes, (bytes, bytearray)) or len(wm_bytes) == 0:
                return jsonify({"error": "watermarking produced no output"}), 500
        except Exception as e:
            return jsonify({"error": f"watermarking failed: {e}"}), 500

        # 写到磁盘
        base_name = Path(row.name or file_path.name).stem
        intended_slug = secure_filename(intended_for)
        dest_dir = file_path.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)
        candidate = f"{base_name}__{intended_slug}.pdf"
        dest_path = dest_dir / candidate
        try:
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
        except Exception as e:
            return jsonify({"error": f"failed to write watermarked file: {e}"}), 500


        import uuid
        link_token = uuid.uuid4().hex
        method_official = WMUtils.get_method(method).name

        params = {
            "documentid": doc_id,
            "link": link_token,
            "intended_for": intended_for,
            "secret": secret,
            "method": method_official,
            "position": position or "",
            "path": str(dest_path),
        }

        # 9. 入库 + 处理重复 link 的情况（uq_Versions_link）
        try:
            # 正常情况：插入一条新的版本记录
            with get_engine(app).begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Versions
                            (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    params,
                )
                vid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())

        except IntegrityError as e:
            # 这里专门处理「uq_Versions_link 唯一键冲突」—— 说明同一个 link 已经存在
            msg = str(getattr(e, "orig", e))
            if "Duplicate entry" in msg and "uq_Versions_link" in msg:
                # 把已经存在的那条版本记录查出来，当作结果返回（幂等）
                with get_engine(app).connect() as conn:
                    row = conn.execute(
                        text("""
                            SELECT id
                            FROM Versions
                            WHERE documentid = :documentid AND link = :link
                        """),
                        {"documentid": doc_id, "link": link_token},
                    ).first()

                if row is not None:
                    vid = int(row.id)
                    # 不再视为错误，直接返回成功响应
                    return jsonify(
                        {
                            "id": vid,
                            "documentid": doc_id,
                            "link": link_token,
                            "intended_for": intended_for,
                            "method": method_official,
                            "position": position,
                            "filename": candidate,
                            "size": len(wm_bytes),
                        }
                    ), 201

            # 如果不是我们预期的唯一键错误，走通用错误处理
            try:
                dest_path.unlink(missing_ok=True)
            except Exception:
                pass
            return jsonify(
                {"error": f"database error during version insert: {e}"}
            ), 503

        except Exception as e:
            # 其它任何异常，仍然走通用错误处理
            try:
                dest_path.unlink(missing_ok=True)
            except Exception:
                pass
            return jsonify(
                {"error": f"database error during version insert: {e}"}
            ), 503

        return jsonify({

            "id": vid,
            "documentid": doc_id,
            "link": link_token,
            "intended_for": intended_for,
            "method": method_official,
            "position": position,
            "filename": candidate,
            "size": len(wm_bytes),

        }), 201

    # GET /api/get-watermarking-methods
    @app.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        methods = []
        for m in WMUtils.METHODS:
            methods.append({"name": m, "description": WMUtils.get_method(m).get_usage()})
        return jsonify({"methods": methods, "count": len(methods)}), 200

    # POST /api/read-watermark[/<id>]
    @app.post("/api/read-watermark")
    @app.post("/api/read-watermark/<int:document_id>")
    @require_auth
    def read_watermark(document_id: int | None = None):
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = int(document_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document id required and must be integer"}), 400

        payload = request.get_json(silent=True) or {}
        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")

        # ------------------ RESTORED: Real watermark-reading code ------------------
        if not method or not isinstance(key, str):
            return jsonify({"error": "method and key are required"}), 400

        # Enforce ownership (secure behavior)
        try:
            with get_engine(app).connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id AND ownerid = :ownerid
                        LIMIT 1
                    """),
                    {"id": doc_id, "ownerid": int(g.user["id"])},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {e}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404
        

        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        try:
            secret = WMUtils.read_watermark(
                method=method,
                pdf=str(file_path),
                key=key
            )
        except Exception as e:
            return jsonify({"error": f"Error when attempting to read watermark: {e}"}), 400

        return jsonify({
            "documentid": doc_id,
            "secret": secret,
            "method": method,
            "position": position
        }), 200
        # ---------------------------------------------------------------------


    # -----------------------------------------------------------------------
    # 8. 插件加载 API：load-plugin
    # -----------------------------------------------------------------------
    # POST /api/load-plugin  (安全加固并修复缺失 import re)
    @app.post("/api/load-plugin")
    @require_auth
    def load_plugin():
        """
        Load a serialized Python class implementing WatermarkingMethod from
        STORAGE_DIR/files/plugins/<filename>.{pkl|dill} and register it in WMUtils.METHODS.
        Body: { "filename": "MyMethod.pkl", "overwrite": false }
        """
        payload = request.get_json(silent=True) or {}
        filename = (payload.get("filename") or "").strip()
        overwrite = bool(payload.get("overwrite", False))

        if not filename:
            return jsonify({"error": "filename is required"}), 400

        if not re.match(r'^[a-zA-Z0-9_\-]+\.(pkl|dill)$', filename):
            return jsonify({"error": "invalid filename format"}), 400

        safe_filename = secure_filename(filename)
        if safe_filename != filename:
            return jsonify({"error": "filename contains invalid characters"}), 400

        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        plugins_dir = storage_root / "files" / "plugins"
        try:
            plugins_dir.mkdir(parents=True, exist_ok=True)
            plugin_path = (plugins_dir / safe_filename).resolve()
            # Portable relative_to check
            try:
                plugin_path.relative_to(plugins_dir.resolve())
            except ValueError:
                return jsonify({"error": "invalid file path"}), 400
        except Exception as e:
            return jsonify({"error": f"plugin path error: {e}"}), 500

        if not plugin_path.exists():
            return jsonify({"error": f"plugin file not found: {safe_filename}"}), 404

        max_plugin_size = 10 * 1024 * 1024
        size = plugin_path.stat().st_size
        if size == 0:
            return jsonify({"error": "plugin file is empty"}), 400
        if size > max_plugin_size:
            return jsonify({"error": "plugin file too large"}), 400

        try:
            with plugin_path.open("rb") as f:
                obj = _pickle.load(f)
        except _pickle.UnpicklingError as e:
            return jsonify({"error": f"malformed plugin file: {e}"}), 400
        except Exception as e:
            return jsonify({"error": f"failed to deserialize plugin: {e}"}), 400

        allowed_types = (type, WatermarkingMethod)
        if not isinstance(obj, allowed_types):
            return jsonify({"error": "plugin must be a class or WatermarkingMethod instance"}), 400

        cls = obj if isinstance(obj, type) else obj.__class__
        class_name = getattr(cls, "__name__", "")
        if any(pat in class_name.lower() for pat in ["system", "os", "subprocess", "eval", "exec"]):
            return jsonify({"error": "suspicious class name detected"}), 400

        method_name = getattr(cls, "name", getattr(cls, "__name__", None))
        if not method_name or not isinstance(method_name, str):
            return jsonify({"error": "plugin class must define a readable name"}), 400
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", method_name):
            return jsonify({"error": "invalid method name format"}), 400

        has_api = all(hasattr(cls, attr) for attr in ("add_watermark", "read_secret"))
        is_ok = issubclass(cls, WatermarkingMethod) and has_api if WatermarkingMethod is not None else has_api
        if not is_ok:
            return jsonify({"error": "plugin does not implement WatermarkingMethod API (add_watermark/read_secret)"}), 400

        if not overwrite and method_name in WMUtils.METHODS:
            return jsonify({"error": f"method '{method_name}' already exists, use overwrite=true to replace"}), 409

        try:
            WMUtils.METHODS[method_name] = cls()
        except Exception as e:
            return jsonify({"error": f"failed to instantiate plugin: {e}"}), 500

        return jsonify({
            "loaded": True,
            "filename": safe_filename,
            "registered_as": method_name,
            "class_qualname": f"{getattr(cls, '__module__', '?')}.{getattr(cls, '__qualname__', cls.__name__)}",
            "methods_count": len(WMUtils.METHODS)
        }), 201


    return app



# WSGI entrypoint
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)