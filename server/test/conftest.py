import pytest
import sys
import uuid
from pathlib import Path
from sqlalchemy import text, create_engine, event
from sqlalchemy.pool import StaticPool
import fitz  # PyMuPDF
import binascii

# 确保能导入 server 模块
ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from server.src.server import create_app

# --- 自定义 UNHEX 函数 ---
def _sqlite_unhex(hex_str):
    if hex_str is None:
        return None
    try:
        return binascii.unhexlify(hex_str)
    except Exception:
        return None

@pytest.fixture(scope="function")
def app(tmp_path):
    """
    提供 Flask app，并强制注入使用 StaticPool 的内存数据库引擎。
    """
    # 1. 创建持久的内存数据库引擎
    test_engine = create_engine(
        "sqlite:///:memory:", 
        connect_args={"check_same_thread": False}, 
        poolclass=StaticPool 
    )
    
    # 注册 UNHEX
    @event.listens_for(test_engine, "connect")
    def register_custom_functions(dbapi_connection, connection_record):
        dbapi_connection.create_function("UNHEX", 1, _sqlite_unhex)

    flask_app = create_app()
    
    # 配置临时存储目录
    storage_dir = tmp_path / "storage_test"
    storage_dir.mkdir(exist_ok=True)
    
    # 【关键】：直接将 test_engine 注入到 app.config
    # 这样 server.py 中的 get_engine(app) 就会直接返回它，而不会去创建新连接
    flask_app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "_ENGINE": test_engine,  # <--- 核心：直接注入引擎
        "STORAGE_DIR": storage_dir,
    })

    # 2. 建表
    sqlite_schema = """
    CREATE TABLE Users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        hpassword TEXT NOT NULL,
        login TEXT NOT NULL,
        UNIQUE(email),
        UNIQUE(login)
    );

    CREATE TABLE Documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        path TEXT NOT NULL,
        ownerid INTEGER NOT NULL,
        sha256 BLOB,
        size INTEGER,
        creation TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(path),
        FOREIGN KEY(ownerid) REFERENCES Users(id) ON DELETE CASCADE
    );

    CREATE TABLE Versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        documentid INTEGER NOT NULL,
        link TEXT NOT NULL,
        intended_for TEXT,
        secret TEXT NOT NULL,
        method TEXT NOT NULL,
        position TEXT,
        path TEXT NOT NULL,
        UNIQUE(link),
        FOREIGN KEY(documentid) REFERENCES Documents(id) ON DELETE CASCADE
    );
    """

    with flask_app.app_context():
        # 这里不需要 get_engine()，直接用我们手里的 test_engine
        with test_engine.begin() as conn:
            for statement in sqlite_schema.strip().split(';'):
                if statement.strip():
                    conn.execute(text(statement))
            
    yield flask_app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def auth_headers(client):
    email = f"auto-{uuid.uuid4().hex[:8]}@example.com"
    password = "Passw0rd!"
    client.post("/api/create-user", json={
        "email": email, "login": f"u_{uuid.uuid4().hex[:8]}", "password": password
    })
    resp = client.post("/api/login", json={"email": email, "password": password})
    if resp.status_code != 200:
        return {}
    token = resp.get_json()["token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture(scope="session")
def sample_pdf_path(tmp_path_factory):
    pdf_path = tmp_path_factory.mktemp("pdfs") / "sample.pdf"
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((50, 50), "Valid PDF Content")
    doc.save(str(pdf_path))
    doc.close()
    return pdf_path