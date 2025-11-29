import pytest
import sys
import uuid
from pathlib import Path
from sqlalchemy import text, create_engine
from sqlalchemy.pool import StaticPool
import fitz  # PyMuPDF

# 确保能导入 server 模块
ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from server.src.server import create_app

@pytest.fixture
def app(mocker, tmp_path):
    """
    提供配置了内存数据库且已初始化表的 Flask app。
    使用 StaticPool + Mock get_engine，确保服务器连接到正确的数据库实例。
    """
    
    # 1. 创建一个持久的内存数据库引擎 (StaticPool)
    test_engine = create_engine(
        "sqlite:///:memory:", 
        connect_args={"check_same_thread": False}, 
        poolclass=StaticPool 
    )
    
    # 【核心绝杀】：直接劫持 server.py 中的 get_engine 函数
    # 无论服务器怎么调用，都强制返回我们这个已经建好表的 test_engine
    mocker.patch('server.src.server.get_engine', return_value=test_engine)
    
    # 同时劫持 rmap_routes 中的 _get_engine (以防万一)
    mocker.patch('server.src.rmap_routes._get_engine', return_value=test_engine)

    # 2. 配置 Flask 和 临时存储
    flask_app = create_app()
    storage_dir = tmp_path / "storage_test"
    storage_dir.mkdir(exist_ok=True)
    
    flask_app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "_ENGINE": test_engine, 
        "STORAGE_DIR": storage_dir,
    })

    # 3. 直接写入 SQLite 表结构 (无需读取 tatou.sql)
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

    # 4. 初始化数据库
    with flask_app.app_context():
        with test_engine.begin() as conn:
            for statement in sqlite_schema.strip().split(';'):
                if statement.strip():
                    conn.execute(text(statement))
            
    return flask_app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def auth_headers(client):
    """自动注册并登录，返回 Header"""
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
    """使用 fitz 生成合法 PDF，解决 zero pages 问题"""
    pdf_path = tmp_path_factory.mktemp("pdfs") / "sample.pdf"
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((50, 50), "Valid Content")
    doc.save(str(pdf_path))
    doc.close()
    return pdf_path