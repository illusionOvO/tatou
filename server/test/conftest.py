import pytest
import sys
import uuid
from pathlib import Path
from sqlalchemy import text
import fitz  # PyMuPDF

# 确保能导入 server 模块
ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from server.src.server import create_app, get_engine, db_url

@pytest.fixture
def app(mocker, tmp_path):
    """
    提供配置了内存数据库且已初始化表的 Flask app。
    【绝杀方案】：直接使用 Python 字符串定义 SQLite 表结构，不再读取 tatou.sql 文件。
    """
    # 1. 强制 server.py 里的 db_url 使用 SQLite
    mocker.patch('server.src.server.db_url', return_value='sqlite:///:memory:')
    
    flask_app = create_app()
    
    # 配置临时存储目录，解决 PermissionError
    storage_dir = tmp_path / "storage_test"
    storage_dir.mkdir(exist_ok=True)

    flask_app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "_ENGINE": None,
        "STORAGE_DIR": storage_dir, 
    })

    # 2. 直接定义 SQLite 兼容的建表语句 (不含 MySQL 特有语法)
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

    # 3. 执行建表
    with flask_app.app_context():
        engine = get_engine(flask_app)
        with engine.begin() as conn:
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
    """
    使用 fitz 生成一个合法的单页 PDF。
    这能彻底解决 'cannot save with zero pages' 问题。
    """
    pdf_path = tmp_path_factory.mktemp("pdfs") / "sample.pdf"
    doc = fitz.open()
    page = doc.new_page()  # 创建一个页面
    page.insert_text((50, 50), "Test PDF Content")
    doc.save(pdf_path)
    doc.close()
    return pdf_path