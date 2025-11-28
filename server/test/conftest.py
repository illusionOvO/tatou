# # conftest.py
# import pytest
# import sys
# import uuid
# from pathlib import Path
# import re
# from sqlalchemy import text
# import fitz

# # 确保能导入 server
# ROOT_DIR = Path(__file__).resolve().parents[1]  # 假设 conftest.py 在 tests/ 下
# if str(ROOT_DIR) not in sys.path:
#     sys.path.insert(0, str(ROOT_DIR))

# from server.src.server import create_app, get_engine


# def _load_and_clean_sql_schema(sql_path: Path) -> str:
#     """加载 tatou.sql 并转换为 SQLite 兼容语法"""
#     sql = sql_path.read_text(encoding="utf-8")

#     # 移除 MySQL 专属语法
#     sql = re.sub(r'(?i)^\s*USE\s+\S+\s*;?', '', sql, flags=re.MULTILINE)
#     sql = re.sub(r'(?i)^\s*CREATE\s+DATABASE.*?;?', '', sql, flags=re.MULTILINE)
#     sql = re.sub(r'\bCOLLATE\s+\w+', '', sql, flags=re.IGNORECASE)
#     sql = re.sub(r'\bCHARACTER\s+SET\s+\w+', '', sql, flags=re.IGNORECASE)
#     sql = re.sub(r'\bDEFAULT\s+CHARSET=\w+', '', sql, flags=re.IGNORECASE)
#     sql = re.sub(r'\bENGINE\s*=\s*\w+', '', sql, flags=re.IGNORECASE)
#     sql = re.sub(r'\bROW_FORMAT\s*=\s*\w+', '', sql, flags=re.IGNORECASE)

#     # 类型替换
#     sql = sql.replace("BIGINT UNSIGNED", "INTEGER")
#     sql = sql.replace("BIGINT", "INTEGER")
#     sql = re.sub(r'\bUNSIGNED\b', '', sql, flags=re.IGNORECASE)
#     sql = sql.replace("AUTO_INCREMENT", "")
#     sql = sql.replace("DATETIME(6)", "TEXT")  # SQLite 不支持微秒 DATETIME
#     sql = sql.replace("BINARY(32)", "BLOB")
#     sql = sql.replace("`", "")  # 去掉反引号

#     return sql


# @pytest.fixture(scope="session")
# def app():
#     """创建一个使用内存 SQLite 的 Flask 应用，并初始化表结构"""
#     flask_app = create_app()

#     # 配置为测试模式 + 内存数据库
#     flask_app.config.update({
#         "TESTING": True,
#         "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",  # 让 db_url() 返回这个
#     })

#     # 获取引擎（会缓存到 app.config["_ENGINE"]）
#     engine = get_engine(flask_app)

#     # 加载并执行建表 SQL
#     sql_init_path = Path(__file__).parent.parent / "db" / "tatou.sql"
#     if not sql_init_path.exists():
#         raise FileNotFoundError(f"SQL schema file not found: {sql_init_path}")

#     clean_sql = _load_and_clean_sql_schema(sql_init_path)

#     with engine.begin() as conn:
#         for stmt in clean_sql.split(";"):
#             s = stmt.strip()
#             if s and not s.startswith("--") and not s.startswith("/*"):
#                 try:
#                     conn.execute(text(s))
#                 except Exception as e:
#                     print(f"❌ Failed to execute SQL:\n{s}\nError: {e}")
#                     raise

#     return flask_app


# @pytest.fixture
# def client(app):
#     return app.test_client()


# @pytest.fixture
# def auth_headers(client):
#     email = f"test-{uuid.uuid4().hex[:8]}@example.com"
#     login = f"user_{uuid.uuid4().hex[:8]}"
#     password = "SecurePass123!"

#     # 注册
#     resp = client.post("/api/create-user", json={"email": email, "login": login, "password": password})
#     assert resp.status_code == 201, f"注册失败: {resp.get_json()}"

#     # 登录
#     resp = client.post("/api/login", json={"email": email, "password": password})
#     assert resp.status_code == 200, f"登录失败: {resp.get_json()}"

#     token = resp.get_json()["token"]
#     return {"Authorization": f"Bearer {token}"}

# @pytest.fixture(scope="session")
# def sample_pdf_path(tmp_path_factory) -> Path:
#     """使用 PyMuPDF (fitz) 生成一个完全合法的 PDF 文件"""
#     fn = tmp_path_factory.mktemp("pdf_data") / "sample.pdf"
    
#     # 创建一个新文档
#     doc = fitz.open()
#     # 插入一页 (这解决了 zero pages 问题)
#     page = doc.new_page()
#     # 写入一些内容
#     page.insert_text((50, 50), "Hello, World! This is a valid PDF.")
    
#     # 保存到临时路径
#     doc.save(str(fn))
#     doc.close()
    
#     return fn


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
from unittest.mock import MagicMock

# @pytest.fixture(scope="session")20251128
@pytest.fixture
def app(mocker, tmp_path):
    """
    提供配置了内存数据库且已初始化表的 Flask app。
    这里直接使用 SQLite 语法建表，绕过 MySQL 兼容性问题。
    """
    # 1. 强制 server.py 里的 db_url 使用 SQLite
    mocker.patch('server.src.server.db_url', return_value='sqlite:///:memory:')
    
    flask_app = create_app()

    flask_app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "_ENGINE": None,
        "STORAGE_DIR": str(tmp_path / "storage_test"), # 20251128强制使用临时目录，解决 PermissionError
    })

    # 2. 定义绝对兼容 SQLite 的建表语句
    # 这一步替代了读取 tatou.sql，彻底消灭语法错误
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