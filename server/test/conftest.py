import pytest
import sys
import uuid
from pathlib import Path
from sqlalchemy import text, create_engine, event
from sqlalchemy.pool import StaticPool
import fitz  # PyMuPDF
import binascii
from unittest.mock import patch

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from server.src.server import create_app

def _sqlite_unhex(hex_str):
    if hex_str is None: return None
    try: return binascii.unhexlify(hex_str)
    except Exception: return None

@pytest.fixture(scope="function")
def app(tmp_path):
    # 1. 创建内存数据库
    test_engine = create_engine("sqlite:///:memory:", 
                                connect_args={"check_same_thread": False}, 
                                poolclass=StaticPool)
    
    @event.listens_for(test_engine, "connect")
    def register_custom_functions(dbapi_connection, connection_record):
        dbapi_connection.create_function("UNHEX", 1, _sqlite_unhex)

    # 2. 劫持 server.py 的数据库连接
    with patch('server.src.server.db_url', return_value='sqlite:///:memory:'), \
         patch('server.src.server.get_engine', return_value=test_engine), \
         patch('server.src.rmap_routes._get_engine', return_value=test_engine):
        
        flask_app = create_app()
        storage_dir = tmp_path / "storage_test"
        storage_dir.mkdir(exist_ok=True)
        
        flask_app.config.update({
            "TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "_ENGINE": test_engine, "STORAGE_DIR": storage_dir,
        })

        # 3. 硬编码建表 (终极修复版)
        sqlite_schema = """
        CREATE TABLE Users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL, hpassword TEXT NOT NULL, login TEXT NOT NULL,
            UNIQUE(email), UNIQUE(login)
        );
        CREATE TABLE Documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL, path TEXT NOT NULL, ownerid INTEGER NOT NULL,
            sha256 BLOB, size INTEGER, creation TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(path), FOREIGN KEY(ownerid) REFERENCES Users(id) ON DELETE CASCADE
        );
        CREATE TABLE Versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            documentid INTEGER NOT NULL, link TEXT NOT NULL, intended_for TEXT,
            secret TEXT NOT NULL, method TEXT NOT NULL, position TEXT, path TEXT NOT NULL,
            UNIQUE(link), FOREIGN KEY(documentid) REFERENCES Documents(id) ON DELETE CASCADE
        );
        """
        with flask_app.app_context():
            with test_engine.begin() as conn:
                for s in sqlite_schema.strip().split(';'):
                    if s.strip(): conn.execute(text(s))
        yield flask_app

@pytest.fixture
def client(app): return app.test_client()

@pytest.fixture
def auth_headers(client):
    email = f"auto-{uuid.uuid4().hex[:8]}@example.com"
    client.post("/api/create-user", json={"email": email, "login": f"u_{uuid.uuid4().hex[:8]}", "password": "p"})
    token = client.post("/api/login", json={"email": email, "password": "p"}).get_json()["token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture(scope="session")
def sample_pdf_path(tmp_path_factory):
    # 这里的 PDF 是真的！包含页面！
    pdf_path = tmp_path_factory.mktemp("pdfs") / "sample.pdf"
    doc = fitz.open()
    doc.new_page().insert_text((50, 50), "Valid PDF")
    doc.save(str(pdf_path))
    doc.close()
    return pdf_path