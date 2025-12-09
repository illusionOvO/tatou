import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event

# conftest 在 server/unitest
UNITEST_DIR = Path(__file__).resolve().parent     # .../server/unitest
SERVER_DIR = UNITEST_DIR.parent                  # .../server
REPO_ROOT = SERVER_DIR.parent                    # root

# add repo so `import server.src.xxx` can find server package
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# (New) Automate start TEST_MODE when testing
@pytest.fixture(scope="session", autouse=True)
def set_test_mode():
    os.environ["TEST_MODE"] = "1"
    yield



@pytest.fixture()
def temp_storage(tmp_path):
    storage = tmp_path / "storage"
    storage.mkdir()
    return storage


@pytest.fixture()
def sqlite_engine():
    """
    server/src/server.py 路由里用了 UNHEX/HEX (MySQL函数)
    sqlite 下注册等价函数防止 SQL 报错
    """
    eng = create_engine("sqlite+pysqlite:///:memory:", future=True)

    @event.listens_for(eng, "connect")
    def connect(dbapi_conn, _):
        def unhex(x):
            if x is None:
                return None
            return bytes.fromhex(x)

        def hex_(b):
            if b is None:
                return None
            if isinstance(b, memoryview):
                b = bytes(b)
            return b.hex().upper()

        dbapi_conn.create_function("UNHEX", 1, unhex)
        dbapi_conn.create_function("HEX", 1, hex_)

    # 维持你原先的建表逻辑，避免现有测试失效
    with eng.begin() as conn:
        conn.exec_driver_sql("""
        CREATE TABLE Users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            login TEXT UNIQUE NOT NULL,
            hpassword TEXT NOT NULL
        );
        """)
        conn.exec_driver_sql("""
        CREATE TABLE Documents(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            path TEXT NOT NULL,
            ownerid INTEGER NOT NULL,
            creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            sha256 BLOB,
            size INTEGER,
            FOREIGN KEY(ownerid) REFERENCES Users(id)
        );
        """)
        conn.exec_driver_sql("""
        CREATE TABLE Versions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            documentid INTEGER NOT NULL,
            link TEXT UNIQUE NOT NULL,
            intended_for TEXT,
            secret TEXT,
            method TEXT,
            position TEXT,
            path TEXT,
            FOREIGN KEY(documentid) REFERENCES Documents(id)
        );
        """)
    return eng


@pytest.fixture()
def app_client(sqlite_engine, temp_storage):
    from server.src import server as server_mod  

    app = server_mod.create_app()
    app.config["TESTING"] = True

    
    app.config["SQLALCHEMY_DATABASE_URI"] = str(sqlite_engine.url)
    app.config["_ENGINE"] = sqlite_engine
    app.config["STORAGE_DIR"] = temp_storage

    client = app.test_client()
    return app, client


#  Humanly add fixture in test
@pytest.fixture()
def seed_basic_user_doc(sqlite_engine):
    """
    插入一个用户(id=1)和一个文档(id=1)，方便 create/read-watermark 的分支测试用。
    不 autouse，避免影响你现有测试。
    """
    with sqlite_engine.begin() as conn:
        conn.exec_driver_sql("""
        INSERT INTO Users (email, login, hpassword)
        VALUES ('test@example.com', 'testuser', 'password');
        """)
        conn.exec_driver_sql("""
        INSERT INTO Documents (name, path, ownerid, sha256, size)
        VALUES ('TestDoc', '/tmp/test.pdf', 1, X'00', 123);
        """)
    # 返回固定 id，测试里直接用
    return {"user_id": 1, "document_id": 1}


def make_pdf_bytes(text=b"hello"):
    return b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n" + text
