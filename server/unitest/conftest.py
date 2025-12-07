import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event

# conftest 在 server/unitest
UNITEST_DIR = Path(__file__).resolve().parent     # .../server/unitest
SERVER_DIR = UNITEST_DIR.parent                  # .../server
REPO_ROOT = SERVER_DIR.parent                    # 项目根目录

# 必须把 repo 根目录加进去，这样 `import server.src.xxx` 才能找到 server 包
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture()
def temp_storage(tmp_path):
    storage = tmp_path / "storage"
    storage.mkdir()
    return storage


@pytest.fixture()
def sqlite_engine():
    """
    server/src/server.py 路由里用了 UNHEX/HEX（MySQL函数）
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
    from server.src import server as server_mod  # 注意：在 server/src/server.py

    app = server_mod.create_app()
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = str(sqlite_engine.url)
    app.config["_ENGINE"] = sqlite_engine
    app.config["STORAGE_DIR"] = temp_storage

    client = app.test_client()
    return app, client


def make_pdf_bytes(text=b"hello"):
    return b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n" + text
