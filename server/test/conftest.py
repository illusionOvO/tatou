import pytest
import sys
import uuid
from pathlib import Path
from sqlalchemy import text # 需要导入 text 来执行原始 SQL 语句
import os

# 确保项目根目录在 sys.path 中，以便正确导入 server.src
ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# 从 server.py 中导入必要的函数
# 注意：你的 server.py 中 create_app 和 get_engine 都是全局函数
from server.src.server import create_app, get_engine

# 使用 create_app 创建一个 Flask 实例，用于全局引用
flask_app = create_app()

@pytest.fixture(scope="session")
def app():
    """提供配置了内存数据库且已初始化表的 Flask app"""
    # 1. 强制使用内存数据库，防止连接外部 MySQL 失败
    flask_app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",  # 内存数据库
        "_ENGINE": None # 每次重置引擎
    })
    
    # 2. 构造 SQL 文件路径 (tatou/db/tatou.sql)
    SQL_INIT_PATH = ROOT_DIR / "db" / "tatou.sql"
    
    # 3. 初始化数据库表结构
    if not SQL_INIT_PATH.exists():
         # 如果找不到 db/tatou.sql，测试就无法运行
         raise FileNotFoundError(f"Missing SQL initialization file at: {SQL_INIT_PATH}")

    with flask_app.app_context():
        # 调用 get_engine(app) 获取数据库引擎
        engine = get_engine(flask_app)
        with engine.begin() as conn:  # 使用 begin 开启事务并提交
            # 读取并执行 SQL 初始化文件，创建 Users, Documents, Versions 等表
            conn.execute(text(SQL_INIT_PATH.read_text()))
            
    return flask_app

@pytest.fixture
def client(app):
    """提供 Flask 测试客户端"""
    return app.test_client()

# --- 鉴权夹具 ---

@pytest.fixture
def auth_headers(client):
    """自动注册并登录一个用户，返回认证 Headers"""
    email = f"auto-{uuid.uuid4().hex[:8]}@example.com"
    password = "Passw0rd!"
    # 注册
    client.post("/api/create-user", json={
        "email": email, "login": f"u_{uuid.uuid4().hex[:8]}", "password": password
    })
    # 登录
    resp = client.post("/api/login", json={"email": email, "password": password})
    if resp.status_code != 200:
        return {}
    token = resp.get_json()["token"]
    return {"Authorization": f"Bearer {token}"}

# --- 文件夹具 ---

@pytest.fixture(scope="session")
def sample_pdf_path(tmp_path_factory) -> Path:
    """动态创建最小合法 PDF 文件 (用于修复 FileNotFoundError)"""
    fn = tmp_path_factory.mktemp("data") / "sample.pdf"
    fn.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"trailer\n<< >>\n"
        b"%%EOF\n"
    )
    return fn

# --- 其他夹具 (如 unique_user_data) ---
@pytest.fixture
def unique_user_data():
    return {
        "email": f"test-{uuid.uuid4().hex}@example.com",
        "login": f"test_login_{uuid.uuid4().hex[:8]}",
        "password": "SecurePassword123!"
    }