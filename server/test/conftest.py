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

            # --- 【关键修复：SQL 清理】 ---
            sql_script = SQL_INIT_PATH.read_text()
            
            # --- 【增强 SQL 清理：移除所有 MySQL 专用 DDL 语法】 ---
            cleaned_sql = (
                sql_script
                # 移除所有会导致 SQLite 崩溃的 MySQL 语句/关键字
                .replace("USE `tatou`;", "")                  
                .replace("CREATE DATABASE", "-- CREATE DATABASE")
                .replace("DEFAULT CHARSET=utf8mb4", "")       
                .replace("CHARACTER SET utf8mb4", "")        
                .replace("CHARACTER SET latin1", "")
                .replace("ENGINE=InnoDB", "")
                .replace("COMMENT", "-- COMMENT")             
                .replace("UNSIGNED", "")                     
                .replace("ON UPDATE CURRENT_TIMESTAMP", "")   
                .replace("ON DELETE CASCADE", "")             
                .replace("DEFAULT NULL", "")                  
                
                # 2. 移除所有不兼容的日期函数和括号
                .replace("DEFAULT CURRENT_TIMESTAMP", "DEFAULT NULL") 
                .replace("DEFAULT (datetime('now'))", "DEFAULT NULL")
                .replace("NOW()", "NULL")
                .replace("(", "") 
                .replace(")", "") 
                
                # 3. 修正列类型和主键 (CRITICAL FIX)
                .replace("BIGINT NOT NULL", "INTEGER NOT NULL")   # 转换 BIGINT
                .replace("BIGINT", "INTEGER")                     # 转换 BIGINT
                .replace("PRIMARY id", "PRIMARY KEY")             # 修正 PRIMARY id 错误
                .replace("PRIMARY KEY", "PRIMARY KEY")            # 确保修正正确
                .replace("AUTO_INCREMENT", "") 
                
                # 4. 最终清理
                .replace("`", "") 
                .replace("KEY", "")                          
                .replace("utf8mb4_unicode_ci", "")
                .replace("utf8mb4_general_ci", "")
                .replace("utf8mb4_u", "")
                .replace("COLLATE", "")                      
                .replace("\\n", "\n")
            )
            # ----------------------------------------------------
            
            # 逐条执行 SQL
            for statement in cleaned_sql.split(';'):
                statement = statement.strip()
                if statement:
                    conn.execute(text(statement))
            
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
    """
    动态创建最小合法的 PDF 文件 (用于修复 FileNotFoundError)。
    使用 tmp_path_factory 确保文件在整个测试会话中都存在。
    """
    # 在一个安全的临时目录中创建文件
    fn = tmp_path_factory.mktemp("temp_pdf_data") / "sample.pdf"
    
    # 写入最小合法的 PDF 字节流 (包含 Catalog, Pages, Page 对象)
    fn.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" 
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>\nendobj\n"
        b"trailer\n<< /Root 1 0 R >>\n"
        b"startxref\n189\n%%EOF\n"
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