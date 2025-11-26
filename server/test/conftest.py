import pytest
import sys
import uuid
from pathlib import Path
from sqlalchemy import text
import os
import re

# 确保项目根目录在 sys.path 中
ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# 导入 Flask app 和数据库引擎
from server.src.server import create_app, get_engine


@pytest.fixture(scope="session")
def app():
    """提供配置了内存数据库且已初始化表的 Flask app"""
    # 创建 Flask 应用实例
    flask_app = create_app()
    
    # 强制使用 SQLite 内存数据库
    flask_app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "_ENGINE": None
    })

    # 构造 SQL 文件路径
    SQL_INIT_PATH = ROOT_DIR / "db" / "tatou.sql"
    if not SQL_INIT_PATH.exists():
        raise FileNotFoundError(f"Missing SQL initialization file at: {SQL_INIT_PATH}")

    # 读取并彻底清理 SQL 脚本
    sql_script = SQL_INIT_PATH.read_text()

    # === 关键：移除所有 MySQL/MariaDB 专属语法 ===
    # 移除 USE 和 CREATE DATABASE
    sql_script = re.sub(r'(?i)^\s*USE\s+\S+\s*;?', '', sql_script, flags=re.MULTILINE)
    sql_script = re.sub(r'(?i)^\s*CREATE\s+DATABASE.*?;?', '', sql_script, flags=re.MULTILINE)

    # 移除字段级 MySQL 属性
    sql_script = re.sub(r'\bCOLLATE\s+\w+', '', sql_script, flags=re.IGNORECASE)
    sql_script = re.sub(r'\bCHARACTER\s+SET\s+\w+', '', sql_script, flags=re.IGNORECASE)
    sql_script = re.sub(r'\bDEFAULT\s+CHARSET=\w+', '', sql_script, flags=re.IGNORECASE)
    sql_script = re.sub(r'\bENGINE\s*=\s*\w+', '', sql_script, flags=re.IGNORECASE)
    sql_script = re.sub(r'\bROW_FORMAT\s*=\s*\w+', '', sql_script, flags=re.IGNORECASE)

    # 替换数据类型和关键字
    sql_script = sql_script.replace("BIGINT UNSIGNED", "INTEGER")
    sql_script = sql_script.replace("BIGINT", "INTEGER")
    sql_script = sql_script.replace("UNSIGNED", "")
    sql_script = sql_script.replace("AUTO_INCREMENT", "")
    sql_script = sql_script.replace("DATETIME(6)", "TEXT")      # SQLite 用 TEXT 存时间
    sql_script = sql_script.replace("BINARY(32)", "BLOB")       # SHA256 二进制
    sql_script = sql_script.replace("`", "")                    # 去掉反引号
    sql_script = sql_script.replace("\\n", "\n")

    # 执行清理后的 SQL
    with flask_app.app_context():
        engine = get_engine(flask_app)
        with engine.begin() as conn:
            for statement in sql_script.split(';'):
                stmt = statement.strip()
                if stmt and not stmt.startswith("--") and not stmt.startswith("/*"):
                    try:
                        conn.execute(text(stmt))
                    except Exception as e:
                        print(f"\n❌ Failed to execute SQL:\n{stmt}\nError: {e}\n")
                        raise

    return flask_app


@pytest.fixture
def client(app):
    """提供 Flask 测试客户端"""
    return app.test_client()


@pytest.fixture
def auth_headers(client):
    """自动注册并登录一个用户，返回认证 Headers"""
    email = f"auto-{uuid.uuid4().hex[:8]}@example.com"
    password = "Passw0rd!"

    # 注册
    client.post("/api/create-user", json={
        "email": email,
        "login": f"u_{uuid.uuid4().hex[:8]}",
        "password": password
    })

    # 登录
    resp = client.post("/api/login", json={"email": email, "password": password})
    if resp.status_code != 200:
        return {}
    token = resp.get_json()["token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def sample_pdf_path(tmp_path_factory) -> Path:
    """生成一个有效的测试 PDF 文件"""
    fn = tmp_path_factory.mktemp("pdfs") / "sample.pdf"
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(str(fn))
    c.drawString(100, 750, "Test PDF for Tatou")
    c.save()
    return fn


@pytest.fixture
def unique_user_data():
    return {
        "email": f"test-{uuid.uuid4().hex}@example.com",
        "login": f"test_login_{uuid.uuid4().hex[:8]}",
        "password": "SecurePassword123!"
    }