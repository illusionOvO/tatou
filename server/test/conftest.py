# conftest.py
import pytest
import sys
import uuid
from pathlib import Path
import re
from sqlalchemy import text

# 确保能导入 server
ROOT_DIR = Path(__file__).resolve().parents[1]  # 假设 conftest.py 在 tests/ 下
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from server import create_app, get_engine


def _load_and_clean_sql_schema(sql_path: Path) -> str:
    """加载 tatou.sql 并转换为 SQLite 兼容语法"""
    sql = sql_path.read_text(encoding="utf-8")

    # 移除 MySQL 专属语法
    sql = re.sub(r'(?i)^\s*USE\s+\S+\s*;?', '', sql, flags=re.MULTILINE)
    sql = re.sub(r'(?i)^\s*CREATE\s+DATABASE.*?;?', '', sql, flags=re.MULTILINE)
    sql = re.sub(r'\bCOLLATE\s+\w+', '', sql, flags=re.IGNORECASE)
    sql = re.sub(r'\bCHARACTER\s+SET\s+\w+', '', sql, flags=re.IGNORECASE)
    sql = re.sub(r'\bDEFAULT\s+CHARSET=\w+', '', sql, flags=re.IGNORECASE)
    sql = re.sub(r'\bENGINE\s*=\s*\w+', '', sql, flags=re.IGNORECASE)
    sql = re.sub(r'\bROW_FORMAT\s*=\s*\w+', '', sql, flags=re.IGNORECASE)

    # 类型替换
    sql = sql.replace("BIGINT UNSIGNED", "INTEGER")
    sql = sql.replace("BIGINT", "INTEGER")
    sql = re.sub(r'\bUNSIGNED\b', '', sql, flags=re.IGNORECASE)
    sql = sql.replace("AUTO_INCREMENT", "")
    sql = sql.replace("DATETIME(6)", "TEXT")  # SQLite 不支持微秒 DATETIME
    sql = sql.replace("BINARY(32)", "BLOB")
    sql = sql.replace("`", "")  # 去掉反引号

    return sql


@pytest.fixture(scope="session")
def app():
    """创建一个使用内存 SQLite 的 Flask 应用，并初始化表结构"""
    flask_app = create_app()

    # 配置为测试模式 + 内存数据库
    flask_app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",  # 让 db_url() 返回这个
    })

    # 获取引擎（会缓存到 app.config["_ENGINE"]）
    engine = get_engine(flask_app)

    # 加载并执行建表 SQL
    sql_init_path = Path(__file__).parent.parent / "db" / "tatou.sql"
    if not sql_init_path.exists():
        raise FileNotFoundError(f"SQL schema file not found: {sql_init_path}")

    clean_sql = _load_and_clean_sql_schema(sql_init_path)

    with engine.begin() as conn:
        for stmt in clean_sql.split(";"):
            s = stmt.strip()
            if s and not s.startswith("--") and not s.startswith("/*"):
                try:
                    conn.execute(text(s))
                except Exception as e:
                    print(f"❌ Failed to execute SQL:\n{s}\nError: {e}")
                    raise

    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_headers(client):
    email = f"test-{uuid.uuid4().hex[:8]}@example.com"
    login = f"user_{uuid.uuid4().hex[:8]}"
    password = "SecurePass123!"

    # 注册
    resp = client.post("/api/create-user", json={"email": email, "login": login, "password": password})
    assert resp.status_code == 201, f"注册失败: {resp.get_json()}"

    # 登录
    resp = client.post("/api/login", json={"email": email, "password": password})
    assert resp.status_code == 200, f"登录失败: {resp.get_json()}"

    token = resp.get_json()["token"]
    return {"Authorization": f"Bearer {token}"}