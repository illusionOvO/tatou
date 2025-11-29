# server/test/test_create_user.py

import pytest
import uuid
import json
from unittest.mock import MagicMock
from sqlalchemy.exc import IntegrityError, DBAPIError # 使用 DBAPIError 模拟连接失败

# 假设您的服务器模块名为 server.py，它位于 server/src/
# 并且 get_engine, app 已经被提升到模块级。
# from server.src.server import app as server_app 

import sys
print("Modules:", list(sys.modules.keys()))
print("server.src.server path:", sys.modules.get('server.src.server'))


@pytest.fixture
def unique_user_data():
    """生成一组唯一的、有效的用户数据"""
    email = f"test-{uuid.uuid4().hex}@example.com"
    login = f"test_login_{uuid.uuid4().hex[:8]}"
    password = "SecurePassword123!"
    return {"email": email, "login": login, "password": password}


# ----------------------------------------------------------------------
# 1. 成功注册 (201)
# ----------------------------------------------------------------------

def test_create_user_success(client, unique_user_data):
    """
    测试成功注册新用户，覆盖 201 成功分支。
    """
    resp = client.post(
        "/api/create-user",
        json=unique_user_data,
    )
    
    assert resp.status_code == 201
    data = resp.get_json()
    assert "id" in data
    assert data["email"] == unique_user_data["email"]


# ----------------------------------------------------------------------
# 2. 重复注册 (409)
# ----------------------------------------------------------------------

def test_create_user_duplicate_email_or_login(client, unique_user_data):
    """
    测试使用已存在的 email/login 注册，覆盖 except IntegrityError (409) 分支。
    """
    # 1. 第一次注册（成功）
    client.post("/api/create-user", json=unique_user_data)
    
    # 2. 第二次注册，使用相同的 email
    resp_dup = client.post(
        "/api/create-user",
        # 使用相同的 email，但新的 login 确保触发 email 的唯一约束
        json={
            "email": unique_user_data["email"],
            "login": f"new_login_{uuid.uuid4().hex[:8]}", 
            "password": unique_user_data["password"]
        },
    )
    
    # 3. 断言：检查状态码是否是 409 Conflict
    assert resp_dup.status_code == 409
    data = resp_dup.get_json()
    assert "email or login already exists" in data.get("error", "")


# ----------------------------------------------------------------------
# 3. 服务器错误 (503) - 核心 Mocking 修复点
# ----------------------------------------------------------------------


def test_create_user_server_error_final(client, unique_user_data, mocker):
    """
    通过 Mocking create_engine 并清除缓存，强制 get_engine 在运行时抛出异常。
    覆盖 except Exception (503) 分支。
    """
    
    # 1. 模拟 create_engine 失败：让它在被调用时抛出 DBAPIError (它继承自 Exception)
    #    这样 get_engine 就会失败，create_user 路由会捕获到 Exception。
    mocker.patch(
        'server.src.server.create_engine', 
        side_effect=DBAPIError("Simulated connection failure (InternalError)", {}, {})
    )
    
    # 2. 清理 app 缓存的 engine
    #    这是关键：确保 get_engine 必须调用 create_engine (即 Mock) 而不是使用缓存
    original_engine = client.application.config.get("_ENGINE")
    client.application.config["_ENGINE"] = None
    
    # 3. 调用 create-user API
    resp = client.post(
        "/api/create-user",
        json=unique_user_data,
    )

    # 4. 恢复 app 缓存 (重要，防止影响其他测试)
    client.application.config["_ENGINE"] = original_engine

    # 5. 断言：状态码必须是 503 Service Unavailable
    assert resp.status_code == 503 
    
    # 6. 断言：检查返回的错误信息
    data = resp.get_json()
    assert "database error" in data.get("error", "")
    assert "InternalError" in data.get("error", "")
    

# ----------------------------------------------------------------------
# 4. 必填参数缺失 (400)
# ----------------------------------------------------------------------

def test_create_user_missing_fields(client):
    """
    测试缺少 email, login 或 password 时返回 400 Bad Request。
    """
    # 缺少 email
    resp1 = client.post(
        "/api/create-user",
        json={"login": "test", "password": "pass"},
    )
    assert resp1.status_code == 400
    assert "email, login, and password are required" in resp1.get_json()["error"]
    
    # 缺少 password
    resp2 = client.post(
        "/api/create-user",
        json={"email": "a@b.com", "login": "test"},
    )
    assert resp2.status_code == 400