# server/test/test_watermark_api.py

import io
import uuid
import os
import sys
import pytest
from sqlalchemy.exc import IntegrityError, DBAPIError
from flask import g
from unittest.mock import MagicMock

# 把 tatou/server 加到 sys.path，保证可以 import src.server
THIS_DIR = os.path.dirname(__file__)
SERVER_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))
if SERVER_ROOT not in sys.path:
    sys.path.insert(0, SERVER_ROOT)

# from src.server import app

def _sample_pdf_bytes() -> bytes:
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"trailer\n<< >>\n"
        b"%%EOF\n"
    )

def _signup_and_login(client):
    """注册一个随机用户并登录，返回带 Authorization 的 headers"""
    email = f"wm-{uuid.uuid4().hex}@example.com"
    login = f"wm_{uuid.uuid4().hex[:8]}"
    password = "Passw0rd!"

    # 注册
    resp = client.post(
        "/api/create-user",
        json={"email": email, "login": login, "password": password},
    )
    # assert resp.status_code in (201, 409)
    assert resp.status_code == 201
    # 登录
    resp = client.post(
        "/api/login",
        json={"email": email, "password": password},
    )
    # assert resp.status_code == 200
    assert resp.status_code == 200
    token = resp.get_json()["token"]
    return {"Authorization": f"Bearer {token}"}



def test_create_and_read_watermark_roundtrip(client, auth_headers, sample_pdf_path):
    # 1. 上传干净文件
    r = client.post(
        "/api/upload-document",
        data={"file": (io.BytesIO(sample_pdf_path.read_bytes()), "clean.pdf")},
        headers=auth_headers,
        content_type="multipart/form-data",
    )
    doc_id = r.get_json()["id"]
    
    # 2. 让服务器创建水印版本
    secret = "server-secret"
    key = "server-key"
    r = client.post(
        f"/api/create-watermark/{doc_id}",
        headers=auth_headers,
        json={
            "method": "trailer-hmac",
            "intended_for": "test",
            "secret": secret,
            "key": key,
            "position": "eof"
        }
    )
    assert r.status_code == 201
    link = r.get_json()["link"]
    
    # 3. 下载生成的版本 (Get Version)
    r_down = client.get(f"/api/get-version/{link}")
    assert r_down.status_code == 200
    wm_file_bytes = r_down.data
    
    # 4. 将下载的文件作为新文档上传 (闭环测试)
    r_up = client.post(
        "/api/upload-document",
        data={"file": (io.BytesIO(wm_file_bytes), "downloaded_wm.pdf")},
        headers=auth_headers,
        content_type="multipart/form-data",
    )
    assert r_up.status_code == 201
    new_doc_id = r_up.get_json()["id"]
    
    # 5. 验证读取
    r_read = client.post(
        f"/api/read-watermark/{new_doc_id}",
        headers=auth_headers,
        json={
            "method": "trailer-hmac",
            "key": key,
            "position": "eof"
        }
    )
    assert r_read.status_code == 200
    assert r_read.get_json()["secret"] == secret



def test_create_watermark_duplicate_link_retrieves_existing_id(client, mocker, upload_document_id):
    """
    🎯 目标：测试当插入 Versions 表发生 IntegrityError (重复链接) 时，
    服务器是否尝试检索现有版本 ID 并返回 201 (L965-973)。
    """
    # 1. Mock 认证 (假设已登录并上传文档)
    logged_in_user_id = 1
    mocker.patch('server.src.server._serializer', return_value=MagicMock(loads=MagicMock(return_value={"uid": logged_in_user_id, "login": "testuser"})))
    
    # 2. 模拟水印成功
    mocker.patch('server.src.server.WMUtils.apply_watermark', return_value=b'watermarked_bytes')
    mocker.patch('server.src.server.WMUtils.get_method', return_value=MagicMock(name="test_method"))
    mocker.patch('server.src.server.WMUtils.is_watermarking_applicable', return_value=True)

    # 3. Mock 数据库引擎，准备抛出 IntegrityError
    mock_engine = MagicMock()
    mock_conn = MagicMock()
    
    # 模拟事务：第一次 execute 抛出 IntegrityError (重复)
    db_exception = IntegrityError("Duplicate entry", None, MagicMock(msg="Duplicate entry for uq_Versions_link"))
    
    # 模拟第二次 execute 成功检索到现有 ID
    MockExistingRow = MagicMock(id=123)
    
    # 模拟 conn.execute 的 side_effect：第一次失败，第二次成功
    mock_conn.execute.side_effect = [
        db_exception, # 第一次插入失败 (L965)
        MockExistingRow # 第二次查询成功 (L970)
    ]
    
    # 将 mock_conn 注入
    mock_engine.begin.return_value.__enter__.return_value = mock_conn
    mocker.patch('server.src.server.get_engine', return_value=mock_engine)
    mocker.patch('flask.g', user={"id": logged_in_user_id, "login": "testuser"}) # 确保 g.user 存在

    # 4. 运行请求
    with client.application.app_context():
        resp = client.post(
            f"/api/create-watermark/{upload_document_id}",
            json={
                "method": "test_method",
                "intended_for": "recipient_a",
                "secret": "my_secret",
                "key": "my_key",
            }
        )

    # 5. 断言
    assert resp.status_code == 201
    assert resp.get_json()["id"] == 123 # 断言返回了现有 ID
    
    # 断言数据库 execute 被调用了两次
    assert mock_conn.execute.call_count == 2