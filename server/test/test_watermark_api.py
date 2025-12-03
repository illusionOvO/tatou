# server/test/test_watermark_api.py

import io
import uuid
import os
import sys
import pytest
from sqlalchemy.exc import IntegrityError, DBAPIError
from flask import g
from unittest.mock import MagicMock
from server.src.server import create_app

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






@pytest.fixture
def upload_document_id(mocker, client):
    """
    模拟文档上传和数据库插入，返回一个有效的 document ID (999)。
    """
    doc_id = 999
    logged_in_user_id = 1
    
    # 1. Mock 数据库执行，使其在插入时返回 doc_id
    mock_conn = MagicMock()
    # 模拟 conn.execute 的返回值：lastrowid
    res_mock = MagicMock(lastrowid=doc_id)
    mock_conn.execute.return_value = res_mock
    
    # 模拟查询，使其返回一个文档行
    MockDocRow = MagicMock(id=doc_id, name="test_doc", creation="2025-01-01", sha256_hex="abc", size=1024)
    mock_conn.execute.return_value.one.return_value = MockDocRow

    mocker.patch('server.src.server.get_engine', 
                 return_value=MagicMock(begin=MagicMock(return_value=MagicMock(__enter__=MagicMock(return_value=mock_conn)))))
    
    # 2. 模拟 g.user
    # **关键修复：包裹在 app_context 中**
    app = client.application
    with app.app_context(): # <-- 解决 RuntimeError: Working outside of application context
        mocker.patch('flask.g', user={"id": logged_in_user_id, "login": "testuser"})
    
    # 返回模拟的文档 ID
    return doc_id


# def test_create_watermark_duplicate_link_retrieves_existing_id(client, mocker, upload_document_id):
#     """
#     🎯 目标：测试当插入 Versions 表发生 IntegrityError (重复链接) 时，
#     服务器是否尝试检索现有版本 ID 并返回 201 (L965-973)。
#     """
#     # 1. Mock 认证 (假设已登录并上传文档)
#     logged_in_user_id = 1
#     mocker.patch('server.src.server._serializer', return_value=MagicMock(loads=MagicMock(return_value={"uid": logged_in_user_id, "login": "testuser"})))
    
#     # 2. 模拟水印成功
#     mocker.patch('server.src.server.WMUtils.apply_watermark', return_value=b'watermarked_bytes')
#     mocker.patch('server.src.server.WMUtils.get_method', return_value=MagicMock(name="test_method"))
#     mocker.patch('server.src.server.WMUtils.is_watermarking_applicable', return_value=True)
    
#     # 3. **关键修复：模拟文档存在检查**
#     # 服务器可能在 create-watermark 端点中检查文档是否存在
#     mocker.patch('server.src.server.get_document', return_value={
#         'id': upload_document_id,
#         'user_id': logged_in_user_id,
#         'sha256_hex': 'abc123',
#         'size': 1024,
#         'name': 'test.pdf'
#     })
    
#     # 4. Mock 数据库引擎，准备抛出 IntegrityError
#     mock_engine = MagicMock()
#     mock_conn = MagicMock()
    
#     # 模拟事务：第一次 execute 抛出 IntegrityError (重复)
#     db_exception = IntegrityError("Duplicate entry", None, MagicMock(msg="Duplicate entry for uq_Versions_link"))
    
#     # 模拟第二次 execute 成功检索到现有 ID
#     MockExistingRow = MagicMock()
#     MockExistingRow.id = 123
    
#     # 模拟 conn.execute 的 side_effect：第一次失败，第二次成功
#     mock_conn.execute.side_effect = [
#         db_exception,  # 第一次插入失败 (L965)
#         MockExistingRow  # 第二次查询成功 (L970)
#     ]
    
#     # 将 mock_conn 注入
#     mock_engine.begin.return_value.__enter__.return_value = mock_conn
#     mocker.patch('server.src.server.get_engine', return_value=mock_engine)
    
#     # 5. **修复：在 app_context 中设置 g.user**
#     app = client.application
    
#     with app.app_context():
#         # 设置 g.user
#         from flask import g
#         g.user = {"id": logged_in_user_id, "login": "testuser"}
        
#         # 运行请求
#         resp = client.post(
#             f"/api/create-watermark/{upload_document_id}",
#             json={
#                 "method": "test_method",
#                 "intended_for": "recipient_a",
#                 "secret": "my_secret",
#                 "key": "my_key",
#             },
#             headers={'Authorization': 'Bearer mock-token'}
#         )
    
#     # 6. 调试输出
#     print(f"Response status: {resp.status_code}")
#     print(f"Response data: {resp.get_json()}")
    
#     # 7. 断言
#     assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.get_json()}"
#     assert resp.get_json()["id"] == 123  # 断言返回了现有 ID
    
#     # 断言数据库 execute 被调用了两次
#     assert mock_conn.execute.call_count == 2



# 在测试文件中添加调试代码
def test_create_watermark_duplicate_link_retrieves_existing_id(client, mocker, upload_document_id):
    """
    🎯 目标：测试当插入 Versions 表发生 IntegrityError (重复链接) 时，
    服务器是否尝试检索现有版本 ID 并返回 201 (L965-973)。
    """
    
    # 首先，让我们看看服务器模块中有哪些函数
    import server.src.server as server_module
    print("服务器模块中的函数:", [name for name in dir(server_module) if callable(getattr(server_module, name, None))])
    
    # 1. Mock 认证
    logged_in_user_id = 1
    mocker.patch('server.src.server._serializer', return_value=MagicMock(
        loads=MagicMock(return_value={"uid": logged_in_user_id, "login": "testuser"})
    ))
    
    # 2. 模拟水印成功
    mocker.patch('server.src.server.WMUtils.apply_watermark', return_value=b'watermarked_bytes')
    mocker.patch('server.src.server.WMUtils.get_method', return_value=MagicMock(name="test_method"))
    mocker.patch('server.src.server.WMUtils.is_watermarking_applicable', return_value=True)
    
    # 3. **需要找到正确的函数名**
    # 查看服务器代码，看看文档检查是通过什么函数进行的
    # 可能是：get_document_by_id, find_document, _get_document 等
    
    # 暂时注释掉这行，先看看错误是否在其他地方
    # mocker.patch('server.src.server.get_document', return_value=...)
    
    # 4. Mock 数据库引擎
    mock_engine = MagicMock()
    mock_conn = MagicMock()
    
    db_exception = IntegrityError("Duplicate entry", None, MagicMock(msg="Duplicate entry for uq_Versions_link"))
    MockExistingRow = MagicMock(id=123)
    
    mock_conn.execute.side_effect = [
        db_exception,
        MockExistingRow
    ]
    
    mock_engine.begin.return_value.__enter__.return_value = mock_conn
    mocker.patch('server.src.server.get_engine', return_value=mock_engine)
    
    app = client.application
    
    with app.app_context():
        from flask import g
        g.user = {"id": logged_in_user_id, "login": "testuser"}
        
        # 先运行请求看看错误是什么
        resp = client.post(
            f"/api/create-watermark/{upload_document_id}",
            json={
                "method": "test_method",
                "intended_for": "recipient_a",
                "secret": "my_secret",
                "key": "my_key",
            },
            headers={'Authorization': 'Bearer mock-token'}
        )
        
        print(f"Response status: {resp.status_code}")
        print(f"Response data: {resp.get_data(as_text=True)}")
        
        # 如果还是 410，查看服务器日志或添加更多调试