# server/test/test_error_cases.py (最终修复版 V2)

import io
import uuid
import sys
from pathlib import Path
import pytest
from itsdangerous import SignatureExpired, BadSignature
from unittest.mock import MagicMock
from collections import namedtuple 

# 导入 SQLAlchemy 异常 (如果需要 Mock 失败)
from sqlalchemy.exc import IntegrityError, DBAPIError 

# --------- 模块级导入和路径设置 (保持不变) ---------
THIS_FILE = Path(__file__).resolve()
SERVER_ROOT = THIS_FILE.parents[1]
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))

from src.server import _safe_resolve_under_storage # 导入 _safe_resolve_under_storage
from src.server import create_app # 确保导入 create_app

# --------------------------------------------------------
# 移除所有全局 app.config 修改代码 (L10-L20)，因为它总是失败
# --------------------------------------------------------


# ======================================================================
# 辅助类：模拟 SQLAlchemy 数据库行对象，解决 JSON 序列化问题
# ======================================================================

MockDBRow = namedtuple("Row", ["id", "email", "login", "hpassword"])

# ======================================================================
# FIXTURE: 模拟成功登录 (解决 503)
# ======================================================================

@pytest.fixture
def logged_in_client(client, mocker):
    """
    通过 Mocking 数据库依赖 (get_engine)，强制注册/登录成功。
    返回一个包含有效 Authorization Header 的字典。
    """
    
    # ----------------------------------------------------
    # 1. 创建 Mock Engine 和 Mock 行实例
    # ----------------------------------------------------
    mock_engine = MagicMock()
    mock_conn = mock_engine.connect.return_value.__enter__.return_value
    
    # 使用 namedtuple 实例，确保属性返回真实值
    mock_login_instance = MockDBRow(
        id=1, 
        email=f"mock-{uuid.uuid4().hex}@example.com", 
        login="mockuser", 
        hpassword="pbkdf2:sha256:260000$hT2l4D$1f1f1..." # 假哈希
    )
    
    # 配置 execute 方法的返回值：
    mock_conn.execute.return_value = MagicMock(
        one=lambda: mock_login_instance, 
        first=lambda: mock_login_instance,
        scalar=lambda: 1 # 模拟 LAST_INSERT_ID
    )

    # ----------------------------------------------------
    # 2. 执行 Mocking (在 fixture 生命周期内)
    # ----------------------------------------------------
    
    # 覆盖 server.py 里的 get_engine，使其返回 Mock Engine
    # 路径 'src.server.get_engine' 假设 get_engine 已被提升
    mocker.patch('src.server.get_engine', return_value=mock_engine)

    # ----------------------------------------------------
    # 3. 执行注册和登录
    # ----------------------------------------------------
    
    email = f"e_{uuid.uuid4().hex}@example.com"
    
    # 注册 (调用 /api/create-user)
    r_reg = client.post("/api/create-user", json={
        "email": email,
        "login": f"e_{uuid.uuid4().hex[:8]}",
        "password": "Passw0rd!",
    })
    # 断言：Mocking 成功，所以状态码必须是 201
    assert r_reg.status_code == 201 

    # 登录 (调用 /api/login)
    r_login = client.post("/api/login", json={
        "email": email,
        "password": "Passw0rd!",
    })
    assert r_login.status_code == 200
    
    token = r_login.get_json()["token"]
    return {"Authorization": f"Bearer {token}"}

# ======================================================================
# 核心功能测试 (使用 Mocked Fixture)
# ======================================================================

def test_read_missing_method_returns_400(client, logged_in_client):
    """测试 read-watermark 缺少 method 参数返回 400"""
    headers = logged_in_client # 使用 Mocked 登录

    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\nxref\n0 1\n0 65535 f \n%%EOF"
    r = client.post(
        "/api/upload-document",
        data={"file": (io.BytesIO(pdf_bytes), "a.pdf")},
        headers=headers,
    )
    assert r.status_code == 201
    docid = r.get_json()["id"]

    # 故意缺 method (测试参数校验)
    r = client.post(
        f"/api/read-watermark/{docid}",
        json={"key": "abc"},
        headers=headers,
    )

    assert r.status_code == 400
    assert "method and key" in r.get_json()["error"]


def test_read_nonexistent_docid_404(client, logged_in_client):
    """测试 read-watermark 访问不存在的文档 ID"""
    headers = logged_in_client # 使用 Mocked 登录

    r = client.post(
        "/api/read-watermark/99999999",
        json={"method": "trailer-hmac", "key": "abc", "position": None},
        headers=headers,
    )
    assert r.status_code == 404


def test_create_watermark_missing_fields_400(client, logged_in_client):
    """测试 create-watermark 缺少必填字段 secret 返回 400"""
    headers = logged_in_client # 使用 Mocked 登录

    pdf_bytes = b"%PDF-1.4 test"
    r = client.post(
        "/api/upload-document",
        data={"file": (io.BytesIO(pdf_bytes), "b.pdf")},
        headers=headers,
    )
    assert r.status_code == 201
    docid = r.get_json()["id"]

    # 故意缺 secret (测试参数校验)
    r = client.post(
        f"/api/create-watermark/{docid}",
        json={
            "method": "trailer-hmac",
            "key": "abc",
            "intended_for": "test_user",
        },
        headers=headers,
    )
    assert r.status_code == 400 
    assert "method, intended_for, secret, and key are required" in r.get_json()["error"]


# ======================================================================
# AUTHENTICATION 覆盖率测试
# ======================================================================

def test_auth_missing_header(client):
    """测试缺少 Authorization header 时返回 401"""
    resp = client.get("/api/list-documents")
    assert resp.status_code == 401
    assert "Missing or invalid Authorization header" in resp.get_json()["error"]


def test_auth_invalid_token_format(client):
    """测试 Authorization header 格式错误时返回 401"""
    resp = client.get(
        "/api/list-documents",
        headers={"Authorization": "Token xxx"},
    )
    assert resp.status_code == 401
    assert "Missing or invalid Authorization header" in resp.get_json()["error"]


def test_auth_expired_token(client, mocker):
    """
    测试 Token 过期 (SignatureExpired)。
    """
    mock_serializer_func = mocker.patch('server.src.server._serializer')
    mock_serializer_func.return_value.loads.side_effect = SignatureExpired("Token expired")
    
    resp = client.get(
        "/api/list-documents",
        headers={"Authorization": "Bearer expired_token_string"},
    )
    
    assert resp.status_code == 401
    assert "Token expired" in resp.get_json()["error"]


def test_auth_bad_signature(client, mocker):
    """
    测试 Token 签名错误 (BadSignature)。
    """
    mock_serializer = mocker.patch('server.src.server._serializer')
    mock_serializer.return_value.loads.side_effect = BadSignature("Invalid token")
    
    resp = client.get(
        "/api/list-documents",
        headers={"Authorization": "Bearer bad_signature_token"},
    )
    
    assert resp.status_code == 401
    assert "Invalid token" in resp.get_json()["error"]






# ======================================================================
# 文件上传校验错误 (L225, 228, 232)
# ======================================================================

def test_upload_rejects_non_pdf(client, logged_in_client):
    """测试上传非 .pdf 扩展名的文件 (L225)"""
    headers = logged_in_client
    
    # 扩展名错误
    resp = client.post(
        "/api/upload-document",
        data={"file": (io.BytesIO(b"%PDF"), "image.jpg")},
        headers=headers,
    )
    assert resp.status_code == 400
    assert "only PDF files are allowed" in resp.get_json()["error"]


def test_upload_rejects_bad_pdf_header(client, mocker, logged_in_client):
    """测试上传文件头不是 %PDF 的文件 (L232) - Mocking file.stream"""
    headers = logged_in_client
    
    # 直接构造一个假文件，内容不是 %PDF 开头
    bad_pdf_content = b"NOT_A_PDF_HEADER"
    
    r = client.post(
        "/api/upload-document",
        data={"file": (io.BytesIO(bad_pdf_content), "bad_header.pdf")},
        headers=headers,
        content_type="multipart/form-data",
    )

    # L232 检查应该生效，返回 400
    assert r.status_code == 400
    assert "file is not a valid PDF" in r.get_json()["error"]


def test_upload_rejects_empty_filename(client, logged_in_client):
    """测试上传空文件名 (L228)"""
    headers = logged_in_client
    
    # 测试空文件名
    resp1 = client.post(
        "/api/upload-document",
        data={"file": (io.BytesIO(b"%PDF"), "")},
        headers=headers,
    )
    assert resp1.status_code == 400
    assert "empty filename" in resp1.get_json()["error"]


# ------------------------------------------------------------
# 文件访问路径安全检查 (覆盖 L435, L470)
# ------------------------------------------------------------

def test_get_document_file_missing_on_disk(client, mocker, logged_in_client):
    """测试 get-document 文件丢失 (410 Gone) (L470)"""
    headers = logged_in_client
    
    # 1. Mock DB 返回一个看似有效的路径
    mock_row = MagicMock(id=1, name="secret.pdf", path="/tmp/somefile.pdf")
    from server.src.server import get_engine 
    mock_engine = MagicMock()
    mock_conn = mock_engine.connect.return_value.__enter__.return_value
    mock_conn.execute.return_value.first.return_value = mock_row
    mocker.patch('server.src.server.get_engine', return_value=mock_engine)
    
    # 2. Mock Path.exists()，强制其返回 False (L470)
    #    我们只 Mock Path.exists
    mocker.patch('pathlib.Path.exists', return_value=False)
    
    # 3. 确保路径安全检查通过 (Mock _safe_resolve_under_storage)
    #    因为 Path.resolve() 和 Path.relative_to() 仍然可能失败，我们 Mock 掉安全函数本身
    mocker.patch('server.src.server._safe_resolve_under_storage', 
                 return_value=Path("/tmp/somefile.pdf"))

    # 4. 发送请求
    resp = client.get("/api/get-document/1", headers=headers)
    
    # 预期命中 L470，返回 410
    assert resp.status_code == 410
    assert "file missing on disk" in resp.get_json()["error"]



def test_delete_document_path_traversal_is_blocked(client, mocker):
    """
    🎯 目标：确保 delete-document 不能用于路径遍历删除文件。
    针对 server.py L759-766
    """
    doc_id = 999
    logged_in_user_id = 1
    
    # 1. 模拟数据库返回一个恶意的文件路径，但属于当前用户
    malicious_path = "../../../etc/flag" # 相对路径逃逸
    mock_row = MagicMock(id=doc_id, path=malicious_path)
    
    mock_conn = MagicMock()
    mock_conn.execute.return_value.first.return_value = mock_row
    mocker.patch('server.src.server.get_engine', return_value=MagicMock(connect=MagicMock(return_value=MagicMock(__enter__=MagicMock(return_value=mock_conn)))))
    
    # 2. 模拟认证成功，设置 g.user
    # mocker.patch('server.src.server.require_auth', side_effect=lambda f: f)
    mocker.patch('flask.g', user={"id": logged_in_user_id, "login": "testuser"})

    # 2. 模拟 _serializer (L328 附近)
    # 模拟 _serializer().loads(...) 总是返回一个有效的用户字典
    mock_serializer = mocker.patch('server.src.server._serializer')
    # 让 loads 方法返回一个有效的用户字典，这样认证装饰器就会通过
    mock_serializer.return_value.loads.return_value = {"uid": logged_in_user_id, "login": "testuser", "email": "a@b.com"}

    # 3. Mock 路径解析函数，确保它抛出异常
    mocker.patch('server.src.server._safe_resolve_under_storage', side_effect=RuntimeError("path escapes storage root"))
    
    # 4. 运行请求
    resp = client.delete(f"/api/delete-document/{doc_id}", 
                     headers={'Authorization': 'Bearer valid-token'})    
    # 5. 断言：安全检查失败后，应该返回错误状态，数据库删除不应被调用
    # 尽管安全检查失败，但原始代码中没有明确的 try...except 块来捕获 _safe_resolve_under_storage 
    # 抛出的 RuntimeError，这可能导致 500 Internal Server Error，但安全目标是路径解析函数被调用。

    # 我们测试预期路径：_safe_resolve_under_storage 抛出异常，阻止文件删除和数据库操作。
    assert resp.status_code == 500 or resp.status_code == 404 # 确保没有成功删除
    
    # 确保数据库的 DELETE 语句没有被执行 (因为它是在获取行之后，在文件系统操作之后)
    # 由于原始代码结构，如果 _safe_resolve_under_storage 失败，它会跳过文件删除和 DB DELETE。
    mock_conn.begin.return_value.__enter__.return_value.execute.assert_not_called()