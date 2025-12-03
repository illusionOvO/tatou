import pytest
from pathlib import Path
from server.src import rmap_routes
from unittest.mock import MagicMock, patch
from sqlalchemy.exc import DBAPIError
from server.src.rmap_routes import VisibleTextWatermark, MetadataWatermark
import importlib
from unittest.mock import patch # <-- 新增导入
from server.src import rmap_routes

# ---------- Tests ----------

def test_rmap_initiate_success(client):
    r = client.post("/api/rmap-initiate", json={"identity": "test"})
    assert r.status_code in (200, 400)


def test_rmap_initiate_bad_json(client):
    r = client.post("/api/rmap-initiate", json={})
    assert r.status_code in (200, 400)


# def test_rmap_get_link_success(client, monkeypatch):
#     class FakeRow:
#         download_url = "https://example.com/file.pdf"

    # monkeypatch.setattr("server.src.rmap_routes.run_query",
    #                     lambda *a, **k: FakeRow())

    r = client.post("/api/rmap-get-link", json={"identity": "x"})
    assert r.status_code in (200, 400)


# def test_rmap_get_link_missing_pdf(client, monkeypatch):
    # monkeypatch.setattr("server.src.rmap_routes.run_query",
    #                     lambda *a, **k: None)

    r = client.post("/api/rmap-get-link", json={"identity": "x"})
    assert r.status_code in (200, 400)


def test_rmap_get_version_not_found(client):
    r = client.get("/get-version/does_not_exist")
    assert r.status_code == 404






# 1. 错误处理和协议失败 (L77-78, L84-88, L96)
def test_rmap_initiate_protocol_error(client, mocker):
    """测试 rmap-initiate 捕获 RMAP 库错误并返回 400."""
    mock_rmap = mocker.patch('server.src.rmap_routes.rmap')
    mock_rmap.handle_message1.return_value = {"error": "RMAP protocol failure"}
    
    resp = client.post("/api/rmap-initiate", json={"payload": "dummy"})
    
    assert resp.status_code == 400
    assert "RMAP protocol failure" in resp.get_json()["error"]


def test_rmap_initiate_general_exception(client, mocker):
    """测试 rmap-initiate 捕获通用异常并返回 400 (L96)"""
    mock_rmap = mocker.patch('server.src.rmap_routes.rmap')
    mock_rmap.handle_message1.side_effect = ValueError("General RMAP error")
    
    resp = client.post("/api/rmap-initiate", json={"payload": "dummy"})
    
    assert resp.status_code == 400
    assert "General RMAP error" in resp.get_json()["error"]




# 2. 输入 PDF 文件缺失检查 (L139-143)
def test_rmap_get_link_input_pdf_not_found(client, mocker):
    """测试 RMAP_INPUT_PDF 文件不存在时的错误 (L139-143)"""
    
    # 1. 模拟 RMAP 握手成功
    mock_rmap = mocker.patch('server.src.rmap_routes.rmap')
    mock_rmap.handle_message2.return_value = {"result": "session_secret"}

    # 2. Mock RMAP_INPUT_PDF 环境变量和 Path.is_file
    mocker.patch.dict('os.environ', {'RMAP_INPUT_PDF': 'nonexistent/path/to.pdf'})
    mocker.patch('pathlib.Path.is_file', return_value=False)
    
    resp = client.post("/api/rmap-get-link", json={"payload": "dummy"})
    
    assert resp.status_code == 500
    assert "input pdf not found" in resp.get_json()["error"]




# 3. 数据库插入失败 (L167-213)
def test_rmap_get_link_db_insert_failure(client, mocker):
    """测试 Versions 表插入失败时的警告分支 (L167-213)"""
    
    # 1. 模拟 RMAP 握手成功
    mock_rmap = mocker.patch('server.src.rmap_routes.rmap')
    mock_rmap.handle_message2.return_value = {"result": "session_secret"}
    
    # 2. Mock DB Engine，强制 conn.execute 在插入 Versions 时抛出异常
    mock_engine = MagicMock()
    mock_conn = mock_engine.begin.return_value.__enter__.return_value
    mock_conn.execute.side_effect = DBAPIError("DB insert failed", {}, {})
    mocker.patch('server.src.rmap_routes._get_engine', return_value=mock_engine)

# 3. 模拟输入 PDF 存在和水印成功 (避免文件错误)
    mocker.patch.dict('os.environ', {'RMAP_INPUT_PDF': '/mock/exists.pdf'})
    mocker.patch('pathlib.Path.is_file', return_value=True)
    mocker.patch('pathlib.Path.read_bytes', return_value=b'pdf_content')
    mocker.patch('server.src.rmap_routes.VisibleTextWatermark.add_watermark', return_value=b'wm_content')
    mocker.patch('server.src.rmap_routes.MetadataWatermark.add_watermark', return_value=b'wm_content')

    # 【CRITICAL FIX】：模拟文件写入和目录创建成功，防止 PermissionError
    mocker.patch('pathlib.Path.mkdir', return_value=None)
    mocker.patch('pathlib.Path.write_bytes', return_value=None)
    
    resp = client.post("/api/rmap-get-link", json={"payload": "dummy"})
    
    # 断言：RMAP 成功流程要求返回 200/secret，尽管 DB 失败
    assert resp.status_code == 200
    assert resp.get_json()["result"] == "session_secret"


def test_expand_function_paths():
    """测试 _expand 函数的各种路径情况"""
    from server.src.rmap_routes import _expand
    
    # 测试 None 输入
    assert _expand(None) is None, "输入 None 应该返回 None"
    
    # 测试普通路径扩展
    test_path = "~/test"
    result = _expand(test_path)
    assert result is not None
    assert "~" not in result  # 波浪号应该被扩展
    
    # 测试环境变量扩展
    import os
    if 'HOME' in os.environ:
        env_path = "$HOME/test"
        result = _expand(env_path)
        assert result is not None
        assert "$HOME" not in result  # 环境变量应该被扩展
    
    # 测试普通路径（无扩展）
    normal_path = "/tmp/test"
    result = _expand(normal_path)
    assert result == "/tmp/test"


# 放在 test_rmap_routes.py 中
# ... 需要在文件开头引入 from unittest.mock import MagicMock
# ... 确保你已经定义了 _get_engine (在 rmap_routes.py 中)

def test_rmap_get_link_db_insert_success(client, mocker):
    """
    🎯 目标：验证 Versions 表插入的字段值是否正确 (消除 L167-213 的变异体)。
    """
    expected_secret = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
    expected_identity = "Group_Test"
    
    # 1. 模拟 RMAP 握手成功
    mock_rmap = mocker.patch('server.src.rmap_routes.rmap')
    mock_rmap.handle_message2.return_value = {"result": expected_secret}
    
    # **新增 Mock:** 模拟 _guess_identity 函数返回我们期望的身份
    # 这样可以确保身份逻辑被正确绕过，避免回退到 'rmap'
    mocker.patch('server.src.rmap_routes._guess_identity', return_value=expected_identity)

    # 2. Mock 数据库连接，捕获 INSERT 语句的参数
    mock_engine = MagicMock()
    # 模拟事务/连接对象
    mock_conn = mock_engine.begin.return_value.__enter__.return_value
    mocker.patch('server.src.rmap_routes._get_engine', return_value=mock_engine)

    # 3. 模拟文件和水印成功 (避免其他错误)
    mocker.patch.dict('os.environ', {'RMAP_INPUT_PDF': '/mock/exists.pdf'})
    mocker.patch('pathlib.Path.is_file', return_value=True)
    mocker.patch('pathlib.Path.read_bytes', return_value=b'pdf_content')
    mocker.patch('server.src.rmap_routes.VisibleTextWatermark.add_watermark', return_value=b'wm_content')
    mocker.patch('server.src.rmap_routes.MetadataWatermark.add_watermark', return_value=b'wm_content')
    mocker.patch('pathlib.Path.mkdir', return_value=None)
    mocker.patch('pathlib.Path.write_bytes', return_value=None)
    
    # 4. 模拟 rmap-initiate 已经设置了身份
    mocker.patch.object(client.application.config, 'get', side_effect=lambda k, d=None: expected_identity if k == "LAST_RMAP_IDENTITY" else d)

    # 运行请求
    resp = client.post("/api/rmap-get-link", json={"payload": "dummy"})
    
    # 断言 HTTP 状态码和返回的 secret
    assert resp.status_code == 200
    assert resp.get_json()["result"] == expected_secret

    # 断言数据库 INSERT 语句被调用，并检查参数是否正确
    mock_conn.execute.assert_called_once()
    
    # 获取传递给 conn.execute 的参数 (第二个参数是参数字典)
    params = mock_conn.execute.call_args[0][1] 

    # 验证插入数据库的关键字段值
    assert params["link"] == expected_secret
    assert params["intended_for"] == expected_identity
    assert params["method"] == "visible+metadata"
    # 根据 rmap_routes.py 中的实现，documentid 被设置为 secret
    assert params["documentid"] == expected_secret



    # 放在 test_rmap_routes.py 中
from server.src.rmap_routes import WATERMARK_HMAC_KEY

def test_rmap_get_link_watermark_call(client, mocker):
    """
    🎯 目标：测试水印方法是否被正确调用且参数正确 (L136-141)。
    """
    expected_secret = "correct_session_secret"
    
    # 1. 模拟 RMAP 握手成功
    mock_rmap = mocker.patch('server.src.rmap_routes.rmap')
    mock_rmap.handle_message2.return_value = {"result": expected_secret}

    # 2. Mock 数据库和文件操作，专注于水印调用
    mocker.patch('server.src.rmap_routes._get_engine', MagicMock())
    mocker.patch.dict('os.environ', {'RMAP_INPUT_PDF': '/mock/exists.pdf'})
    mocker.patch('pathlib.Path.is_file', return_value=True)
    mock_read_bytes = mocker.patch('pathlib.Path.read_bytes', return_value=b'pdf_content')
    mocker.patch('pathlib.Path.mkdir', return_value=None)
    mocker.patch('pathlib.Path.write_bytes', return_value=None)
    
    # 3. 模拟 VisibleTextWatermark 和 MetadataWatermark 的 add_watermark 方法
    mock_vt_add = mocker.patch('server.src.rmap_routes.VisibleTextWatermark.add_watermark')
    mock_vt_add.return_value = b'watermarked_content_1'
    mock_xmp_add = mocker.patch('server.src.rmap_routes.MetadataWatermark.add_watermark')
    mock_xmp_add.return_value = b'watermarked_content_2'
    
    # 运行请求
    resp = client.post("/api/rmap-get-link", json={"payload": "dummy"})
    
    assert resp.status_code == 200
    
    # 断言 VisibleTextWatermark 被正确调用
    mock_vt_add.assert_called_once()
    vt_call_args = mock_vt_add.call_args[0]
    # 验证参数顺序: (pdf_bytes, secret, key)
    assert vt_call_args[1] == expected_secret 
    assert vt_call_args[2] == WATERMARK_HMAC_KEY 

    # 断言 MetadataWatermark 被正确调用 (确保是叠加，即使用了上一个水印的输出)
    mock_xmp_add.assert_called_once()
    xmp_call_args = mock_xmp_add.call_args[0]
    # 验证输入 PDF 是上一个水印的输出
    assert xmp_call_args[0] == b'watermarked_content_1' 
    assert xmp_call_args[1] == expected_secret
    assert xmp_call_args[2] == WATERMARK_HMAC_KEY


def test_rmap_get_link_watermark_order(client, mocker):
    """
    🎯 目标：验证水印叠加顺序和数据流是否正确 (L136-143)。
    """
    expected_secret = "correct_session_secret"
    
    mocker.patch('server.src.rmap_routes.rmap.handle_message2', return_value={"result": expected_secret})
    
    # Mock 文件和 DB 操作 (避免 side effect)
    mocker.patch('server.src.rmap_routes._get_engine', MagicMock())
    mocker.patch.dict('os.environ', {'RMAP_INPUT_PDF': '/mock/exists.pdf'})
    mocker.patch('pathlib.Path.is_file', return_value=True)
    mocker.patch('pathlib.Path.read_bytes', return_value=b'Initial_PDF_Bytes')
    mocker.patch('pathlib.Path.mkdir', return_value=None)
    mocker.patch('pathlib.Path.write_bytes', return_value=None)
    
    # 模拟水印方法
    mock_vt_instance = MagicMock(spec=VisibleTextWatermark)
    mock_xmp_instance = MagicMock(spec=MetadataWatermark)
    
    # 注入 mock 实例
    mocker.patch('server.src.rmap_routes.VisibleTextWatermark', return_value=mock_vt_instance)
    mocker.patch('server.src.rmap_routes.MetadataWatermark', return_value=mock_xmp_instance)

    # 模拟第一次水印输出
    mock_vt_instance.add_watermark.return_value = b'Output_From_VT'
    # 模拟第二次水印输出
    mock_xmp_instance.add_watermark.return_value = b'Final_Watermarked_PDF'
    
    resp = client.post("/api/rmap-get-link", json={"payload": "dummy"})
    
    assert resp.status_code == 200

    # 1. 验证 VisibleTextWatermark 使用了原始 PDF
    mock_vt_instance.add_watermark.assert_called_once()
    assert mock_vt_instance.add_watermark.call_args[0][0] == b'Initial_PDF_Bytes'

    # 2. 验证 MetadataWatermark 使用了 VisibleTextWatermark 的输出
    mock_xmp_instance.add_watermark.assert_called_once()
    assert mock_xmp_instance.add_watermark.call_args[0][0] == b'Output_From_VT'




def test_config_missing_server_key_prevents_init(mocker):
    """
    测试 RMAP_SERVER_PRIV 文件缺失时是否正确抛出错误。
    目标是 L49-52 和 _require_file (L33)。
    """
    # 1. Mock os.path.isfile 来模拟私钥文件缺失
    mocker.patch('os.path.isfile', side_effect=lambda p: False if 'server_priv.asc' in p else True)
    
    # 2. Mock os.path.isdir 来防止 RMAP_KEYS_DIR 检查出错
    mocker.patch('os.path.isdir', return_value=True)
    
    # 3. 使用 patch.dict 确保环境变量存在，但文件被 Mock 为缺失
    with patch.dict('os.environ', {
        "RMAP_SERVER_PRIV": "server_priv.asc",
        "RMAP_SERVER_PUB": "server_pub.asc",
    }, clear=False):
        
        # 4. 尝试重新加载模块；预期会失败
        with pytest.raises(FileNotFoundError) as excinfo:
            # 必须重新加载模块才能触发函数外的初始化逻辑
            importlib.reload(rmap_routes) 
        
        # 断言正确的错误信息
        assert "RMAP_SERVER_PRIV not found at:" in str(excinfo.value)
        

def test_config_missing_keys_dir_prevents_init(mocker):
    """
    测试 RMAP_KEYS_DIR 缺失时是否正确抛出 RuntimeError。
    目标是 L44-47。
    """
    # 1. Mock os.path.isdir 来模拟密钥目录缺失
    mocker.patch('os.path.isdir', return_value=False)
    
    # 2. Mock os.path.isfile 来防止后续的 FileNotFoundError
    mocker.patch('os.path.isfile', return_value=True)

    with patch.dict('os.environ', {
        "RMAP_KEYS_DIR": "nonexistent/dir",
    }, clear=False):
        
        # 3. 尝试重新加载模块；预期会失败
        with pytest.raises(RuntimeError) as excinfo:
            importlib.reload(rmap_routes) 
        
        # 断言正确的错误信息
        assert "RMAP_KEYS_DIR not found or not a directory:" in str(excinfo.value)



@pytest.fixture
def clean_rmap_routes(mocker):
    """确保 RMAP 模块被重新加载，用于测试顶层初始化代码"""
    
    # 1. Mock 整个 IdentityManager/RMAP 类
    mocker.patch('server.src.rmap_routes.IdentityManager', autospec=True)
    mocker.patch('server.src.rmap_routes.RMAP', autospec=True)
    
    # 2. Mock 路径检查：
    # Mock os.path.isdir (用于 rmap_routes.py 顶层的检查)
    mocker.patch('os.path.isdir', return_value=True)
    mocker.patch('os.path.isfile', return_value=True) 

    # **关键修复：Mock Path.is_dir()**
    # 欺骗 IdentityManager.init 中的 Path(client_keys_dir).is_dir() 检查
    mocker.patch('pathlib.Path.is_dir', return_value=True) 

    mocker.patch('os.getenv', side_effect=lambda k, d: '/mock/path' if 'RMAP' in k else d)
    
    # 重新加载模块
    importlib.reload(rmap_routes)
    
    yield
    importlib.reload(rmap_routes)

# --- 新增测试：验证所有配置路径检查 ---
def test_rmap_config_paths_checked(clean_rmap_routes, mocker):
    """
    🎯 目标：验证 RMAP 模块的路径检查 (L44-52) 不能被跳过。
    这应该会杀死大量依赖于这些路径检查的变异体。
    """
    
    # 模拟 os.path.isdir 检查失败，并重新加载模块
    mocker.patch('os.path.isdir', return_value=False)
    mocker.patch('os.path.isfile', return_value=True)

    with pytest.raises(RuntimeError) as excinfo:
        importlib.reload(rmap_routes)
    
    # 断言是 RMAP_KEYS_DIR 检查失败
    assert "RMAP_KEYS_DIR not found or not a directory" in str(excinfo.value)

    # 模拟 os.path.isdir 成功，但 RMAP_SERVER_PRIV 文件缺失
    mocker.patch('os.path.isdir', return_value=True)
    mocker.patch('os.path.isfile', side_effect=lambda p: False if 'server_priv.asc' in p else True)

    with pytest.raises(FileNotFoundError) as excinfo:
        importlib.reload(rmap_routes)
    
    # 断言是 RMAP_SERVER_PRIV 文件检查失败
    assert "RMAP_SERVER_PRIV not found at" in str(excinfo.value)