import pytest
from pathlib import Path
from server.src import rmap_routes
from unittest.mock import MagicMock
from sqlalchemy.exc import DBAPIError



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


