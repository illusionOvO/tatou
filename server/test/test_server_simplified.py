# server/test/test_server_simplified.py
import pytest
import json
import io
import tempfile
import sys
import os
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from server.src.server import create_app, _sha256_file, _safe_resolve_under_storage


def test_sha256_file_empty():
    """测试 SHA256 计算 - 空文件"""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        file_path = Path(f.name)
    
    try:
        hash_result = _sha256_file(file_path)
        # 空文件的 SHA256
        empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert hash_result == empty_hash
        assert len(hash_result) == 64
    finally:
        file_path.unlink()


def test_sha256_file_with_content():
    """测试 SHA256 计算 - 有内容的文件"""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b'test content')
        file_path = Path(f.name)
    
    try:
        hash_result = _sha256_file(file_path)
        # "test content" 的 SHA256
        expected = "1eebdf4fdc9fc7bf283031b93f9aef3338de9052e3c8d5b4b8525d4e3c6286c4"
        assert hash_result == expected
    finally:
        file_path.unlink()


def test_safe_resolve_under_storage():
    """测试路径安全解析功能"""
    with tempfile.TemporaryDirectory() as temp_dir:
        storage_root = Path(temp_dir)
        
        # 测试相对路径
        relative_path = "files/user/document.pdf"
        resolved = _safe_resolve_under_storage(relative_path, storage_root)
        assert resolved == storage_root / relative_path
        
        # 测试绝对路径（在存储目录内）
        absolute_inside = storage_root / "files/test.pdf"
        resolved = _safe_resolve_under_storage(absolute_inside, storage_root)
        assert resolved == absolute_inside
        
        # 测试路径遍历攻击（应该抛出异常）
        with pytest.raises(RuntimeError):
            _safe_resolve_under_storage("../../../etc/passwd", storage_root)


def test_create_app_basic():
    """测试 create_app 基本功能"""
    app = create_app()
    assert app is not None
    assert 'SECRET_KEY' in app.config
    assert 'STORAGE_DIR' in app.config


def test_healthz_endpoint():
    """测试健康检查端点"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    # Mock 数据库连接
    with patch('server.src.server.get_engine') as mock_engine:
        mock_conn = MagicMock()
        mock_conn.execute.return_value = None
        mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
        
        with app.test_client() as client:
            response = client.get('/healthz')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert 'message' in data
            assert 'db_connected' in data


def test_healthz_db_error():
    """测试健康检查数据库错误"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    # Mock 数据库连接错误
    with patch('server.src.server.get_engine') as mock_engine:
        mock_engine.return_value.connect.side_effect = Exception("DB error")
        
        with app.test_client() as client:
            response = client.get('/healthz')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert 'db_connected' in data
            assert data['db_connected'] is False


def test_create_user_missing_fields():
    """测试创建用户缺少必填字段"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.test_client() as client:
        # 测试缺少 email
        response = client.post('/api/create-user', 
                             json={"login": "test", "password": "pass"})
        assert response.status_code == 400
        
        # 测试缺少 login
        response = client.post('/api/create-user', 
                             json={"email": "test@example.com", "password": "pass"})
        assert response.status_code == 400
        
        # 测试缺少 password
        response = client.post('/api/create-user', 
                             json={"email": "test@example.com", "login": "test"})
        assert response.status_code == 400


def test_create_user_invalid_password_type():
    """测试创建用户密码类型无效"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.test_client() as client:
        # 测试密码是数字的情况
        response = client.post('/api/create-user', 
                             json={"email": "test@example.com", "login": "test", "password": 123})
        assert response.status_code == 400


def test_create_user_login_too_long():
    """测试创建用户登录名太长"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.test_client() as client:
        # 创建超过255字符的登录名
        long_login = 'x' * 256
        response = client.post('/api/create-user', 
                             json={"email": "test@example.com", "login": long_login, "password": "pass"})
        assert response.status_code == 400


def test_login_missing_credentials():
    """测试登录缺少凭证"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.test_client() as client:
        # 测试缺少 email
        response = client.post('/api/login', 
                             json={"password": "pass"})
        assert response.status_code == 400
        
        # 测试缺少 password
        response = client.post('/api/login', 
                             json={"email": "test@example.com"})
        assert response.status_code == 400


def test_login_invalid_password_type():
    """测试登录密码类型无效"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.test_client() as client:
        # 测试密码是数字的情况
        response = client.post('/api/login', 
                             json={"email": "test@example.com", "password": 123})
        assert response.status_code == 400


def test_get_watermarking_methods():
    """测试获取水印方法"""
    app = create_app()
    app.config['TESTING'] = True
    
    with app.test_client() as client:
        response = client.get('/api/get-watermarking-methods')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'methods' in data
        assert 'count' in data


def test_upload_document_no_file():
    """测试上传文档没有文件"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    # Mock token 验证
    with patch('server.src.server._serializer') as mock_serializer:
        mock_serializer.return_value.loads.return_value = {
            "uid": 1, 
            "login": "testuser", 
            "email": "a@b.com"
        }
        
        with app.test_client() as client:
            response = client.post('/api/upload-document', 
                                 data={},
                                 headers={'Authorization': 'Bearer test-token'},
                                 content_type='multipart/form-data')
            assert response.status_code == 400


def test_upload_document_empty_filename():
    """测试上传文档文件名为空"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with patch('server.src.server._serializer') as mock_serializer:
        mock_serializer.return_value.loads.return_value = {
            "uid": 1, 
            "login": "testuser", 
            "email": "a@b.com"
        }
        
        with app.test_client() as client:
            data = {
                'file': (io.BytesIO(b'%PDF-1.4\ntest'), '')
            }
            response = client.post('/api/upload-document', 
                                 data=data,
                                 headers={'Authorization': 'Bearer test-token'},
                                 content_type='multipart/form-data')
            assert response.status_code == 400


def test_upload_document_not_pdf():
    """测试上传非PDF文件"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with patch('server.src.server._serializer') as mock_serializer:
        mock_serializer.return_value.loads.return_value = {
            "uid": 1, 
            "login": "testuser", 
            "email": "a@b.com"
        }
        
        with app.test_client() as client:
            data = {
                'file': (io.BytesIO(b'not a pdf'), 'test.txt')
            }
            response = client.post('/api/upload-document', 
                                 data=data,
                                 headers={'Authorization': 'Bearer test-token'},
                                 content_type='multipart/form-data')
            assert response.status_code == 400


def test_upload_document_invalid_pdf_header():
    """测试上传无效PDF文件头"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with patch('server.src.server._serializer') as mock_serializer:
        mock_serializer.return_value.loads.return_value = {
            "uid": 1, 
            "login": "testuser", 
            "email": "a@b.com"
        }
        
        with app.test_client() as client:
            data = {
                'file': (io.BytesIO(b'NOT%PDF-1.4'), 'test.pdf')
            }
            response = client.post('/api/upload-document', 
                                 data=data,
                                 headers={'Authorization': 'Bearer test-token'},
                                 content_type='multipart/form-data')
            assert response.status_code == 400


def test_upload_document_too_small():
    """测试上传文件太小"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with patch('server.src.server._serializer') as mock_serializer:
        mock_serializer.return_value.loads.return_value = {
            "uid": 1, 
            "login": "testuser", 
            "email": "a@b.com"
        }
        
        with app.test_client() as client:
            # 创建刚好9字节的文件（小于10字节的限制）
            tiny_pdf = b'%PDF-1.4'  # 8 bytes
            data = {
                'file': (io.BytesIO(tiny_pdf), 'tiny.pdf')
            }
            response = client.post('/api/upload-document', 
                                 data=data,
                                 headers={'Authorization': 'Bearer test-token'},
                                 content_type='multipart/form-data')
            assert response.status_code == 400


def test_unauthorized_access():
    """测试未授权访问"""
    app = create_app()
    app.config['TESTING'] = True
    
    with app.test_client() as client:
        # 测试没有 token
        response = client.get('/api/list-documents')
        assert response.status_code == 401
        
        # 测试无效 token 格式
        response = client.get('/api/list-documents', 
                            headers={'Authorization': 'Invalid'})
        assert response.status_code == 401
        
        # 测试没有 Bearer 前缀
        response = client.get('/api/list-documents', 
                            headers={'Authorization': 'token'})
        assert response.status_code == 401


def test_static_files_and_home():
    """测试静态文件和首页"""
    app = create_app()
    app.config['TESTING'] = True
    
    with app.test_client() as client:
        # 测试首页
        response = client.get('/')
        # 可能返回 200 或 404，取决于是否有 index.html
        assert response.status_code in [200, 404]
        
        # 测试不存在的静态文件
        response = client.get('/static/nonexistent.css')
        assert response.status_code == 404


def test_get_version_not_found():
    """测试获取不存在的版本"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with patch('server.src.server.get_engine') as mock_engine:
        mock_conn = MagicMock()
        mock_conn.execute.return_value.first.return_value = None  # 模拟找不到版本
        mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
        
        with app.test_client() as client:
            response = client.get('/api/get-version/nonexistent')
            assert response.status_code == 404


def test_delete_document_missing_id():
    """测试删除文档缺少ID - 使用POST方法"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with patch('server.src.server._serializer') as mock_serializer:
        mock_serializer.return_value.loads.return_value = {
            "uid": 1, 
            "login": "testuser", 
            "email": "a@b.com"
        }
        
        with app.test_client() as client:
            # 使用 POST 方法，因为路由支持 DELETE 和 POST
            response = client.post('/api/delete-document', 
                                 headers={'Authorization': 'Bearer test-token'})
            # 缺少 document_id 应该返回 400
            assert response.status_code == 400


def test_create_watermark_missing_params():
    """测试创建水印缺少参数"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with patch('server.src.server._serializer') as mock_serializer:
        mock_serializer.return_value.loads.return_value = {
            "uid": 1, 
            "login": "testuser", 
            "email": "a@b.com"
        }
        
        with app.test_client() as client:
            # 测试缺少必要参数
            response = client.post('/api/create-watermark', 
                                 json={},
                                 headers={'Authorization': 'Bearer test-token'})
            assert response.status_code == 400


def test_read_watermark_missing_params():
    """测试读取水印缺少参数"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with patch('server.src.server._serializer') as mock_serializer:
        mock_serializer.return_value.loads.return_value = {
            "uid": 1, 
            "login": "testuser", 
            "email": "a@b.com"
        }
        
        with app.test_client() as client:
            # 测试缺少必要参数
            response = client.post('/api/read-watermark', 
                                 json={},
                                 headers={'Authorization': 'Bearer test-token'})
            assert response.status_code == 400


def test_load_plugin_missing_filename():
    """测试加载插件缺少文件名"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with patch('server.src.server._serializer') as mock_serializer:
        mock_serializer.return_value.loads.return_value = {
            "uid": 1, 
            "login": "testuser", 
            "email": "a@b.com"
        }
        
        with app.test_client() as client:
            # 测试空文件名
            response = client.post('/api/load-plugin', 
                                 json={"filename": ""},
                                 headers={'Authorization': 'Bearer test-token'})
            assert response.status_code == 400


def test_load_plugin_invalid_filename():
    """测试加载插件无效文件名"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with patch('server.src.server._serializer') as mock_serializer:
        mock_serializer.return_value.loads.return_value = {
            "uid": 1, 
            "login": "testuser", 
            "email": "a@b.com"
        }
        
        with app.test_client() as client:
            # 测试无效扩展名
            response = client.post('/api/load-plugin', 
                                 json={"filename": "bad.exe"},
                                 headers={'Authorization': 'Bearer test-token'})
            assert response.status_code == 400


if __name__ == '__main__':
    pytest.main([__file__, '-v'])