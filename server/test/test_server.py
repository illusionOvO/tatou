# import tempfile
# import pytest 



# def test_safe_resolve_under_storage():
#     """测试路径安全解析功能"""
#     from server.src.server import _safe_resolve_under_storage
#     from pathlib import Path
    
#     # 创建临时存储目录
#     with tempfile.TemporaryDirectory() as temp_dir:
#         storage_root = Path(temp_dir)
        
#         # 测试相对路径
#         relative_path = "files/user/document.pdf"
#         resolved = _safe_resolve_under_storage(relative_path, storage_root)
#         assert resolved == storage_root / relative_path
        
#         # 测试绝对路径（在存储目录内）
#         absolute_inside = storage_root / "files/test.pdf"
#         resolved = _safe_resolve_under_storage(absolute_inside, storage_root)
#         assert resolved == absolute_inside
        
#         # 测试路径遍历攻击（应该抛出异常）
#         with pytest.raises(RuntimeError):
#             _safe_resolve_under_storage("../../../etc/passwd", storage_root)

# def test_upload_document_file_validation(mocker):
#     """测试文件上传的验证逻辑"""
#     # 这个测试会覆盖很多文件验证相关的变异
#     from server.src.server import create_app
#     import io

#     app = create_app()
    
#     with app.test_client() as client:
        
#         # **重要：Mock 身份验证**
#         # 模拟 Token 被成功解析，并设置 Flask 的全局 g.user 对象
#         # 我们需要 Mock 装饰器内部使用的 _serializer.loads 方法
        
#         mock_serializer = mocker.patch('server.src.server._serializer')
#         # 模拟 loads 方法返回一个有效的用户字典
#         mock_serializer.return_value.loads.return_value = {"uid": 1, "login": "testuser", "email": "a@b.com"}
        
#         # 测试非PDF文件
#         response = client.post('/api/upload-document',
#                              data={'file': (io.BytesIO(b'not a pdf'), 'test.txt')},
#                              headers={'Authorization': 'Bearer test-token'})
#         # 现在身份验证会成功，并继续执行文件类型检查，应该返回 400
#         assert response.status_code == 400
        
#         # 测试空文件
#         response = client.post('/api/upload-document',
#                              data={'file': (io.BytesIO(b''), 'empty.pdf')},
#                              headers={'Authorization': 'Bearer test-token'})
#         assert response.status_code == 400


# test_server.py
import tempfile
import pytest
import io
import json
from unittest.mock import patch, MagicMock
from pathlib import Path

# 导入 server 模块
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
from server.src import server

# 或者如果直接导入有问题，可以这样导入
try:
    from server.src.server import create_app, _safe_resolve_under_storage
except ImportError:
    # 备选导入方式
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from server.src.server import create_app, _safe_resolve_under_storage


def test_safe_resolve_under_storage():
    """测试路径安全解析功能"""
    from pathlib import Path
    
    # 创建临时存储目录
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


def test_upload_document_file_validation():
    """测试文件上传的验证逻辑"""
    app = create_app()
    app.config['TESTING'] = True
    
    with app.test_client() as client:
        # 测试非PDF文件
        data = {
            'file': (io.BytesIO(b'not a pdf'), 'test.txt')
        }
        headers = {'Authorization': 'Bearer test-token'}
        
        # 使用 mock 绕过 token 验证
        with patch('server.src.server._serializer') as mock_serializer:
            mock_serializer.return_value.loads.return_value = {
                "uid": 1, 
                "login": "testuser", 
                "email": "a@b.com"
            }
            
            response = client.post('/api/upload-document', 
                                 data=data, 
                                 headers=headers,
                                 content_type='multipart/form-data')
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'only PDF files are allowed' in data.get('error', '')


def test_upload_empty_file():
    """测试上传空文件"""
    app = create_app()
    app.config['TESTING'] = True
    
    with app.test_client() as client:
        data = {
            'file': (io.BytesIO(b''), 'empty.pdf')
        }
        headers = {'Authorization': 'Bearer test-token'}
        
        with patch('server.src.server._serializer') as mock_serializer:
            mock_serializer.return_value.loads.return_value = {
                "uid": 1, 
                "login": "testuser", 
                "email": "a@b.com"
            }
            
            response = client.post('/api/upload-document', 
                                 data=data, 
                                 headers=headers,
                                 content_type='multipart/form-data')
            assert response.status_code == 400


def test_upload_invalid_pdf_header():
    """测试无效的 PDF 文件头"""
    app = create_app()
    app.config['TESTING'] = True
    
    with app.test_client() as client:
        data = {
            'file': (io.BytesIO(b'NOT%PDF-1.4'), 'invalid.pdf')
        }
        headers = {'Authorization': 'Bearer test-token'}
        
        with patch('server.src.server._serializer') as mock_serializer:
            mock_serializer.return_value.loads.return_value = {
                "uid": 1, 
                "login": "testuser", 
                "email": "a@b.com"
            }
            
            response = client.post('/api/upload-document', 
                                 data=data, 
                                 headers=headers,
                                 content_type='multipart/form-data')
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'not a valid PDF' in data.get('error', '')


def test_create_user_missing_fields():
    """测试创建用户缺少必填字段"""
    app = create_app()
    app.config['TESTING'] = True
    
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


def test_login_missing_credentials():
    """测试登录缺少凭证"""
    app = create_app()
    app.config['TESTING'] = True
    
    with app.test_client() as client:
        # 测试缺少 email
        response = client.post('/api/login', 
                             json={"password": "pass"})
        assert response.status_code == 400
        
        # 测试缺少 password
        response = client.post('/api/login', 
                             json={"email": "test@example.com"})
        assert response.status_code == 400


def test_health_check():
    """测试健康检查端点"""
    app = create_app()
    app.config['TESTING'] = True
    
    with app.test_client() as client:
        response = client.get('/healthz')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'message' in data
        assert 'db_connected' in data


def test_get_document_not_found():
    """测试获取不存在的文档"""
    app = create_app()
    app.config['TESTING'] = True
    
    with app.test_client() as client:
        with patch('server.src.server._serializer') as mock_serializer:
            mock_serializer.return_value.loads.return_value = {
                "uid": 1, 
                "login": "testuser", 
                "email": "a@b.com"
            }
            
            response = client.get('/api/get-document/999', 
                                headers={'Authorization': 'Bearer test-token'})
            assert response.status_code == 404


def test_delete_document_missing_id():
    """测试删除文档缺少ID"""
    app = create_app()
    app.config['TESTING'] = True
    
    with app.test_client() as client:
        with patch('server.src.server._serializer') as mock_serializer:
            mock_serializer.return_value.loads.return_value = {
                "uid": 1, 
                "login": "testuser", 
                "email": "a@b.com"
            }
            
            response = client.delete('/api/delete-document', 
                                   headers={'Authorization': 'Bearer test-token'})
            assert response.status_code == 400


def test_create_watermark_missing_params():
    """测试创建水印缺少参数"""
    app = create_app()
    app.config['TESTING'] = True
    
    with app.test_client() as client:
        with patch('server.src.server._serializer') as mock_serializer:
            mock_serializer.return_value.loads.return_value = {
                "uid": 1, 
                "login": "testuser", 
                "email": "a@b.com"
            }
            
            # 测试缺少必要参数
            response = client.post('/api/create-watermark', 
                                 json={},
                                 headers={'Authorization': 'Bearer test-token'})
            assert response.status_code == 400


def test_sha256_file():
    """测试 SHA256 计算函数"""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b'test content')
        f.flush()
        
        hash_result = server._sha256_file(Path(f.name))
        # SHA256 of "test content"
        expected = "956a5d1f2e5b1f38e2e3d3a5b5e5f3e5d1f2e5b1f38e2e3d3a5b5e5f3e5d1f2e5b"
        assert len(hash_result) == 64  # SHA256 哈希长度


if __name__ == '__main__':
    pytest.main([__file__, '-v'])