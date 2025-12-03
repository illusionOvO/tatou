# server/test/test_server_specific_coverage.py
import pytest
import json
import io
import tempfile
import sys
import os
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from server.src.server import create_app, _safe_resolve_under_storage, _sha256_file


def test_server_import_exception_handling():
    """测试导入异常处理（行 65-68, 74-78）"""
    # 这些行处理 dill 导入失败的情况
    with patch('server.src.server._pickle', None):
        # 重新导入模块以触发异常处理
        import importlib
        import server.src.server as server_module
        importlib.reload(server_module)
        
        # 验证 _pickle 被设置为 _std_pickle
        assert server_module._pickle == server_module._std_pickle


def test_auth_error_helper_in_app_context():
    """测试 _auth_error 辅助函数在应用上下文中"""
    app = create_app()
    
    with app.app_context():
        # 需要访问内部的 _auth_error 函数
        # 由于它在 create_app 内部定义，我们需要间接测试
        
        # 测试未授权访问触发 _auth_error
        with app.test_client() as client:
            response = client.get('/api/list-documents')
            assert response.status_code == 401
            data = json.loads(response.data)
            assert 'Missing or invalid' in data.get('error', '')


def test_require_auth_token_expired():
    """测试 token 过期情况（行 158, 161）"""
    app = create_app()
    app.config['TESTING'] = True
    
    # 创建一个需要认证的路由来测试
    @app.route('/test-auth')
    @app.require_auth
    def test_auth_route():
        return jsonify({"message": "ok"})
    
    with app.test_client() as client:
        with patch('server.src.server._serializer') as mock_serializer:
            # 模拟 token 过期
            from itsdangerous import SignatureExpired
            mock_serializer.return_value.loads.side_effect = SignatureExpired("Token expired")
            
            response = client.get('/test-auth', headers={'Authorization': 'Bearer expired-token'})
            assert response.status_code == 401
            data = json.loads(response.data)
            assert 'Token expired' in data.get('error', '')


def test_require_auth_invalid_token():
    """测试无效 token 情况（行 158, 161）"""
    app = create_app()
    app.config['TESTING'] = True
    
    @app.route('/test-auth2')
    @app.require_auth
    def test_auth_route2():
        return jsonify({"message": "ok"})
    
    with app.test_client() as client:
        with patch('server.src.server._serializer') as mock_serializer:
            # 模拟无效 token
            from itsdangerous import BadSignature
            mock_serializer.return_value.loads.side_effect = BadSignature("Invalid token")
            
            response = client.get('/test-auth2', headers={'Authorization': 'Bearer invalid-token'})
            assert response.status_code == 401
            data = json.loads(response.data)
            assert 'Invalid token' in data.get('error', '')


def test_upload_document_no_form_name():
    """测试上传文档时没有提供表单名称（行 178-179）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    with app.test_client() as client:
        with patch('server.src.server._serializer') as mock_serializer:
            mock_serializer.return_value.loads.return_value = {
                "uid": 1, 
                "login": "testuser", 
                "email": "a@b.com"
            }
            
            # 上传 PDF 但没有提供 name 参数
            pdf_content = b'%PDF-1.4\ntest content'
            data = {
                'file': (io.BytesIO(pdf_content), 'test.pdf')
            }
            
            response = client.post('/api/upload-document', 
                                 data=data,
                                 headers={'Authorization': 'Bearer test-token'},
                                 content_type='multipart/form-data')
            
            # 应该使用文件名作为 name
            if response.status_code == 201:
                data = json.loads(response.data)
                assert data['name'] == 'test.pdf'


def test_create_user_integrity_error_specific_message():
    """测试创建用户时的完整性错误处理（行 193）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    with patch('server.src.server.get_engine') as mock_engine:
        mock_conn = MagicMock()
        
        # 模拟 IntegrityError
        from sqlalchemy.exc import IntegrityError
        error = IntegrityError("statement", "params", "orig")
        error.orig = Exception("Duplicate entry")
        
        mock_conn.execute.side_effect = error
        mock_engine.return_value.begin.return_value.__enter__.return_value = mock_conn
        
        with app.test_client() as client:
            response = client.post('/api/create-user', 
                                 json={"email": "test@example.com", "login": "test", "password": "pass"})
            # IntegrityError 应该返回 409 Conflict
            assert response.status_code == 409


def test_list_versions_invalid_document_id():
    """测试 list_versions 无效的 document_id（行 235）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    with app.test_client() as client:
        with patch('server.src.server._serializer') as mock_serializer:
            mock_serializer.return_value.loads.return_value = {
                "uid": 1, 
                "login": "testuser", 
                "email": "a@b.com"
            }
            
            # 测试无效的 document_id
            response = client.get('/api/list-versions?id=invalid')
            assert response.status_code == 400
            
            # 测试缺少 document_id
            response = client.get('/api/list-versions')
            assert response.status_code == 400


def test_get_document_invalid_document_id():
    """测试 get_document 无效的 document_id（行 275-276）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    with app.test_client() as client:
        with patch('server.src.server._serializer') as mock_serializer:
            mock_serializer.return_value.loads.return_value = {
                "uid": 1, 
                "login": "testuser", 
                "email": "a@b.com"
            }
            
            # 测试无效的 document_id
            response = client.get('/api/get-document?id=invalid')
            assert response.status_code == 400


def test_get_version_file_missing():
    """测试 get_version 文件不存在（行 300-301）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    with tempfile.TemporaryDirectory() as temp_dir:
        storage_dir = Path(temp_dir)
        
        with patch('server.src.server.get_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_row = MagicMock()
            mock_row.path = str(storage_dir / "nonexistent.pdf")
            mock_row.link = "test-link"
            mock_conn.execute.return_value.first.return_value = mock_row
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
            
            with patch('server.src.server.app.config') as mock_config:
                mock_config.get.return_value = storage_dir
                
                app = create_app()
                app.config['TESTING'] = True
                
                with app.test_client() as client:
                    response = client.get('/api/get-version/test-link')
                    # 文件不存在应该返回 410
                    assert response.status_code == 410


def test_delete_document_path_safety_check_failed():
    """测试删除文档时路径安全检查失败（行 317-321）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    with patch('server.src.server.get_engine') as mock_engine:
        mock_conn = MagicMock()
        mock_row = MagicMock()
        mock_row.id = 1
        mock_row.path = "/etc/passwd"  # 危险路径
        mock_conn.execute.return_value.first.return_value = mock_row
        mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
        
        with patch('server.src.server._serializer') as mock_serializer:
            mock_serializer.return_value.loads.return_value = {
                "uid": 1, 
                "login": "testuser", 
                "email": "a@b.com"
            }
            
            with app.test_client() as client:
                # Mock _safe_resolve_under_storage 抛出异常
                with patch('server.src.server._safe_resolve_under_storage') as mock_resolve:
                    mock_resolve.side_effect = RuntimeError("Path safety check failed")
                    
                    response = client.delete('/api/delete-document/1', 
                                           headers={'Authorization': 'Bearer test-token'})
                    # 即使路径检查失败，删除操作应该继续
                    assert response.status_code == 200


def test_create_watermark_invalid_document_id():
    """测试创建水印时无效的 document_id（行 335-336）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    with app.test_client() as client:
        with patch('server.src.server._serializer') as mock_serializer:
            mock_serializer.return_value.loads.return_value = {
                "uid": 1, 
                "login": "testuser", 
                "email": "a@b.com"
            }
            
            # 测试无效的 document_id
            response = client.post('/api/create-watermark?id=invalid', 
                                 json={"method": "test", "intended_for": "test", "secret": "test", "key": "test"},
                                 headers={'Authorization': 'Bearer test-token'})
            assert response.status_code == 400


def test_read_watermark_invalid_document_id():
    """测试读取水印时无效的 document_id（行 363-364）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    with app.test_client() as client:
        with patch('server.src.server._serializer') as mock_serializer:
            mock_serializer.return_value.loads.return_value = {
                "uid": 1, 
                "login": "testuser", 
                "email": "a@b.com"
            }
            
            # 测试无效的 document_id
            response = client.post('/api/read-watermark?id=invalid', 
                                 json={"method": "test", "key": "test"},
                                 headers={'Authorization': 'Bearer test-token'})
            assert response.status_code == 400


def test_load_plugin_empty_filename():
    """测试加载插件时文件名为空（行 380-384）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    with app.test_client() as client:
        with patch('server.src.server._serializer') as mock_serializer:
            mock_serializer.return_value.loads.return_value = {
                "uid": 1, 
                "login": "testuser", 
                "email": "a@b.com"
            }
            
            # 测试空文件名
            response = client.post('/api/load-plugin', 
                                 json={"filename": ""},
                                 headers={'Authorization': 'Bearer test-token'})
            assert response.status_code == 400


def test_load_plugin_invalid_filename_format():
    """测试加载插件时文件名格式无效（行 397-398）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    with app.test_client() as client:
        with patch('server.src.server._serializer') as mock_serializer:
            mock_serializer.return_value.loads.return_value = {
                "uid": 1, 
                "login": "testuser", 
                "email": "a@b.com"
            }
            
            # 测试无效的文件名格式
            test_cases = [
                "badfile.exe",  # 错误扩展名
                "file.",  # 没有扩展名
                ".pkl",  # 只有扩展名
            ]
            
            for filename in test_cases:
                response = client.post('/api/load-plugin', 
                                     json={"filename": filename},
                                     headers={'Authorization': 'Bearer test-token'})
                assert response.status_code == 400


def test_load_plugin_filename_contains_invalid_chars():
    """测试加载插件时文件名包含非法字符（行 405-406）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    with app.test_client() as client:
        with patch('server.src.server._serializer') as mock_serializer:
            mock_serializer.return_value.loads.return_value = {
                "uid": 1, 
                "login": "testuser", 
                "email": "a@b.com"
            }
            
            # secure_filename 会清理这些字符
            test_cases = [
                "../../bad.pkl",  # 路径遍历
                "file with spaces.pkl",  # 空格
                "file<>.pkl",  # 特殊字符
            ]
            
            for filename in test_cases:
                from werkzeug.utils import secure_filename
                safe_name = secure_filename(filename)
                if safe_name != filename:
                    response = client.post('/api/load-plugin', 
                                         json={"filename": filename},
                                         headers={'Authorization': 'Bearer test-token'})
                    assert response.status_code == 400


def test_load_plugin_file_not_found():
    """测试加载插件时文件不存在（行 439-440）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    with app.test_client() as client:
        with patch('server.src.server._serializer') as mock_serializer:
            mock_serializer.return_value.loads.return_value = {
                "uid": 1, 
                "login": "testuser", 
                "email": "a@b.com"
            }
            
            # 模拟文件不存在
            with tempfile.TemporaryDirectory() as temp_dir:
                with patch('server.src.server.app.config') as mock_config:
                    mock_config.get.return_value = Path(temp_dir)
                    
                    response = client.post('/api/load-plugin', 
                                         json={"filename": "nonexistent.pkl"},
                                         headers={'Authorization': 'Bearer test-token'})
                    assert response.status_code == 404


def test_load_plugin_file_empty():
    """测试加载插件时文件为空（行 443）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # 创建空文件
        empty_file = Path(temp_dir) / "empty.pkl"
        empty_file.touch()
        
        with patch('server.src.server.app.config') as mock_config:
            mock_config.get.return_value = Path(temp_dir)
            
            with app.test_client() as client:
                with patch('server.src.server._serializer') as mock_serializer:
                    mock_serializer.return_value.loads.return_value = {
                        "uid": 1, 
                        "login": "testuser", 
                        "email": "a@b.com"
                    }
                    
                    response = client.post('/api/load-plugin', 
                                         json={"filename": "empty.pkl"},
                                         headers={'Authorization': 'Bearer test-token'})
                    # 空文件应该返回 400
                    assert response.status_code == 400


def test_load_plugin_file_too_large():
    """测试加载插件时文件太大（行 448-449）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # 创建大文件（超过 10MB）
        large_file = Path(temp_dir) / "large.pkl"
        # 写入 11MB 的数据
        with open(large_file, 'wb') as f:
            f.write(b'x' * (11 * 1024 * 1024))
        
        with patch('server.src.server.app.config') as mock_config:
            mock_config.get.return_value = Path(temp_dir)
            
            with app.test_client() as client:
                with patch('server.src.server._serializer') as mock_serializer:
                    mock_serializer.return_value.loads.return_value = {
                        "uid": 1, 
                        "login": "testuser", 
                        "email": "a@b.com"
                    }
                    
                    response = client.post('/api/load-plugin', 
                                         json={"filename": "large.pkl"},
                                         headers={'Authorization': 'Bearer test-token'})
                    # 文件太大应该返回 400
                    assert response.status_code == 400


def test_load_plugin_malformed_file():
    """测试加载插件时文件格式错误（行 451）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # 创建无效的 pickle 文件
        bad_file = Path(temp_dir) / "bad.pkl"
        with open(bad_file, 'wb') as f:
            f.write(b'invalid pickle data')
        
        with patch('server.src.server.app.config') as mock_config:
            mock_config.get.return_value = Path(temp_dir)
            
            with app.test_client() as client:
                with patch('server.src.server._serializer') as mock_serializer:
                    mock_serializer.return_value.loads.return_value = {
                        "uid": 1, 
                        "login": "testuser", 
                        "email": "a@b.com"
                    }
                    
                    response = client.post('/api/load-plugin', 
                                         json={"filename": "bad.pkl"},
                                         headers={'Authorization': 'Bearer test-token'})
                    # 格式错误的文件应该返回 400
                    assert response.status_code == 400


def test_load_plugin_invalid_object_type():
    """测试加载插件时对象类型无效（行 477-478）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # 创建包含无效对象的 pickle 文件
        bad_file = Path(temp_dir) / "invalid.pkl"
        
        # 创建一个不是类也不是 WatermarkingMethod 的对象
        invalid_obj = {"not": "a class"}
        
        import pickle
        with open(bad_file, 'wb') as f:
            pickle.dump(invalid_obj, f)
        
        with patch('server.src.server.app.config') as mock_config:
            mock_config.get.return_value = Path(temp_dir)
            
            with app.test_client() as client:
                with patch('server.src.server._serializer') as mock_serializer:
                    mock_serializer.return_value.loads.return_value = {
                        "uid": 1, 
                        "login": "testuser", 
                        "email": "a@b.com"
                    }
                    
                    response = client.post('/api/load-plugin', 
                                         json={"filename": "invalid.pkl"},
                                         headers={'Authorization': 'Bearer test-token'})
                    # 无效对象应该返回 400
                    assert response.status_code == 400


if __name__ == '__main__':
    pytest.main([__file__, '-v'])


# 继续在 test_server_specific_coverage.py 中添加

def test_create_watermark_database_error_handling():
    """测试创建水印时的数据库错误处理（行 630-671）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    with patch('server.src.server.get_engine') as mock_engine:
        mock_conn = MagicMock()
        mock_row = MagicMock()
        mock_row.id = 1
        mock_row.name = "test.pdf"
        mock_row.path = "/tmp/test.pdf"
        mock_conn.execute.return_value.first.return_value = mock_row
        mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
        
        # Mock 适用性检查和应用成功
        with patch('server.src.server.WMUtils.is_watermarking_applicable') as mock_check:
            mock_check.return_value = True
            
            with patch('server.src.server.WMUtils.apply_watermark') as mock_apply:
                mock_apply.return_value = b'watermarked content'
                
                # Mock 文件写入成功
                with patch('builtins.open', mock_open()) as mock_file:
                    # Mock 数据库插入抛出 IntegrityError
                    from sqlalchemy.exc import IntegrityError
                    error = IntegrityError("statement", "params", "orig")
                    error.orig = Exception("Duplicate entry uq_Versions_link")
                    
                    mock_engine.return_value.begin.return_value.__enter__.return_value.execute.side_effect = error
                    
                    # Mock 第二次查询返回 existing row
                    mock_existing_row = MagicMock()
                    mock_existing_row.id = 999
                    mock_engine.return_value.connect.return_value.__enter__.return_value.execute.return_value.first.return_value = mock_existing_row
                    
                    with app.test_client() as client:
                        with patch('server.src.server._serializer') as mock_serializer:
                            mock_serializer.return_value.loads.return_value = {
                                "uid": 1, 
                                "login": "testuser", 
                                "email": "a@b.com"
                            }
                            
                            response = client.post('/api/create-watermark/1', 
                                                 json={
                                                     "method": "test-method",
                                                     "intended_for": "someone",
                                                     "secret": "secret",
                                                     "key": "key"
                                                 },
                                                 headers={'Authorization': 'Bearer test-token'})
                            # 即使有 IntegrityError，如果找到现有行应该返回 201
                            assert response.status_code == 201


def test_load_plugin_suspicious_class_name():
    """测试加载插件时类名可疑（行 486-487）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    # 创建包含可疑类名的插件
    import pickle
    
    class SuspiciousClass:
        name = "suspicious"
    
    SuspiciousClass.__name__ = "SystemExploit"
    
    with tempfile.TemporaryDirectory() as temp_dir:
        suspicious_file = Path(temp_dir) / "suspicious.pkl"
        with open(suspicious_file, 'wb') as f:
            pickle.dump(SuspiciousClass, f)
        
        with patch('server.src.server.app.config') as mock_config:
            mock_config.get.return_value = Path(temp_dir)
            
            with app.test_client() as client:
                with patch('server.src.server._serializer') as mock_serializer:
                    mock_serializer.return_value.loads.return_value = {
                        "uid": 1, 
                        "login": "testuser", 
                        "email": "a@b.com"
                    }
                    
                    response = client.post('/api/load-plugin', 
                                         json={"filename": "suspicious.pkl"},
                                         headers={'Authorization': 'Bearer test-token'})
                    # 可疑类名应该返回 400
                    assert response.status_code == 400


def test_load_plugin_missing_api_methods():
    """测试加载插件时缺少必要的 API 方法（行 501）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    # 创建缺少必要方法的类
    import pickle
    
    class IncompleteClass:
        name = "incomplete"
        # 缺少 add_watermark 和 read_secret 方法
    
    with tempfile.TemporaryDirectory() as temp_dir:
        incomplete_file = Path(temp_dir) / "incomplete.pkl"
        with open(incomplete_file, 'wb') as f:
            pickle.dump(IncompleteClass, f)
        
        with patch('server.src.server.app.config') as mock_config:
            mock_config.get.return_value = Path(temp_dir)
            
            with app.test_client() as client:
                with patch('server.src.server._serializer') as mock_serializer:
                    mock_serializer.return_value.loads.return_value = {
                        "uid": 1, 
                        "login": "testuser", 
                        "email": "a@b.com"
                    }
                    
                    response = client.post('/api/load-plugin', 
                                         json={"filename": "incomplete.pkl"},
                                         headers={'Authorization': 'Bearer test-token'})
                    # 缺少必要方法应该返回 400
                    assert response.status_code == 400


def test_load_plugin_method_already_exists():
    """测试加载插件时方法已存在（行 511-512）"""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    })
    
    # 创建有效的插件类
    import pickle
    
    class ValidPlugin:
        name = "existing_method"
        
        def add_watermark(self, *args, **kwargs):
            return b"watermarked"
        
        def read_secret(self, *args, **kwargs):
            return "secret"
    
    with tempfile.TemporaryDirectory() as temp_dir:
        plugin_file = Path(temp_dir) / "plugin.pkl"
        with open(plugin_file, 'wb') as f:
            pickle.dump(ValidPlugin, f)
        
        with patch('server.src.server.app.config') as mock_config:
            mock_config.get.return_value = Path(temp_dir)
            
            # 首先添加方法到 WMUtils.METHODS
            from server.src import watermarking_utils as WMUtils
            original_methods = WMUtils.METHODS.copy()
            WMUtils.METHODS["existing_method"] = ValidPlugin()
            
            try:
                with app.test_client() as client:
                    with patch('server.src.server._serializer') as mock_serializer:
                        mock_serializer.return_value.loads.return_value = {
                            "uid": 1, 
                            "login": "testuser", 
                            "email": "a@b.com"
                        }
                        
                        # 测试不覆盖的情况
                        response = client.post('/api/load-plugin', 
                                             json={"filename": "plugin.pkl", "overwrite": False},
                                             headers={'Authorization': 'Bearer test-token'})
                        # 方法已存在且不覆盖应该返回 409
                        assert response.status_code == 409
                        
                        # 测试覆盖的情况
                        response = client.post('/api/load-plugin', 
                                             json={"filename": "plugin.pkl", "overwrite": True},
                                             headers={'Authorization': 'Bearer test-token'})
                        # 允许覆盖应该成功
                        assert response.status_code == 201
            finally:
                # 恢复原始方法
                WMUtils.METHODS = original_methods