import tempfile
import pytest 



def test_safe_resolve_under_storage():
    """测试路径安全解析功能"""
    from server.src.server import _safe_resolve_under_storage
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

def test_upload_document_file_validation(mocker):
    """测试文件上传的验证逻辑"""
    # 这个测试会覆盖很多文件验证相关的变异
    from server.src.server import create_app
    import io

    app = create_app()
    
    with app.test_client() as client:
        
        # **重要：Mock 身份验证**
        # 模拟 Token 被成功解析，并设置 Flask 的全局 g.user 对象
        # 我们需要 Mock 装饰器内部使用的 _serializer.loads 方法
        
        mock_serializer = mocker.patch('server.src.server._serializer')
        # 模拟 loads 方法返回一个有效的用户字典
        mock_serializer.return_value.loads.return_value = {"uid": 1, "login": "testuser", "email": "a@b.com"}
        
        # 测试非PDF文件
        response = client.post('/api/upload-document',
                             data={'file': (io.BytesIO(b'not a pdf'), 'test.txt')},
                             headers={'Authorization': 'Bearer test-token'})
        # 现在身份验证会成功，并继续执行文件类型检查，应该返回 400
        assert response.status_code == 400
        
        # 测试空文件
        response = client.post('/api/upload-document',
                             data={'file': (io.BytesIO(b''), 'empty.pdf')},
                             headers={'Authorization': 'Bearer test-token'})
        assert response.status_code == 400