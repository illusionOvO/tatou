import pytest
import tempfile
import os
from pathlib import Path
from unittest import mock
import re


class TestFileOperations:
    """测试文件操作相关的功能"""
    
    def test_sha256_file_with_different_chunk_sizes(self):
        """测试不同块大小对SHA256计算的影响"""
        from server.src.server import _sha256_file
        
        # 创建测试文件
        test_content = b"x" * (3 * 1024 * 1024)  # 3MB数据
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(test_content)
            temp_path = Path(f.name)
        
        try:
            # 计算原始哈希
            original_hash = _sha256_file(temp_path)
            
            # 验证哈希正确性
            import hashlib
            expected_hash = hashlib.sha256(test_content).hexdigest()
            assert original_hash == expected_hash
            
        finally:
            os.unlink(temp_path)
    
    def test_sha256_file_empty(self):
        """测试空文件的SHA256计算"""
        from server.src.server import _sha256_file
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = Path(f.name)
        
        try:
            empty_hash = _sha256_file(temp_path)
            import hashlib
            expected_empty_hash = hashlib.sha256(b"").hexdigest()
            assert empty_hash == expected_empty_hash
        finally:
            os.unlink(temp_path)
    
    def test_sha256_file_nonexistent(self):
        """测试不存在的文件路径"""
        from server.src.server import _sha256_file
        
        with pytest.raises(Exception):  # 应该抛出异常
            _sha256_file(Path("/nonexistent/path/file.pdf"))

    
    @pytest.mark.timeout(3) # <-- 1. 添加超时标记
    def test_upload_document_sha256_timeout(self, client, mocker, sample_pdf_path): 
        """
        测试 /api/upload-document 路由，并增强 SHA256 验证。
        如果 Mutant 355 被植入，此测试将因超时而失败 (Killed)。
        """
        from server.src.server import _serializer
        
        # 0. 确保 sample_pdf_path 是一个文件
        if not sample_pdf_path.exists():
             sample_pdf_path.write_bytes(b"%PDF-1.4\n% Sample Document\n%%EOF\n")

        # 1. Mock 认证成功 (解决未认证问题)
        mock_serializer = mocker.patch('server.src.server._serializer')
        mock_serializer.return_value.loads.return_value = {"uid": 1, "login": "testuser", "email": "a@b.com"}

        # 2. 准备请求数据
        data = {
            'file': (open(sample_pdf_path, 'rb'), 'test_doc.pdf'),
            'name': 'Test Document'
        }
        
        # 3. 运行请求
        # client 是通过 test_upload_document_sha256_timeout(self, client, ...) 传入的
        with client.application.app_context():
             response = client.post(
                '/api/upload-document',
                data=data,
                content_type='multipart/form-data',
                headers={'Authorization': 'Bearer valid-token'}
            )

        # 4. 增强断言
        assert response.status_code == 201
        
        # 确保返回的 JSON 包含 sha256 字段
        response_data = response.get_json()
        assert "sha256" in response_data, "响应中缺少 sha256 字段"
        
        sha_value = response_data["sha256"]
        
        # 增强断言：检查 SHA256 长度和格式
        assert len(sha_value) == 64, "SHA256 长度应为 64"
        assert re.match(r'^[0-9a-fA-F]{64}$', sha_value), "SHA256 必须是有效的十六进制字符串"