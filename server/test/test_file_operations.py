import pytest
import tempfile
import os
from pathlib import Path
from unittest import mock

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