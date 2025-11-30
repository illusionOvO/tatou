import pytest
import tempfile
import os
from pathlib import Path

def test_sha256_file_calculation():
    """测试文件SHA256计算是否正确"""
    from server.src.server import _sha256_file
    import hashlib
    
    # 创建测试文件
    with tempfile.NamedTemporaryFile(delete=False) as f:
        test_content = b"test content for sha256 calculation"
        f.write(test_content)
        temp_path = Path(f.name)
    
    try:
        # 计算SHA256
        calculated_hash = _sha256_file(temp_path)
        
        # 验证结果
        expected_hash = hashlib.sha256(test_content).hexdigest()
        assert calculated_hash == expected_hash
        
        # 测试空文件
        with tempfile.NamedTemporaryFile(delete=False) as f:
            empty_path = Path(f.name)
        empty_hash = _sha256_file(empty_path)
        expected_empty_hash = hashlib.sha256(b"").hexdigest()
        assert empty_hash == expected_empty_hash
        os.unlink(empty_path)
        
    finally:
        os.unlink(temp_path)

def test_sha256_file_large_file():
    """测试大文件的SHA256计算"""
    from server.src.server import _sha256_file
    import hashlib
    
    # 创建稍大的测试文件（超过1MB）
    with tempfile.NamedTemporaryFile(delete=False) as f:
        # 生成2MB的测试数据
        test_content = b"x" * (2 * 1024 * 1024)
        f.write(test_content)
        temp_path = Path(f.name)
    
    try:
        calculated_hash = _sha256_file(temp_path)
        expected_hash = hashlib.sha256(test_content).hexdigest()
        assert calculated_hash == expected_hash
    finally:
        os.unlink(temp_path)