import pytest
import sys
from unittest import mock

def test_pickle_fallback_when_dill_fails():
    """测试当 dill 导入失败时，回退到标准 pickle"""
    
    # 保存原始的 dill 模块
    original_dill = sys.modules.get('dill')
    
    # 模拟 dill 导入失败
    with mock.patch.dict('sys.modules', {'dill': None}):
        # 重新导入 server 模块以触发回退逻辑
        if 'server.src.server' in sys.modules:
            del sys.modules['server.src.server']
        
        # 重新导入，这会触发 dill 导入失败的回退
        from server.src.server import _pickle, _std_pickle
        
        # 验证回退到了标准 pickle
        assert _pickle is _std_pickle, "当 dill 导入失败时，应该回退到标准 pickle"
    
    # 恢复 dill 模块
    if original_dill:
        sys.modules['dill'] = original_dill

def test_pickle_fallback_functionality():
    """测试回退后的 pickle 功能是否正常"""
    
    # 模拟 dill 导入失败
    with mock.patch.dict('sys.modules', {'dill': None}):
        # 重新导入 server 模块
        if 'server.src.server' in sys.modules:
            del sys.modules['server.src.server']
        
        from server.src.server import _pickle
        
        # 测试 pickle 基本功能
        test_data = {"key": "value", "number": 42}
        
        # 序列化
        serialized = _pickle.dumps(test_data)
        assert serialized is not None
        
        # 反序列化
        deserialized = _pickle.loads(serialized)
        assert deserialized == test_data