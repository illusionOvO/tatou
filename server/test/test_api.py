import sys
from pathlib import Path

# 把 "server" 这个目录加到 Python 搜索路径里
ROOT = Path(__file__).resolve().parents[1]   # ...\tatou\server
sys.path.insert(0, str(ROOT))


from src.server import app


def test_healthz_route():
    client = app.test_client()
    resp = client.get("/healthz")

    assert resp.status_code == 200
    assert resp.is_json
    

# test get_watermarking_methods
def test_get_watermarking_methods():
    client = app.test_client()
    resp = client.get("/api/get-watermarking-methods")

    # 1. HTTP 层：应该 200 且是 JSON
    assert resp.status_code == 200
    assert resp.is_json

    data = resp.get_json()

    # 2. 结构检查：必须有 methods 和 count
    assert "methods" in data
    assert "count" in data

    assert isinstance(data["methods"], list)
    assert isinstance(data["count"], int)

    # 3. count 应该等于列表长度（防止实现偷懒写死）
    assert data["count"] == len(data["methods"])

    # 4. 如果有方法的话，每个元素至少有 name / description 字段
    if data["methods"]:
        first = data["methods"][0]
        assert "name" in first
        assert "description" in first