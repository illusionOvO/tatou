# test/test_api_basic.py
import os, requests

BASE = os.environ.get("TATOU_BASE", "http://localhost:5000")

def _signup(email, login, password="Passw0rd!"):
    r = requests.post(f"{BASE}/api/create-user",
                      json={"email": email, "login": login, "password": password})
    assert r.status_code in (201, 409)  # 已存在也允许
    return True

def _login(email, password="Passw0rd!"):
    r = requests.post(f"{BASE}/api/login", json={"email": email, "password": password})
    assert r.status_code == 200
    return r.json()["token"]

def test_healthz_ok():
    r = requests.get(f"{BASE}/healthz")
    assert r.status_code == 200
    assert "message" in r.json()

def test_auth_required_endpoints():
    # 这些端点需要登录（作业要求：只影响已鉴权用户自己的数据）
    # list-documents
    r = requests.get(f"{BASE}/api/list-documents")
    assert r.status_code == 401

def test_owner_isolation_and_leaks(tmp_path):
    # 注册两个用户
    _signup("a@example.com", "alice")
    _signup("b@example.com", "bob")
    tok_a = _login("a@example.com")
    tok_b = _login("b@example.com")

    # A 上传一个最小 PDF
    pdf = tmp_path / "x.pdf"
    pdf.write_bytes(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n")
    with open(pdf, "rb") as f:
        r = requests.post(f"{BASE}/api/upload-document",
                          headers={"Authorization": f"Bearer {tok_a}"},
                          files={"file": ("x.pdf", f, "application/pdf")})
    assert r.status_code == 201
    doc_id = r.json()["id"]

    # B 不应能读/删 A 的文档
    r = requests.get(f"{BASE}/api/get-document/{doc_id}",
                     headers={"Authorization": f"Bearer {tok_b}"})
    assert r.status_code in (403, 404)  # 你的实现用 404 也可

    # list-versions 不应泄露 secret（按规范你应移除 secret）
    r = requests.get(f"{BASE}/api/list-versions/{doc_id}",
                     headers={"Authorization": f"Bearer {tok_a}"})
    assert r.status_code == 200
    assert all("secret" not in v for v in r.json().get("versions", []))

def test_delete_document_requires_auth_and_paramized():
    # 未登录不应能删
    r = requests.delete(f"{BASE}/api/delete-document/1")
    assert r.status_code == 401

    # SQL 注入 payload 应该被拒绝（修复后会 400）
    r = requests.delete(f"{BASE}/api/delete-document",
                        params={"id": "1 OR 1=1"})
    assert r.status_code in (400, 401)
