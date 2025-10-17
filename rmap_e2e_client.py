import json, base64, secrets, requests
from pgpy import PGPKey, PGPMessage

SERVER_URL = "http://127.0.0.1:5000"     # 服务器就在本机
GROUP_NAME = "Group_18"

SERVER_PUB = r"client_keys/server_pub.asc"
CLIENT_PRIV = r"client_keys/Group_18_priv.asc"

srv_pub, _ = PGPKey.from_file(SERVER_PUB)
cli_priv, _ = PGPKey.from_file(CLIENT_PRIV)

def pgp_to_b64(msg):
    return base64.b64encode(bytes(msg)).decode()

def pgp_from_b64(b64):
    return PGPMessage.from_blob(base64.b64decode(b64))

# === Step 1: 发起握手 ===
nonce_client = secrets.randbits(64)
plain1 = json.dumps({"identity": GROUP_NAME, "nonceClient": nonce_client})
enc1 = srv_pub.encrypt(PGPMessage.new(plain1))
payload1 = pgp_to_b64(enc1)
resp1_raw = requests.post(f"{SERVER_URL}/rmap-initiate", json={"payload": payload1}, timeout=20)
print("[DEBUG] /rmap-initiate status:", resp1_raw.status_code)
print("[DEBUG] /rmap-initiate body  :", resp1_raw.text)  # 关键：看到服务器具体错误
resp1 = resp1_raw.json()
pgp_resp1 = pgp_from_b64(resp1["payload"])


# === Step 2: 处理响应 ===
pgp_resp1 = pgp_from_b64(resp1["payload"])
plain_resp1 = cli_priv.decrypt(pgp_resp1).message
if isinstance(plain_resp1, (bytes, bytearray)):
    plain_resp1 = plain_resp1.decode()
obj1 = json.loads(plain_resp1)
assert obj1["nonceClient"] == nonce_client
nonce_server = obj1["nonceServer"]
print("[OK] rmap-initiate success")

# === Step 3: 生成第二条消息 ===
plain2 = json.dumps({"nonceServer": nonce_server})
enc2 = srv_pub.encrypt(PGPMessage.new(plain2))
payload2 = pgp_to_b64(enc2)
resp2 = requests.post(f"{SERVER_URL}/rmap-get-link", json={"payload": payload2}).json()
print("[OK] rmap-get-link:", resp2)
