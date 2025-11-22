#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tatou 增强版 Fuzz 测试工具
功能：自动鉴权、文件上传初始化、针对性变异测试、异常捕获报告。
"""

import argparse
import json
import random
import sys
import time
import requests
import string
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Callable

# =================配置区域=================
DEFAULT_TIMEOUT = 5.0
USER_AGENT = "TatouFuzzer/2.0"

# 攻击载荷库 (Payloads)
PAYLOADS = {
    "int": [
        -1, 0, 1, 999999999999999, -2147483648, 2147483647, 
        "1", "1.0", None, True, False, {}, []
    ],
    "str": [
        "", "a" * 10000,  # 超长字符串
        "<script>alert(1)</script>",  # XSS
        "' OR '1'='1",  # SQLi
        "admin@example.com", 
        "\x00",  # Null byte
        "🔥" * 50,  # Unicode
        "../../../../etc/passwd",  # Path Traversal
        None, 123, {}
    ],
    "email": [
        "bad-email", "@example.com", "user@", "user@.com", 
        "a" * 255 + "@example.com", "' OR 1=1"
    ],
    "base64": [
        "!!!!", "NotBase64", "VGhpcyBpcyBhIHRlc3Q=", 
        "VGhpcyBpcyBhIHRlc3Q"  # 缺少 padding
    ],
    "json": [
        "{", "}", "[", "]", "null", 1, "string" # 破坏 JSON 结构
    ]
}

# =================辅助函数=================

def log(msg: str, color: str = "white"):
    colors = {
        "green": "\033[92m", "red": "\033[91m", 
        "yellow": "\033[93m", "blue": "\033[94m", "white": "\033[0m"
    }
    print(f"{colors.get(color, '')}{msg}\033[0m")

def save_crash_report(endpoint: str, method: str, payload: Any, response: requests.Response, out_dir: Path):
    """保存 500 错误现场"""
    timestamp = int(time.time())
    filename = f"crash_{timestamp}_{random.randint(1000,9999)}.json"
    report = {
        "endpoint": endpoint,
        "method": method,
        "payload": payload,
        "status_code": response.status_code,
        "response_text": response.text[:2000]  # 截断防止过大
    }
    with open(out_dir / filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    log(f"[CRASH] 报告已保存: {filename}", "red")

# =================核心类=================

class TatouFuzzer:
    def __init__(self, base_url: str, out_dir: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.token = None
        self.doc_id = None  # 初始化上传后获取
        self.valid_version_link = "0000000000000000000000000000000000000000" # 伪造的

    def authenticate(self, email: str, password: str):
        """先尝试注册，再登录获取 Token"""
        # 1. 尝试注册 (忽略 409 冲突)
        reg_data = {"login": f"fuzz_{int(time.time())}", "email": email, "password": password}
        try:
            self.session.post(f"{self.base_url}/api/create-user", json=reg_data, timeout=DEFAULT_TIMEOUT)
        except Exception:
            pass

        # 2. 登录
        try:
            res = self.session.post(f"{self.base_url}/api/login", json={"email": email, "password": password}, timeout=DEFAULT_TIMEOUT)
            if res.status_code == 200:
                data = res.json()
                self.token = data.get("token")
                self.session.headers.update({"Authorization": f"Bearer {self.token}"})
                log(f"[AUTH] 登录成功: {email}", "green")
            else:
                log(f"[AUTH] 登录失败: {res.status_code} {res.text}", "red")
                sys.exit(1)
        except Exception as e:
            log(f"[AUTH] 连接异常: {e}", "red")
            sys.exit(1)

    def upload_seed_file(self, file_path: str):
        """上传种子文件以获取 document_id 用于后续测试"""
        if not file_path or not Path(file_path).exists():
            log("[SETUP] 未提供 PDF 文件或文件不存在，跳过文档相关 Fuzz", "yellow")
            return

        try:
            with open(file_path, "rb") as f:
                files = {"file": ("seed.pdf", f, "application/pdf")}
                res = self.session.post(f"{self.base_url}/api/upload-document", files=files, data={"name": "fuzz_seed"})
                if res.status_code == 201:
                    self.doc_id = res.json().get("id")
                    log(f"[SETUP] 文件上传成功 ID: {self.doc_id}", "green")
                else:
                    log(f"[SETUP] 文件上传失败: {res.text}", "red")
        except Exception as e:
            log(f"[SETUP] 上传异常: {e}", "red")

    def _mutate_dict(self, base_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """生成变异字典列表"""
        mutated_list = []
        
        # 1. 针对每个字段进行类型变异
        for key, value in base_data.items():
            # 确定类型
            if "email" in key: p_type = "email"
            elif isinstance(value, int): p_type = "int"
            elif isinstance(value, str): p_type = "str"
            else: p_type = "str"
            
            for payload in PAYLOADS[p_type]:
                new_data = base_data.copy()
                new_data[key] = payload
                mutated_list.append(new_data)
        
        # 2. 随机删除字段
        if base_data:
            for key in base_data.keys():
                new_data = base_data.copy()
                del new_data[key]
                mutated_list.append(new_data)
                
        return mutated_list

    def fuzz_endpoint(self, method: str, path: str, base_data: Optional[Dict] = None, url_params: Optional[Dict] = None):
        """核心 Fuzz 逻辑"""
        target_url = f"{self.base_url}{path}"
        
        # 替换 URL 路径参数
        if "{document_id}" in target_url:
            target_url = target_url.replace("{document_id}", str(self.doc_id if self.doc_id else 99999))
        if "{link}" in target_url:
            target_url = target_url.replace("{link}", self.valid_version_link)

        # 生成请求列表
        requests_to_send = []
        
        # 情况 A: 有 JSON Body
        if base_data:
            mutations = self._mutate_dict(base_data)
            for m in mutations:
                requests_to_send.append({"json": m, "params": url_params})
        # 情况 B: 只有 URL 参数 (GET/DELETE)
        elif url_params:
            # 简单变异 URL 参数
            # 这里简化处理，仅测试空值和坏值
            requests_to_send.append({"params": url_params}) 
        # 情况 C: 无参数 (只测 Auth 头缺失等，这里简化略过)
        else:
            requests_to_send.append({})

        log(f"--> Fuzzing {method} {path} ({len(requests_to_send)} mutations)", "blue")

        for req_kwargs in requests_to_send:
            try:
                # 发送请求
                res = self.session.request(method, target_url, timeout=DEFAULT_TIMEOUT, **req_kwargs)
                
                # 结果分析
                if res.status_code >= 500:
                    log(f"  !! 发现 BUG (5xx): {method} {target_url} -> {res.status_code}", "red")
                    save_crash_report(path, method, req_kwargs.get("json"), res, self.out_dir)
                elif res.status_code == 404:
                    pass # 忽略 404
                elif res.status_code == 401:
                    # 如果带了 Token 还 401 也是个问题，除非是测 Logout
                    pass
                elif res.status_code < 500:
                    # 200/400 都是预期内行为
                    pass
                    
            except Exception as e:
                log(f"  !! 网络异常: {e}", "yellow")

    def run(self):
        """定义所有 API 的基准数据并开始测试"""
        
        # 1. 用户相关
        self.fuzz_endpoint("POST", "/api/create-user", {
            "login": "fuzzer", "password": "pwd", "email": "f@e.com"
        })
        self.fuzz_endpoint("POST", "/api/login", {
            "email": "f@e.com", "password": "pwd"
        })

        # 2. 文档相关
        self.fuzz_endpoint("GET", "/api/list-documents")
        if self.doc_id:
            self.fuzz_endpoint("GET", "/api/get-document/{document_id}")
            self.fuzz_endpoint("DELETE", "/api/delete-document/{document_id}")
            # 同时也测 JSON body 形式的 delete
            self.fuzz_endpoint("DELETE", "/api/delete-document", base_data={"document_id": self.doc_id})

        # 3. 水印相关
        self.fuzz_endpoint("GET", "/api/get-watermarking-methods")
        
        wm_body = {
            "method": "trailer-hmac",
            "key": "secretkey",
            "secret": "mysecret",
            "intended_for": "buyer",
            "position": "eof"
        }
        if self.doc_id:
            self.fuzz_endpoint("POST", f"/api/create-watermark/{self.doc_id}", wm_body)
            # 同时也测 body 中带 id 的情况
            wm_body_with_id = wm_body.copy()
            wm_body_with_id["id"] = self.doc_id
            self.fuzz_endpoint("POST", "/api/create-watermark", wm_body_with_id)

            # 读取水印
            read_body = {"method": "trailer-hmac", "key": "secretkey"}
            self.fuzz_endpoint("POST", f"/api/read-watermark/{self.doc_id}", read_body)

        # 4. 版本列表
        self.fuzz_endpoint("GET", "/api/list-all-versions")
        if self.doc_id:
            self.fuzz_endpoint("GET", f"/api/list-versions/{self.doc_id}")

        # 5. RMAP 协议 (ASCII Armor / Base64)
        rmap_payload = {"payload": "VGhpcyBpcyBhIHRlc3Q="} # "This is a test"
        self.fuzz_endpoint("POST", "/api/rmap-initiate", rmap_payload)
        self.fuzz_endpoint("POST", "/api/rmap-get-link", rmap_payload)

        # 6. 全局健康检查
        self.fuzz_endpoint("GET", "/healthz")


# =================入口=================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tatou Enhanced Fuzzer")
    parser.add_argument("--url", default="http://127.0.0.1:5000", help="Target URL")
    parser.add_argument("--email", default="fuzzer@example.com", help="Auth Email")
    parser.add_argument("--pwd", default="FuzzPass123!", help="Auth Password")
    parser.add_argument("--file", default="test.pdf", help="Seed PDF file path")
    parser.add_argument("--out", default="fuzz_reports", help="Output directory for crash reports")
    
    args = parser.parse_args()
    
    print(f"🔥 Starting Tatou Fuzzer against {args.url}")
    fuzzer = TatouFuzzer(args.url, args.out)
    
    # 1. 认证
    fuzzer.authenticate(args.email, args.pwd)
    
    # 2. 上传种子文件
    fuzzer.upload_seed_file(args.file)
    
    # 3. 开始测试
    try:
        fuzzer.run()
        print("\n✅ Fuzzing Complete. Check output directory for crash reports.")
    except KeyboardInterrupt:
        print("\n🛑 Fuzzing Interrupted.")
