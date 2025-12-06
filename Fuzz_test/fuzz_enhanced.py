#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tatou 增强版 Fuzz 测试工具
"""
import argparse
import json
import random
import sys
import time
import requests
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_TIMEOUT = 5.0
USER_AGENT = "TatouFuzzer/2.0"

PAYLOADS = {
    "int": [-1, 0, 1, 999999999999999, "1", None, {}, []],
    "str": ["", "a" * 10000, "<script>alert(1)</script>", "' OR '1'='1", None],
    "email": ["bad-email", "@example.com", "a" * 255 + "@example.com"],
    "base64": ["!!!!", "NotBase64", "VGhpcyBpcyBhIHRlc3Q"],
    "json": ["{", "}", "null", 1]
}

def log(msg: str, color: str = "white"):
    print(msg)

def save_crash_report(endpoint: str, method: str, payload: Any, response: requests.Response, out_dir: Path):
    timestamp = int(time.time())
    filename = f"crash_{timestamp}_{random.randint(1000, 9999)}.json"
    report = {
        "endpoint": endpoint,
        "method": method,
        "payload": payload,
        "status_code": response.status_code,
        "response_text": response.text[:2000]
    }
    with open(out_dir / filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    log(f"[CRASH] Report saved: {filename}", "red")

class TatouFuzzer:
    def __init__(self, base_url: str, out_dir: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.token = None
        self.doc_id = None

    def authenticate(self, email: str, password: str):
        try:
            self.session.post(f"{self.base_url}/api/create-user", json={"login": f"fuzz_{int(time.time())}", "email": email, "password": password}, timeout=DEFAULT_TIMEOUT)
        except Exception: pass

        try:
            res = self.session.post(f"{self.base_url}/api/login", json={"email": email, "password": password}, timeout=DEFAULT_TIMEOUT)
            if res.status_code == 200:
                self.token = res.json().get("token")
                self.session.headers.update({"Authorization": f"Bearer {self.token}"})
                log(f"[AUTH] Success: {email}", "green")
            else:
                log(f"[AUTH] Failed: {res.status_code}", "red")
                sys.exit(1)
        except Exception as e:
            log(f"[AUTH] Error: {e}", "red")
            sys.exit(1)

    def upload_seed_file(self, file_path: str):
        if not file_path or not Path(file_path).exists(): return
        try:
            with open(file_path, "rb") as f:
                res = self.session.post(f"{self.base_url}/api/upload-document", files={"file": ("seed.pdf", f, "application/pdf")}, data={"name": "fuzz_seed"})
                if res.status_code == 201:
                    self.doc_id = res.json().get("id")
                    log(f"[SETUP] Uploaded ID: {self.doc_id}", "green")
        except Exception: pass

    def _mutate_dict(self, base_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        mutated_list = []
        for key, value in base_data.items():
            p_type = "email" if "email" in key else ("int" if isinstance(value, int) else "str")
            for payload in PAYLOADS.get(p_type, PAYLOADS["str"]):
                new_data = base_data.copy()
                new_data[key] = payload
                mutated_list.append(new_data)
        return mutated_list

    def fuzz_endpoint(self, method: str, path: str, base_data: Optional[Dict] = None):
        target_url = f"{self.base_url}{path}".replace("{document_id}", str(self.doc_id or 1))
        requests_to_send = [{"json": m} for m in self._mutate_dict(base_data)] if base_data else [{}]

        log(f"--> Fuzzing {method} {path}", "blue")
        for req in requests_to_send:
            try:
                res = self.session.request(method, target_url, timeout=DEFAULT_TIMEOUT, **req)
                if res.status_code >= 500:
                    log(f"  !! BUG (5xx): {method} {target_url} -> {res.status_code}", "red")
                    save_crash_report(path, method, req.get("json"), res, self.out_dir)
            except Exception: pass

    def run(self):
        self.fuzz_endpoint("POST", "/api/create-user", {"login": "fuzzer", "password": "pwd", "email": "f@e.com"})
        self.fuzz_endpoint("POST", "/api/login", {"email": "f@e.com", "password": "pwd"})
        if self.doc_id:
            self.fuzz_endpoint("DELETE", "/api/delete-document", {"document_id": self.doc_id})
            self.fuzz_endpoint("POST", f"/api/create-watermark/{self.doc_id}", {"method": "trailer-hmac", "key": "k", "secret": "s", "intended_for": "u"})

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:5000")
    parser.add_argument("--file", default="test.pdf")
    parser.add_argument("--out", default="fuzz_reports")
    args = parser.parse_args()

    fuzzer = TatouFuzzer(args.url, args.out)
    fuzzer.authenticate("fuzzer@example.com", "Pwd123!")
    fuzzer.upload_seed_file(args.file)
    fuzzer.run()
