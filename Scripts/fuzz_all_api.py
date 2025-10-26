#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fuzz_all_api.py — 自动登录 + 可选文件上传（拿到 document_id 后继续 fuzz）
示例：
  # 自动注册+登录 + 先上传 ./test.pdf，再跑（并做无鉴权对比）
  python fuzz_all_api.py --base-url http://127.0.0.1:5000 --auto-signup \
      --login-email fuzzer@example.local --login-password P@ssw0rd! \
      --file ./test.pdf --iter 1 --also-noauth

  # 已有 token 直接跑（仍会先上传）
  python fuzz_all_api.py --base-url http://127.0.0.1:5000 \
      --token "YOUR_TOKEN" --file ./test.pdf --iter 1

输出：
  <out>/report.log           # JSONL，每行一条记录，末尾 SUMMARY 与 HTML 索引
  <out>/htmlcov/index.html   # HTML 报告（红色高亮 5xx / 异常）
"""

import argparse, json, random, sys, time, uuid, os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import requests, html as html_escape

# ---------------------- 内置端点 ----------------------
ENDPOINTS = [
    ("GET",    "/api/healthz",                        False),
    ("GET",    "/healthz",                            False),
    ("POST",   "/api/create-user",                    False),
    ("POST",   "/api/login",                          False),
    ("POST",   "/api/upload-document",                False),
    ("GET",    "/api/list-documents",                 False),

    ("GET",    "/api/get-document",                   False),  # 用 ?id=
    ("GET",    "/api/get-document/{document_id}",     True),

    ("DELETE", "/api/delete-document",                False),  # 用 JSON body: {"document_id": "..."}
    ("DELETE", "/api/delete-document/{document_id}",  True),

    ("GET",    "/api/get-version/{link}",             True),

    ("GET",    "/api/get-watermarking-methods",       False),

    ("POST",   "/api/read-watermark",                 False),  # JSON 体里自动加入 id
    ("POST",   "/api/read-watermark/{document_id}",   True),

    ("POST",   "/api/create-watermark",               False),  # JSON 体里自动加入 id
    ("POST",   "/api/create-watermark/{document_id}", True),

    ("GET",    "/api/list-versions",                  False),  # 用 ?documentid=
    ("GET",    "/api/list-versions/{document_id}",    True),
    ("GET",    "/api/list-all-versions",              False),

    ("POST",   "/api/rmap-initiate",                  False),
    ("POST",   "/api/rmap-get-link",                  False),
]

# ---------------------- 工具函数 ----------------------
def now_ms() -> int:
    return int(time.time() * 1000)

def write_jsonl(path: Path, obj: Dict[str, Any]) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def build_url(base: str, path: str, doc_id: Optional[int]) -> str:
    u = base.rstrip("/") + path
    if "{document_id}" in u:
        u = u.replace("{document_id}", str(doc_id if doc_id is not None else 1))
    if "{link}" in u:
        u = u.replace("{link}", "sample-link")
    return u

def gen_example_body(path: str, method: str, doc_id: Optional[int]) -> Optional[Dict[str, Any]]:
    if path.startswith("/api/create-user"):
        stamp = str(now_ms())
        return {"login": f"fuzzer_{stamp}", "password": "P@ssw0rd!", "email": f"fuzzer{stamp}@example.local"}

    if path.startswith("/api/read-watermark"):
        body = {"method": "simple", "position": "center", "key": "k"}
        if doc_id is not None:
            body["id"] = int(doc_id)
        return body

    if path.startswith("/api/create-watermark"):
        body = {"method": "simple", "position": "center", "key": "k", "secret": "s", "intended_for": "user"}
        if doc_id is not None:
            body["id"] = int(doc_id)
        return body

    if path.startswith("/api/rmap-initiate") or path.startswith("/api/rmap-get-link"):
        return {"payload": "VGhpcyBpcyBhIHRlc3Q="}

    if path == "/api/delete-document":
        if doc_id is not None:
            return {"document_id": str(doc_id)}
        return None

    # 其他端点默认不发 body
    return None

def gen_fuzz_body(example: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if example is None:
        return {"__fuzz__": random.choice(["", "<bad>", 2**50, {"x":"y"}, "../../../"])}
    if isinstance(example, dict):
        b = dict(example)
        if b:
            k = next(iter(b.keys()))
            b[k] = random.choice(["", "<script>F</script>", 999999999999, None])
        else:
            b["__fuzz__"] = "<bad>"
        return b
    return example

# ---------------------- 登录（token 或 cookie） ----------------------
def try_auto_signup_and_login(base: str, session: requests.Session, email: str, password: str, auto_signup: bool, timeout: float) -> Tuple[Optional[str], bool]:
    if auto_signup:
        try:
            body = {"login": f"fuzzer_{now_ms()}", "password": password, "email": email}
            session.post(base.rstrip("/") + "/api/create-user", json=body, timeout=timeout)
        except Exception:
            pass

    try:
        resp = session.post(base.rstrip("/") + "/api/login", json={"email": email, "password": password}, timeout=timeout)
    except Exception:
        return (None, False)

    # JSON 中拿 token
    try:
        j = resp.json()
        cands = []
        if isinstance(j, dict):
            cands += [j.get("token"), j.get("access_token"), j.get("authorization")]
            if isinstance(j.get("data"), dict):
                dj = j["data"]
                cands += [dj.get("token"), dj.get("access_token")]
        for v in cands:
            if isinstance(v, str) and v:
                return (v, False)
    except ValueError:
        pass

    # 响应头里拿 Authorization
    ah = resp.headers.get("Authorization") or resp.headers.get("authorization")
    if ah:
        if ah.lower().startswith("bearer "):
            return (ah.split(None, 1)[1], False)
        return (ah, False)

    # Cookie 会话
    if session.cookies:
        return (None, True)

    return (None, False)

# ---------------------- 上传文档并解析 document_id ----------------------
def upload_document(base: str, requester, headers: Dict[str, str], timeout: float, file_path: Path) -> Optional[int]:
    url = base.rstrip("/") + "/api/upload-document"
    files = {"file": (file_path.name, open(file_path, "rb"), "application/pdf")}
    data = {"name": file_path.stem}
    try:
        r = requester.post(url, headers=headers, files=files, data=data, timeout=timeout)
    finally:
        try:
            files["file"][1].close()
        except Exception:
            pass
    # 解析返回 id
    # 兼容几种常见格式：{"id": 123} / {"document_id":123} / {"data":{"id":123}}
    try:
        j = r.json()
        if isinstance(j, dict):
            for key in ("id", "document_id", "doc_id"):
                if key in j and isinstance(j[key], (int, str)):
                    try:
                        return int(j[key])
                    except Exception:
                        pass
            if isinstance(j.get("data"), dict):
                dj = j["data"]
                for key in ("id", "document_id"):
                    if key in dj and isinstance(dj[key], (int, str)):
                        try:
                            return int(dj[key])
                        except Exception:
                            pass
    except Exception:
        pass
    return None

# ---------------------- HTML 报告 ----------------------
def generate_html_report(summary: Dict[str, Dict[str, Any]], outdir: Path) -> Path:
    parts = []
    parts.append("<!doctype html><html><head><meta charset='utf-8'><title>fuzz htmlcov</title>")
    parts.append("<style>body{font-family:Arial,Helvetica,sans-serif}table{border-collapse:collapse}th,td{border:1px solid #ddd;padding:8px;vertical-align:top}th{background:#f5f5f5}pre{white-space:pre-wrap;max-width:700px}.bad{background:#ffd6d6}</style>")
    parts.append("</head><body>")
    parts.append("<h1>Fuzz HTML Coverage (auto login + upload)</h1>")
    parts.append(f"<p>Generated: {time.ctime()}</p>")
    parts.append("<table><tr><th>Endpoint</th><th>Method</th><th>Attempts</th><th>Statuses (count)</th><th>Sample Request</th><th>Sample Response</th></tr>")
    for ep, methods in sorted(summary.items()):
        for m, stats in methods.items():
            statuses = ", ".join(f"{s}:{c}" for s,c in sorted(stats['by_status'].items(), key=lambda x:-x[1]))
            row_bad = any((s != "-1" and int(s) >= 500) or (s == "-1") for s in stats["by_status"])
            cls = " class='bad'" if row_bad else ""
            sample_req = html_escape.escape(json.dumps(stats.get("sample_req"), ensure_ascii=False)) if stats.get("sample_req") else ""
            sample_resp = html_escape.escape(stats.get("sample_resp","")) if stats.get("sample_resp") else ""
            parts.append(f"<tr{cls}><td>{html_escape.escape(ep)}</td><td>{html_escape.escape(m)}</td>"
                         f"<td>{stats.get('attempts',0)}</td><td>{statuses}</td>"
                         f"<td><pre>{sample_req}</pre></td><td><pre>{sample_resp}</pre></td></tr>")
    parts.append("</table></body></html>")
    d = outdir / "htmlcov"
    d.mkdir(parents=True, exist_ok=True)
    idx = d / "index.html"
    idx.write_text("\n".join(parts), encoding="utf-8")
    return idx

# ---------------------- 主流程 ----------------------
def main() -> int:
    ap = argparse.ArgumentParser("fuzz_all_api (auto login + upload)")
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--token", action="append", default=[], help="Bearer token（可多次传入）")
    ap.add_argument("--also-noauth", action="store_true", help="除带鉴权外，再跑一轮无鉴权对比")
    ap.add_argument("--auto-signup", action="store_true", help="先尝试 create-user 再 login")
    ap.add_argument("--login-email", default="fuzzer@example.local")
    ap.add_argument("--login-password", default="P@ssw0rd!")
    ap.add_argument("--file", type=str, default=None, help="要上传的 PDF 文件路径，如 ./test.pdf")
    ap.add_argument("--upload-first", action="store_true", default=False, help="若提供 --file，则先上传并解析 document_id")
    ap.add_argument("--iter", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--out", default="fuzz-results")
    args = ap.parse_args()

    random.seed(1337)
    outdir = Path(args.out); outdir.mkdir(parents=True, exist_ok=True)
    report = outdir / "report.log"
    if report.exists(): report.unlink()

    session = requests.Session()
    token_list = args.token[:]  # 优先手动 token
    have_cookie_auth = False

    if not token_list:
        tok, used_cookie = try_auto_signup_and_login(
            args.base_url, session,
            email=args.login_email, password=args.login_password,
            auto_signup=args.auto_signup, timeout=args.timeout,
        )
        if tok:
            token_list = [tok]
        elif used_cookie:
            have_cookie_auth = True

    # 选择请求函数 & headers 生成器
    def make_requester(mode: str):
        def build_headers():
            h: Dict[str, str] = {}
            if mode == "auth":
                if token_list:
                    h["Authorization"] = f"Bearer {random.choice(token_list)}"
            return h
        return (session if (mode == "auth" and have_cookie_auth) else requests), build_headers

    # 如需上传文件，先上传并拿到 document_id
    doc_id: Optional[int] = None
    if args.file and args.upload_first:
        pdf_path = Path(args.file)
        if pdf_path.exists() and pdf_path.is_file():
            requester, header_builder = make_requester("auth" if (token_list or have_cookie_auth) else "noauth")
            headers = header_builder()
            try:
                did = upload_document(args.base_url, requester, headers, args.timeout, pdf_path)
                doc_id = did
                write_jsonl(report, {"ts": now_ms(), "_type": "UPLOAD_RESULT", "file": str(pdf_path), "document_id": doc_id})
            except Exception as e:
                write_jsonl(report, {"ts": now_ms(), "_type": "UPLOAD_ERROR", "file": str(pdf_path), "exception": repr(e)})
        else:
            write_jsonl(report, {"ts": now_ms(), "_type": "UPLOAD_SKIP", "reason": "file_not_found", "file": args.file})

    # 测试模式：优先 auth；可选 noauth；若没拿到鉴权则只跑 noauth
    modes = []
    if token_list or have_cookie_auth:
        modes.append("auth")
    if args.also_noauth or not modes:
        modes.append("noauth")

    summary: Dict[str, Dict[str, Any]] = {}
    any_bad = False

    for method, path, _ in ENDPOINTS:
        ep = path
        summary.setdefault(ep, {}).setdefault(method, {"attempts":0, "by_status":{}, "sample_req":None, "sample_resp":None})

        # 基于 doc_id 构造 URL
        url = build_url(args.base_url, path, doc_id)

        for mode in modes:
            requester, header_builder = make_requester(mode)
            for _ in range(max(1, args.iter)):
                headers = header_builder()

                # —— normal 构造 ——
                params = {}
                body = gen_example_body(path, method, doc_id)

                # 特定接口补齐 query 参数
                if path == "/api/get-document" and doc_id is not None:
                    params["id"] = int(doc_id)
                if path == "/api/list-versions" and doc_id is not None:
                    params["documentid"] = int(doc_id)

                # 1) normal
                try:
                    req_kwargs: Dict[str, Any] = {"timeout": args.timeout, "headers": headers}
                    if params: req_kwargs["params"] = params

                    # /api/upload-document 用 multipart/form-data
                    if path == "/api/upload-document" and args.file and Path(args.file).exists():
                        files = {"file": (Path(args.file).name, open(args.file, "rb"), "application/pdf")}
                        data = {"name": Path(args.file).stem}
                        try:
                            r = requester.request(method, url, files=files, data=data, **req_kwargs)
                        finally:
                            try: files["file"][1].close()
                            except Exception: pass
                    else:
                        if body is not None:
                            req_kwargs["json"] = body
                        r = requester.request(method, url, **req_kwargs)

                    entry = {
                        "ts": now_ms(), "endpoint": ep, "method": method, "mode": mode,
                        "status": r.status_code, "req": {"headers": headers, "params": params or None, "body": body},
                        "resp_sample": r.text[:1000] if r.text else "",
                    }
                    write_jsonl(report, entry)
                    s = summary[ep][method]
                    s["attempts"] += 1
                    s["by_status"][str(r.status_code)] = s["by_status"].get(str(r.status_code), 0) + 1
                    if not s["sample_req"]:
                        s["sample_req"] = entry["req"]; s["sample_resp"] = entry["resp_sample"]
                    if 500 <= r.status_code < 600:
                        any_bad = True

                    # 若是上传且之前没拿到 doc_id，尝试从此处解析
                    if path == "/api/upload-document" and doc_id is None:
                        try:
                            j = r.json()
                            if isinstance(j, dict):
                                for k in ("id","document_id","doc_id"):
                                    if k in j:
                                        doc_id = int(j[k]); break
                                if doc_id is None and isinstance(j.get("data"), dict):
                                    dj = j["data"]
                                    for k in ("id","document_id"):
                                        if k in dj:
                                            doc_id = int(dj[k]); break
                        except Exception:
                            pass

                except Exception as e:
                    write_jsonl(report, {"ts": now_ms(), "endpoint": ep, "method": method, "mode": mode, "status": -1, "exception": repr(e)})
                    s = summary[ep][method]; s["attempts"] += 1
                    s["by_status"]["-1"] = s["by_status"].get("-1",0) + 1
                    if not s["sample_req"]:
                        s["sample_req"] = {"headers": headers, "params": params or None, "body": body}
                        s["sample_resp"] = repr(e)
                    any_bad = True

                # 2) fuzz
                try:
                    params_f = dict(params)
                    if not params_f:
                        params_f = {"_f": random.choice(["", "../../../../", "<script>", "🔥"])}
                    body_f = gen_fuzz_body(body)

                    req_kwargs: Dict[str, Any] = {"timeout": args.timeout, "headers": headers}
                    if params_f: req_kwargs["params"] = params_f

                    if path == "/api/upload-document" and args.file and Path(args.file).exists():
                        # 对上传端点就不重复 fuzz 文件体，避免重复打开；只加奇怪的 query param
                        files = {"file": (Path(args.file).name, open(args.file, "rb"), "application/pdf")}
                        data = {"name": Path(args.file).stem + "_fuzz"}
                        try:
                            r = requester.request(method, url, files=files, data=data, **req_kwargs)
                        finally:
                            try: files["file"][1].close()
                            except Exception: pass
                    else:
                        if body_f is not None:
                            req_kwargs["json"] = body_f
                        r = requester.request(method, url, **req_kwargs)

                    entry = {
                        "ts": now_ms(), "endpoint": ep, "method": method, "mode": mode, "fuzz": True,
                        "status": r.status_code, "req": {"headers": headers, "params": params_f or None, "body": body_f},
                        "resp_sample": r.text[:1000] if r.text else "",
                    }
                    write_jsonl(report, entry)
                    s = summary[ep][method]
                    s["attempts"] += 1
                    s["by_status"][str(r.status_code)] = s["by_status"].get(str(r.status_code), 0) + 1
                    if not s["sample_req"]:
                        s["sample_req"] = entry["req"]; s["sample_resp"] = entry["resp_sample"]
                    if 500 <= r.status_code < 600:
                        any_bad = True

                except Exception as e:
                    write_jsonl(report, {"ts": now_ms(), "endpoint": ep, "method": method, "mode": mode, "status": -1, "exception": repr(e), "fuzz": True})
                    s = summary[ep][method]; s["attempts"] += 1
                    s["by_status"]["-1"] = s["by_status"].get("-1",0) + 1
                    if not s["sample_req"]:
                        s["sample_req"] = {"headers": headers, "params": params or None, "body": body}
                        s["sample_resp"] = repr(e)
                    any_bad = True

    write_jsonl(report, {"ts": now_ms(), "_type":"SUMMARY", "any_bad": any_bad, "note": "doc_id used" if 'doc_id' in locals() and doc_id else "no doc_id"})
    idx = generate_html_report(summary, outdir)
    write_jsonl(report, {"ts": now_ms(), "_type":"SUMMARY_META", "html_index": str(idx)})
    print("Done. report:", str(report), "html:", str(idx))
    return 1 if any_bad else 0

if __name__ == "__main__":
    sys.exit(main())
