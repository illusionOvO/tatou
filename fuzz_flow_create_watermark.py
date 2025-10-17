# fuzz_flow_create_watermark.py
# End-to-end fuzz: register->login->upload->fuzz create-watermark/<id>
# Requires: requests, hypothesis
#
# Usage examples:
#   TATOU_BASE=http://127.0.0.1:5000 python -u fuzz_flow_create_watermark.py
#   (PowerShell) $env:TATOU_BASE="http://127.0.0.1:5000"; python -u .\fuzz_flow_create_watermark.py

import os
import time
import json
import requests
from pathlib import Path
from hypothesis import given, strategies as st, settings, Verbosity

BASE = os.getenv("TATOU_BASE", "http://127.0.0.1:5000").rstrip("/")

CREATE_USER = f"{BASE}/api/create-user"
LOGIN       = f"{BASE}/api/login"
UPLOAD      = f"{BASE}/api/upload-document"
# We'll fill TARGET once we have doc id

OUTDIR = Path("fuzz-results")
OUTDIR.mkdir(exist_ok=True)

def log_info(*args, **kw):
    print("[INFO]", *args, **kw, flush=True)

def log_warn(*args, **kw):
    print("[WARN]", *args, **kw, flush=True)

def log_alert(*args, **kw):
    print("[ALERT]", *args, **kw, flush=True)

def safe_json(r):
    try:
        return r.json()
    except Exception:
        return None

def register_and_login():
    ts = int(time.time())
    login = f"fuzz_user_{ts}"
    email = f"{login}@example.local"
    password = f"P@zz-{ts}"

    # try create
    try:
        r = requests.post(CREATE_USER, json={"login": login, "password": password, "email": email}, timeout=10)
        log_info("create-user status:", r.status_code)
    except Exception as e:
        log_warn("create-user request failed:", e)

    # try login
    try:
        r = requests.post(LOGIN, json={"email": email, "password": password}, timeout=10)
        log_info("login status:", r.status_code)
        j = safe_json(r) or {}
        # try common token fields
        token = j.get("token") or j.get("access_token") or j.get("jwt") or j.get("data", {}).get("token")
        if token:
            return f"Bearer {token}", login
        # some services return token inside 'session' or similar
        for v in j.values() if isinstance(j, dict) else []:
            if isinstance(v, str) and len(v) > 10:
                # guess
                return f"Bearer {v}", login
    except Exception as e:
        log_warn("login request failed:", e)

    log_warn("Could not obtain token via create/login. Trying to continue without token.")
    return None, login

def ensure_sample_bytes():
    # prefer existing sample.pdf in repo root
    p = Path("sample.pdf")
    if p.exists() and p.stat().st_size > 0:
        log_info("Using existing sample.pdf (size: %d bytes)" % p.stat().st_size)
        return p.read_bytes()
    # else generate a minimal PDF-like content
    log_info("sample.pdf not found — generating small PDF-like bytes")
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length 44 >>\nstream\nBT /F1 24 Tf 100 100 Td (Hello) Tj ET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \n0000000010 00000 n \n0000000065 00000 n \n0000000120 00000 n \n0000000200 00000 n \ntrailer\n<< /Root 1 0 R >>\nstartxref\n280\n%%EOF\n"
    return pdf_bytes

def upload_document(token=None, sample_bytes=None):
    headers = {}
    if token:
        headers["Authorization"] = token
    files = {}
    if sample_bytes is None:
        sample_bytes = ensure_sample_bytes()
    # attach as multipart form file
    files = {"file": ("sample.pdf", sample_bytes, "application/pdf")}
    data = {"name": f"fuzz_sample_{int(time.time())}.pdf"}
    try:
        r = requests.post(UPLOAD, files=files, data=data, headers=headers, timeout=30)
        log_info("upload-document status:", r.status_code)
        j = safe_json(r) or {}
        # try common id fields
        for k in ("id", "document_id", "doc_id", "file_id", "resource_id"):
            if k in j:
                return j[k], r, j
        # sometimes server returns nested
        if isinstance(j.get("data"), dict):
            for k in ("id", "document_id", "doc_id"):
                if k in j["data"]:
                    return j["data"][k], r, j
        # fallback: try to parse text for digits
        txt = r.text
        import re
        m = re.search(r'"?id"?\s*[:=]\s*["\']?(\d+)', txt)
        if m:
            return int(m.group(1)), r, j
        # else return whole json as last resort
        return None, r, j
    except Exception as e:
        log_warn("upload failed:", e)
        return None, None, None

# Hypothesis strategy for create-watermark fields
str_method = st.text(min_size=0, max_size=200)
str_position = st.text(min_size=0, max_size=2000)
str_key = st.text(min_size=0, max_size=1000)
str_secret = st.text(min_size=0, max_size=1000)
str_intended = st.one_of(st.text(min_size=0, max_size=200), st.just(""), st.none())

_counter = {"n": 0}
def tick():
    _counter["n"] += 1
    if _counter["n"] % 25 == 0:
        log_info("fuzz cases sent:", _counter["n"])

@settings(max_examples=500, verbosity=Verbosity.normal, deadline=None)
@given(method=str_method, position=str_position, key=str_key, secret=str_secret, intended_for=str_intended)
def fuzz_create_watermark(method, position, key, secret, intended_for):
    tick()
    payload = {"method": method, "position": position, "key": key, "secret": secret}
    if intended_for is not None:
        payload["intended_for"] = intended_for
    headers = {"Accept": "application/json"}
    if GLOBAL_TOKEN:
        headers["Authorization"] = GLOBAL_TOKEN
    try:
        url = f"{TARGET_ENDPOINT}"
        r = requests.post(url, json=payload, headers=headers, timeout=15)
        # consider 5xx and tracebacks as interesting
        if r is None:
            return
        txt = r.text or ""
        if r.status_code >= 500 or "traceback" in txt.lower():
            ts = int(time.time())
            fn = OUTDIR / f"create-watermark_{r.status_code}_{ts}.log"
            with fn.open("w", encoding="utf-8", errors="ignore") as f:
                f.write("REQ_HEADERS:\n" + json.dumps(dict(headers), ensure_ascii=False) + "\n\n")
                f.write("REQUEST_BODY:\n" + json.dumps(payload, ensure_ascii=False) + "\n\n")
                f.write("STATUS: " + str(r.status_code) + "\n\n")
                f.write("RESPONSE_TEXT:\n" + txt)
            log_alert("Saved crash ->", str(fn))
    except Exception as e:
        fn = OUTDIR / f"create-watermark-exception_{int(time.time())}.log"
        with fn.open("a", encoding="utf-8") as f:
            f.write(repr(e) + "\n")
        log_warn("Exception while fuzzing:", e)

if __name__ == "__main__":
    log_info("BASE:", BASE)
    log_info("Create-user:", CREATE_USER)
    log_info("Login:", LOGIN)
    log_info("Upload:", UPLOAD)

    # 1) register & login
    GLOBAL_TOKEN, uname = register_and_login()
    log_info("Token obtained:", bool(GLOBAL_TOKEN), "username:", uname)

    # 2) upload document (get id)
    sample_bytes = ensure_sample_bytes()
    doc_id, resp, parsed = upload_document(GLOBAL_TOKEN, sample_bytes)
    if doc_id is None:
        log_warn("Could not determine document id from upload response.")
        log_warn("Upload response status/text/json:", getattr(resp, "status_code", None), getattr(resp, "text", None), parsed)
        # we still try to continue by guessing id = 1
        guessed = 1
        log_info("Falling back to guessed document id:", guessed)
        doc_id = guessed

    TARGET_ENDPOINT = f"{BASE}/api/create-watermark/{doc_id}"
    log_info("Targeting endpoint:", TARGET_ENDPOINT)

    log_info("Starting fuzz campaign for create-watermark ...")
    fuzz_create_watermark()
    log_info("Fuzz campaign finished. Results in ./fuzz-results/")
