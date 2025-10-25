# fuzz_all_api.py
# Full-API fuzz for Tatou. Inspired by fuzz_flow_create_watermark.py
# Requires: requests, hypothesis
#
# Usage:
#   Linux/Git Bash:
#     TATOU_BASE=http://127.0.0.1:5000 FUZZ_EXAMPLES=200 python -u fuzz_all_api.py
#   PowerShell:
#     $env:TATOU_BASE="http://127.0.0.1:5000"; $env:FUZZ_EXAMPLES="200"; python -u .\fuzz_all_api.py
#
# Logs:
#   ./fuzz-results/<endpoint>_*.log  (interesting cases)
#   ./fuzz-results/summary_<ts>.json (counts per endpoint)
#   ./fuzz-results/summary_<ts>.log  (human-readable)

import subprocess, sys, os, time, json, base64, random, traceback, re
from pathlib import Path

def ensure_installed(pkg):
    try:
        __import__(pkg)
    except ImportError:
        print(f"[+] Installing {pkg} ...", flush=True)
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

for dep in ["requests", "hypothesis"]:
    ensure_installed(dep)

import requests
from hypothesis import given, strategies as st, settings, Verbosity

# ---------------------------------------------------------------------
# Config & globals
# ---------------------------------------------------------------------
BASE = os.getenv("TATOU_BASE", "http://127.0.0.1:5000").rstrip("/")
MAX_EXAMPLES = int(os.getenv("FUZZ_EXAMPLES", "200"))
OUTDIR = Path("fuzz-results")
OUTDIR.mkdir(exist_ok=True)

CREATE_USER = f"{BASE}/api/create-user"
LOGIN       = f"{BASE}/api/login"
UPLOAD      = f"{BASE}/api/upload-document"
LIST_DOCS   = f"{BASE}/api/list-documents"
LIST_ALL    = f"{BASE}/api/list-all-versions"        # per API.md（个别实现可能也复用 /api/list-versions）
LIST_VERS   = f"{BASE}/api/list-versions"
HEALTHZ     = f"{BASE}/api/healthz"
GET_METHODS = f"{BASE}/api/get-watermarking-methods"
GET_DOC     = f"{BASE}/api/get-document"
READ_WM     = f"{BASE}/api/read-watermark"
CREATE_WM   = f"{BASE}/api/create-watermark"
GET_VER     = f"{BASE}/api/get-version"
DEL_DOC     = f"{BASE}/api/delete-document"
RMAP_INIT   = f"{BASE}/api/rmap-initiate"
RMAP_LINK   = f"{BASE}/api/rmap-get-link"

GLOBAL_TOKEN = None
GLOBAL_USER  = None
DOC_ID       = None
VERSION_IDS  = []   # endpoint returns (id/link/…) we try to re-use
SUMMARY      = {}   # endpoint -> {sent, saved, last_status}

def add_sum(name, sent=0, saved=0, last=None):
    s = SUMMARY.setdefault(name, {"sent":0, "saved":0, "last_status":None})
    s["sent"] += sent
    s["saved"] += saved
    if last is not None:
        s["last_status"] = last

def headers(auth=True, extra=None):
    h = {"Accept": "application/json"}
    if auth and GLOBAL_TOKEN:
        h["Authorization"] = GLOBAL_TOKEN
    if extra:
        h.update(extra)
    return h

def now_ts():
    return int(time.time())

def log_alert(*a):
    print("[ALERT]", *a, flush=True)

def log_info(*a):
    print("[INFO]", *a, flush=True)

def log_warn(*a):
    print("[WARN]", *a, flush=True)

def save_case(endpoint, status, req, resp_text=None, note=None):
    """Dump interesting case to file and increment summary."""
    ts = now_ts()
    fn = OUTDIR / f"{endpoint}_{status}_{ts}.log"
    with fn.open("w", encoding="utf-8", errors="ignore") as f:
        f.write(f"ENDPOINT: {endpoint}\n")
        if note:
            f.write(f"NOTE: {note}\n")
        f.write("REQUEST:\n")
        f.write(json.dumps(req, ensure_ascii=False, indent=2))
        f.write("\n\n")
        f.write(f"STATUS: {status}\n\n")
        if resp_text is not None:
            f.write("RESPONSE_TEXT:\n")
            f.write(resp_text)
    add_sum(endpoint, saved=1)
    log_alert("Saved ->", str(fn))

def ensure_sample_bytes():
    p = Path("sample.pdf")
    if p.exists() and p.stat().st_size > 0:
        return p.read_bytes()
    # small valid-ish PDF
    return (b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> /Contents 4 0 R >>\nendobj\n"
            b"4 0 obj\n<< /Length 44 >>\nstream\nBT /F1 24 Tf 100 100 Td (Hello) Tj ET\nendstream\nendobj\n"
            b"xref\n0 5\n0000000000 65535 f \n0000000010 00000 n \n0000000065 00000 n \n0000000120 00000 n \n0000000200 00000 n \n"
            b"trailer\n<< /Root 1 0 R >>\nstartxref\n280\n%%EOF\n")

def safe_json(r):
    try:
        return r.json()
    except Exception:
        return None

# ---------------------------------------------------------------------
# Bootstrap: create user -> login -> upload doc (baseline)
# ---------------------------------------------------------------------
def bootstrap_user_and_doc():
    global GLOBAL_TOKEN, GLOBAL_USER, DOC_ID
    ts = now_ts()
    login_name = f"fuzzer_{ts}"
    email = f"{login_name}@example.local"
    password = f"P@ss-{ts}"

    # create-user
    try:
        r = requests.post(CREATE_USER, json={"login": login_name, "password": password, "email": email}, timeout=10)
        add_sum("create-user", sent=1, last=r.status_code)
    except Exception as e:
        save_case("create-user-ex", "EXC", {"url": CREATE_USER, "payload": {"login": login_name, "password": "***", "email": email}}, repr(e))
        log_warn("create-user failed:", e)

    # login
    try:
        r = requests.post(LOGIN, json={"email": email, "password": password}, timeout=10)
        add_sum("login", sent=1, last=r.status_code)
        j = safe_json(r) or {}
        tok = j.get("token") or j.get("access_token") or j.get("jwt") or (j.get("data", {}) if isinstance(j.get("data"), dict) else {})
        if isinstance(tok, dict):
            tok = tok.get("token")
        if isinstance(tok, str) and len(tok) > 8:
            GLOBAL_TOKEN = f"Bearer {tok}"
            GLOBAL_USER = login_name
        else:
            # last-resort: guess first long string
            for v in j.values() if isinstance(j, dict) else []:
                if isinstance(v, str) and len(v) > 10:
                    GLOBAL_TOKEN = f"Bearer {v}"; GLOBAL_USER = login_name; break
    except Exception as e:
        save_case("login-ex", "EXC", {"url": LOGIN, "payload": {"email": email, "password": "***"}}, repr(e))
        log_warn("login failed:", e)

    # upload-document
    bytes_ = ensure_sample_bytes()
    files = {"file": ("sample.pdf", bytes_, "application/pdf")}
    data = {"name": f"fuzz_{ts}.pdf"}
    try:
        r = requests.post(UPLOAD, files=files, data=data, headers=headers(True), timeout=30)
        add_sum("upload-document", sent=1, last=r.status_code)
        j = safe_json(r) or {}
        # discover id keys
        for k in ("id","document_id","doc_id","file_id","resource_id"):
            if k in j:
                DOC_ID = j[k]; break
        if DOC_ID is None and isinstance(j.get("data"), dict):
            for k in ("id","document_id","doc_id"):
                if k in j["data"]:
                    DOC_ID = j["data"][k]; break
        if DOC_ID is None:
            m = re.search(r'"?id"?\s*[:=]\s*["\']?(\d+)', r.text or "")
            if m: DOC_ID = int(m.group(1))
        if DOC_ID is None:
            DOC_ID = 1  # fallback guess
            save_case("upload-document", r.status_code, {"url": UPLOAD, "form": list(data.items())}, r.text, note="Could not parse id; fallback to 1")
    except Exception as e:
        save_case("upload-document-ex", "EXC", {"url": UPLOAD}, repr(e))
        DOC_ID = 1

# ---------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------
short_txt = st.text(min_size=0, max_size=64)
long_txt  = st.text(min_size=0, max_size=2048)
email_s   = st.text(min_size=0, max_size=64)
b64_s     = st.binary(min_size=0, max_size=128).map(lambda b: base64.b64encode(b).decode("ascii", "ignore"))
maybe_int = st.one_of(st.integers(min_value=0, max_value=1_000_000), st.text(min_size=0, max_size=32), st.none())
wm_method = st.one_of(short_txt, st.sampled_from(["add-after-eof","visible-text","xref-pad","%PDF-1.4",""]))
position  = long_txt
key_s     = long_txt
secret_s  = long_txt
intended  = st.one_of(short_txt, st.just(""), st.none())

# ---------------------------------------------------------------------
# Fuzz helpers
# ---------------------------------------------------------------------
def interesting(r, expect_json=False):
    if r is None:
        return True
    txt = (r.text or "")
    if r.status_code >= 500:
        return True
    if "traceback" in txt.lower():
        return True
    if expect_json:
        try:
            r.json()
        except Exception:
            return True
    return False

def fuzz_post_json(endpoint, url, payload, need_auth=True, expect_json=False, timeout=15):
    try:
        r = requests.post(url, json=payload, headers=headers(need_auth), timeout=timeout)
        add_sum(endpoint, sent=1, last=r.status_code)
        if interesting(r, expect_json):
            save_case(endpoint, r.status_code, {"url": url, "payload": payload, "auth": bool(GLOBAL_TOKEN)}, r.text)
    except Exception as e:
        save_case(endpoint, "EXC", {"url": url, "payload": payload}, repr(e))

def fuzz_get(endpoint, url, need_auth=False, params=None, expect_json=False, timeout=15):
    try:
        r = requests.get(url, params=params or {}, headers=headers(need_auth), timeout=timeout)
        add_sum(endpoint, sent=1, last=r.status_code)
        if interesting(r, expect_json):
            save_case(endpoint, r.status_code, {"url": url, "params": params or {}, "auth": bool(GLOBAL_TOKEN)}, r.text)
    except Exception as e:
        save_case(endpoint, "EXC", {"url": url, "params": params or {}}, repr(e))

# ---------------------------------------------------------------------
# Individual endpoint fuzzers
# ---------------------------------------------------------------------
@settings(max_examples=MAX_EXAMPLES, verbosity=Verbosity.normal, deadline=None)
@given(login=short_txt, password=short_txt, email=email_s)
def fuzz_create_user(login, password, email):
    payload = {"login": login, "password": password, "email": email}
    fuzz_post_json("create-user", CREATE_USER, payload, need_auth=False, expect_json=True)

@settings(max_examples=MAX_EXAMPLES, verbosity=Verbosity.normal, deadline=None)
@given(email=short_txt, password=short_txt)
def fuzz_login(email, password):
    payload = {"email": email, "password": password}
    fuzz_post_json("login", LOGIN, payload, need_auth=False, expect_json=True)

@settings(max_examples=MAX_EXAMPLES, verbosity=Verbosity.normal, deadline=None)
@given(name=short_txt, rnd=st.binary(min_size=0, max_size=4096))
def fuzz_upload_document(name, rnd):
    files = {"file": ("sample.pdf", rnd or ensure_sample_bytes(), "application/pdf")}
    data = {"name": name}
    try:
        r = requests.post(UPLOAD, files=files, data=data, headers=headers(True), timeout=30)
        add_sum("upload-document", sent=1, last=r.status_code)
        if interesting(r, expect_json=True):
            save_case("upload-document", r.status_code, {"url": UPLOAD, "form": {"name": name, "file": f"{len(rnd)}B"}}, r.text)
    except Exception as e:
        save_case("upload-document", "EXC", {"url": UPLOAD, "form": {"name": name}}, repr(e))

@settings(max_examples=MAX_EXAMPLES, verbosity=Verbosity.normal, deadline=None)
@given(method=wm_method, position=position, key=key_s, secret=secret_s, intended=intended)
def fuzz_create_watermark(method, position, key, secret, intended):
    # path with id (preferred)
    url = f"{CREATE_WM}/{DOC_ID}"
    payload = {"method": method, "position": position, "key": key, "secret": secret}
    if intended is not None:
        payload["intended_for"] = intended
    fuzz_post_json("create-watermark", url, payload, need_auth=True, expect_json=True)

@settings(max_examples=MAX_EXAMPLES, verbosity=Verbosity.normal, deadline=None)
@given(method=wm_method, position=position, key=key_s, doc_id=maybe_int)
def fuzz_read_watermark(method, position, key, doc_id):
    # both variants: with body id or path id
    if doc_id is None:
        url = f"{READ_WM}/{DOC_ID}"
        payload = {"method": method, "position": position, "key": key}
    else:
        url = READ_WM
        payload = {"method": method, "position": position, "key": key, "id": doc_id}
    fuzz_post_json("read-watermark", url, payload, need_auth=True, expect_json=True)

@settings(max_examples=MAX_EXAMPLES//5, verbosity=Verbosity.normal, deadline=None)
@given(doc_id=maybe_int)
def fuzz_get_document(doc_id):
    # /get-document and /get-document/<id>
    if doc_id is None:
        url = f"{GET_DOC}/{DOC_ID}"
        fuzz_get("get-document", url, need_auth=True, expect_json=False)
    else:
        fuzz_get("get-document", GET_DOC, need_auth=True, params={"id": doc_id}, expect_json=False)

@settings(max_examples=MAX_EXAMPLES//5, verbosity=Verbosity.normal, deadline=None)
@given(doc_id=maybe_int)
def fuzz_list_versions(doc_id):
    if doc_id is None:
        # /api/list-versions/<id>
        url = f"{LIST_VERS}/{DOC_ID}"
        fuzz_get("list-versions", url, need_auth=True, expect_json=True)
    else:
        # /api/list-versions?documentid=...
        fuzz_get("list-versions", LIST_VERS, need_auth=True, params={"documentid": doc_id}, expect_json=True)

@settings(max_examples=MAX_EXAMPLES//5, verbosity=Verbosity.normal, deadline=None)
@given()
def fuzz_list_documents():
    fuzz_get("list-documents", LIST_DOCS, need_auth=True, expect_json=True)

@settings(max_examples=MAX_EXAMPLES//5, verbosity=Verbosity.normal, deadline=None)
@given()
def fuzz_list_all_versions():
    # Some impls may actually use LIST_VERS for "all"; call both
    fuzz_get("list-all-versions", LIST_ALL, need_auth=True, expect_json=True)
    fuzz_get("list-all-versions", LIST_VERS, need_auth=True, expect_json=True)

@settings(max_examples=MAX_EXAMPLES//5, verbosity=Verbosity.normal, deadline=None)
@given()
def fuzz_get_methods():
    fuzz_get("get-watermarking-methods", GET_METHODS, need_auth=False, expect_json=True)

@settings(max_examples=MAX_EXAMPLES//5, verbosity=Verbosity.normal, deadline=None)
@given()
def fuzz_healthz():
    # API.md 里写了 healthz 在 /api/healthz（若实现兼容 /healthz 也顺带探测）
    fuzz_get("healthz", HEALTHZ, need_auth=False, expect_json=True)
    fuzz_get("healthz", f"{BASE}/healthz", need_auth=False, expect_json=True)

@settings(max_examples=MAX_EXAMPLES//5, verbosity=Verbosity.normal, deadline=None)
@given(link=short_txt)
def fuzz_get_version(link):
    # Typically should be a real link; fuzzing arbitrary strings should not 5xx
    url = f"{GET_VER}/{link}"
    fuzz_get("get-version", url, need_auth=True, expect_json=False)

@settings(max_examples=MAX_EXAMPLES//5, verbosity=Verbosity.normal, deadline=None)
@given(doc_id=maybe_int)
def fuzz_delete_document(doc_id):
    # Both variants: /delete-document and /delete-document/<id>
    if doc_id is None:
        url = f"{DEL_DOC}/{DOC_ID}"
        try:
            r = requests.delete(url, headers=headers(True), timeout=15)
            add_sum("delete-document", sent=1, last=r.status_code)
            if interesting(r, expect_json=True):
                save_case("delete-document", r.status_code, {"url": url, "auth": bool(GLOBAL_TOKEN)}, r.text)
        except Exception as e:
            save_case("delete-document", "EXC", {"url": url}, repr(e))
    else:
        try:
            r = requests.request("DELETE", DEL_DOC, json={"id": doc_id}, headers=headers(True), timeout=15)
            add_sum("delete-document", sent=1, last=r.status_code)
            if interesting(r, expect_json=True):
                save_case("delete-document", r.status_code, {"url": DEL_DOC, "payload": {"id": doc_id}}, r.text)
        except Exception as e:
            save_case("delete-document", "EXC", {"url": DEL_DOC, "payload": {"id": doc_id}}, repr(e))

@settings(max_examples=MAX_EXAMPLES//3, verbosity=Verbosity.normal, deadline=None)
@given(payload=b64_s)
def fuzz_rmap_initiate(payload):
    fuzz_post_json("rmap-initiate", RMAP_INIT, {"payload": payload}, need_auth=True, expect_json=True)

@settings(max_examples=MAX_EXAMPLES//3, verbosity=Verbosity.normal, deadline=None)
@given(payload=b64_s)
def fuzz_rmap_get_link(payload):
    fuzz_post_json("rmap-get-link", RMAP_LINK, {"payload": payload}, need_auth=True, expect_json=True)

# ---------------------------------------------------------------------
def write_summary():
    ts = now_ts()
    js = OUTDIR / f"summary_{ts}.json"
    lg = OUTDIR / f"summary_{ts}.log"
    with js.open("w", encoding="utf-8") as f:
        json.dump(SUMMARY, f, indent=2, ensure_ascii=False)
    with lg.open("w", encoding="utf-8") as f:
        f.write("# Tatou Fuzz Summary\n")
        f.write(f"BASE: {BASE}\n")
        for k,v in sorted(SUMMARY.items()):
            f.write(f"{k:24s} sent={v['sent']:5d}  saved={v['saved']:4d}  last={v['last_status']}\n")
    log_info("Summary written:", str(js), str(lg))

if __name__ == "__main__":
    log_info("BASE:", BASE)
    bootstrap_user_and_doc()
    log_info("Token?", bool(GLOBAL_TOKEN), "DOC_ID:", DOC_ID)

    # health endpoints first
    fuzz_healthz()
    fuzz_get_methods()

    # CRUD-ish
    fuzz_create_user()
    fuzz_login()
    fuzz_upload_document()
    fuzz_list_documents()
    fuzz_list_versions()
    fuzz_list_all_versions()
    fuzz_get_document()

    # watermarking
    fuzz_create_watermark()
    fuzz_read_watermark()
    fuzz_get_version()

    # Optional destructive (server should enforce ownership)
    fuzz_delete_document()

    # RMAP
    fuzz_rmap_initiate()
    fuzz_rmap_get_link()

    write_summary()
    log_info("Fuzz campaign finished. See ./fuzz-results/")
