import os, sys, json, time
import requests
from hypothesis import given, strategies as st, settings, Verbosity

BASE = os.getenv("TATOU_BASE", "http://127.0.0.1:5000")
URL = f"{BASE}/create-user"

print(f"[INFO] Target = {URL}", flush=True)
os.makedirs("fuzz-results", exist_ok=True)

# 计数器：每跑 10 个样例打印一次
_count = {"n": 0}
def tick():
    _count["n"] += 1
    if _count["n"] % 10 == 0:
        print(f"[INFO] Sent {_count['n']} cases", flush=True)

str_text = st.text(min_size=0, max_size=2000)
str_bin  = st.binary(max_size=2000).map(lambda b: b.decode("latin1","ignore"))

strat_login    = st.one_of(str_text, str_bin)
strat_password = st.one_of(str_text, str_bin)
strat_email    = st.one_of(st.text(min_size=0, max_size=1000), st.just("not-an-email"), st.just("a@b.c"))

@settings(max_examples=100, verbosity=Verbosity.normal, deadline=None)
@given(login=strat_login, password=strat_password, email=strat_email)
def fuzz_create_user(login, password, email):
    tick()
    payload = {"login": login, "password": password, "email": email}
    try:
        r = requests.post(URL, json=payload, timeout=5)
        if r.status_code >= 500 or "traceback" in r.text.lower():
            ts = int(time.time())
            fn = f"fuzz-results/create-user_{r.status_code}_{ts}.log"
            with open(fn, "w", encoding="utf-8", errors="ignore") as f:
                f.write("REQUEST:\n" + json.dumps(payload, ensure_ascii=False) + "\n\n")
                f.write(f"STATUS: {r.status_code}\n\n")
                f.write(r.text)
            print(f"[ALERT] Crash saved -> {fn}", flush=True)
    except Exception as e:
        with open("fuzz-results/create-user-exception.log","a",encoding="utf-8") as f:
            f.write(repr(e)+"\n")
        print("[WARN] Exception:", repr(e), flush=True)

if __name__ == "__main__":
    print("[INFO] Start fuzzing ...", flush=True)
    fuzz_create_user()
    print("[INFO] Done. See ./fuzz-results/", flush=True)
