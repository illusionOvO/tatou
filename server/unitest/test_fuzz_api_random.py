# server/unitest/test_fuzz_api_random.py
import io
import random
import string
from collections import defaultdict, Counter
import json
import csv
from datetime import datetime

from conftest import make_pdf_bytes


def rand_email():
    return f"fuzz_{random.randint(1,10**9)}@example.com"


def rand_login():
    return "u_" + "".join(random.choices(string.ascii_lowercase, k=6))


VALID_METHODS = ["trailer-hmac", "metadata-xmp", "visible-text", "toy-eof"]
VALID_POSITIONS = ["eof", "metadata", "page"]


def record(stats, name, status):
    stats[name]["total"] += 1
    stats[name]["codes"][status] += 1
    if 200 <= status < 300:
        stats[name]["2xx"] += 1
    elif 400 <= status < 500:
        stats[name]["4xx"] += 1
    elif status >= 500:
        stats[name]["5xx"] += 1


def fuzz_once(client, state):
    choice = random.choice([
        "create_user", "login", "upload",
        "create_wm", "read_wm",
        "delete_doc", "get_version"
    ])

    # ---------------- create_user ----------------
    if choice == "create_user":
        payload = {
            "login": rand_login(),
            "email": rand_email(),
            "password": "pw123456"
        }
        if random.random() < 0.3:
            payload.pop(random.choice(list(payload.keys())))
        if random.random() < 0.2:
            payload[random.choice(list(payload.keys()))] = 123

        r = client.post("/api/create-user", json=payload)
        record(state["stats"], "create_user", r.status_code)
        print("create_user", r.status_code)

    # ---------------- login ----------------
    elif choice == "login":
        email = rand_email()
        login = rand_login()
        pw = "pw123456"

        client.post("/api/create-user", json={
            "login": login,
            "email": email,
            "password": pw
        })

        payload = {"email": email, "password": pw}
        if random.random() < 0.3:
            payload["password"] = "wrong"
        if random.random() < 0.3:
            payload.pop(random.choice(list(payload.keys())))

        r = client.post("/api/login", json=payload)
        record(state["stats"], "login", r.status_code)
        print("login", r.status_code)

        if r.status_code == 200:
            js = r.get_json(silent=True) or {}
            tok = js.get("token") or js.get("access_token")
            if tok:
                state["token"] = tok
                state["headers"] = {"Authorization": f"Bearer {tok}"}

    # ---------------- upload-document ----------------
    elif choice == "upload":
        headers = state.get("headers")

        if not headers:
            r = client.post("/api/upload-document")
            record(state["stats"], "upload(noauth)", r.status_code)
            print("upload(noauth)", r.status_code)
            return

        pdf = make_pdf_bytes() if random.random() < 0.7 else b"BAD"
        filename = random.choice(["a.pdf", "", "a.txt"])

        r = client.post(
            "/api/upload-document",
            data={"file": (io.BytesIO(pdf), filename)},
            headers=headers,
            content_type="multipart/form-data"
        )
        record(state["stats"], "upload", r.status_code)
        print("upload", r.status_code)

        if r.status_code == 201:
            js = r.get_json(silent=True) or {}
            if "id" in js:
                state["doc_ids"].append(js["id"])

    # ---------------- create-watermark ----------------
    elif choice == "create_wm":
        headers = state.get("headers")
        if not headers:
            return

        doc_id = random.choice(state["doc_ids"]) if state["doc_ids"] and random.random() < 0.7 else 999999

        payload = {
            "method": random.choice(VALID_METHODS + [None, "bad", 123]),
            "position": random.choice(VALID_POSITIONS + [None, "bad"]),
            "key": random.choice(["k", "", None, 123]),
            "secret": random.choice(["s", "", None, 123]),
            "intended_for": random.choice(["u", "", None, 123]),
        }

        r = client.post(
            f"/api/create-watermark/{doc_id}",
            json=payload,
            headers=headers
        )
        record(state["stats"], "create_wm", r.status_code)
        print("create_wm", r.status_code)

        if r.status_code in (200, 201):
            js = r.get_json(silent=True) or {}
            link = js.get("link")
            if link:
                state["links"].append(link)

    # ---------------- read-watermark ----------------
    elif choice == "read_wm":
        headers = state.get("headers")
        if not headers:
            return

        doc_id = random.choice(state["doc_ids"]) if state["doc_ids"] and random.random() < 0.7 else 999999

        payload = {
            "method": random.choice(VALID_METHODS + [None, "bad", 123]),
            "key": random.choice(["k", "", None, 123]),
        }

        r = client.post(
            f"/api/read-watermark/{doc_id}",
            json=payload,
            headers=headers
        )
        record(state["stats"], "read_wm", r.status_code)
        print("read_wm", r.status_code)

    # ---------------- delete-document ----------------
    elif choice == "delete_doc":
        headers = state.get("headers")
        if not headers:
            return

        doc_id = random.choice(state["doc_ids"]) if state["doc_ids"] and random.random() < 0.7 else 999999

        r = client.delete(f"/api/delete-document/{doc_id}", headers=headers)
        record(state["stats"], "delete_doc", r.status_code)
        print("delete_doc", r.status_code)

    # ---------------- get-version (public) ----------------
    elif choice == "get_version":
        link = random.choice(state["links"]) if state["links"] and random.random() < 0.7 else "not-exist"

        r = client.get(f"/api/get-version/{link}")
        record(state["stats"], "get_version", r.status_code)
        print("get_version", r.status_code)


def build_report(stats, rounds):
    summary = {}
    for ep, s in stats.items():
        total = s["total"]
        codes = dict(s["codes"])
        common = s["codes"].most_common(5)

        summary[ep] = {
            "total": total,
            "2xx": s["2xx"],
            "4xx": s["4xx"],
            "5xx": s["5xx"],
            "code_breakdown": codes,
            "top_codes": common,
            "success_rate": (s["2xx"] / total) if total else 0.0,
            "client_err_rate": (s["4xx"] / total) if total else 0.0,
            "server_err_rate": (s["5xx"] / total) if total else 0.0,
        }

    return {"rounds": rounds, "summary": summary, "generated_at": datetime.now().isoformat()}


def save_report_files(report, json_path="fuzz_report.json", csv_path="fuzz_report.csv"):
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["endpoint", "total", "2xx", "4xx", "5xx", "success_rate", "code_breakdown"])
        for ep, s in report["summary"].items():
            w.writerow([
                ep, s["total"], s["2xx"], s["4xx"], s["5xx"],
                f"{s['success_rate']:.2%}", s["code_breakdown"]
            ])


def _bar(pct, width=120, color="#4f46e5"):
    # pct: 0~1
    w = int(pct * width)
    return f"""
    <div style="background:#e5e7eb;border-radius:6px;overflow:hidden;height:10px;width:{width}px">
      <div style="background:{color};height:10px;width:{w}px"></div>
    </div>
    """


def save_html_report(report, html_path="fuzz_report.html"):
    rounds = report["rounds"]
    summary = report["summary"]
    gen_time = report["generated_at"]

    # 排序：按请求数降序
    items = sorted(summary.items(), key=lambda x: -x[1]["total"])

    rows = []
    for ep, s in items:
        top_codes = ", ".join([f"{code}×{cnt}" for code, cnt in s["top_codes"]]) or "-"
        rows.append(f"""
        <tr>
          <td class="mono">{ep}</td>
          <td>{s["total"]}</td>
          <td class="ok">{s["2xx"]}</td>
          <td class="warn">{s["4xx"]}</td>
          <td class="err">{s["5xx"]}</td>
          <td>{s["success_rate"]:.1%}{_bar(s["success_rate"], color="#16a34a")}</td>
          <td>{s["client_err_rate"]:.1%}{_bar(s["client_err_rate"], color="#f59e0b")}</td>
          <td>{s["server_err_rate"]:.1%}{_bar(s["server_err_rate"], color="#ef4444")}</td>
          <td class="mono small">{top_codes}</td>
        </tr>
        """)

    html = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8"/>
  <title>Fuzz API Report</title>
  <style>
    body {{
      font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background:#0b1020; color:#e5e7eb; margin:0; padding:24px;
    }}
    .card {{
      background:#111827; border:1px solid #1f2937; border-radius:14px;
      padding:18px 18px; margin-bottom:18px; box-shadow:0 8px 24px rgba(0,0,0,.35);
    }}
    h1 {{ margin:0 0 6px 0; font-size:22px; }}
    .muted {{ color:#9ca3af; font-size:13px; }}
    table {{
      width:100%; border-collapse:collapse; font-size:14px;
    }}
    th, td {{
      padding:10px 8px; border-bottom:1px solid #1f2937; vertical-align:top;
    }}
    th {{ text-align:left; color:#cbd5e1; font-weight:600; }}
    tr:hover td {{ background:#0f172a; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
    .small {{ font-size:12px; color:#cbd5e1; }}
    .ok {{ color:#16a34a; font-weight:600; }}
    .warn {{ color:#f59e0b; font-weight:600; }}
    .err {{ color:#ef4444; font-weight:600; }}
    .pill {{
      display:inline-block; padding:3px 8px; border-radius:999px;
      background:#0f172a; border:1px solid #1f2937; font-size:12px; margin-right:6px;
    }}
    .footer {{ margin-top:14px; color:#9ca3af; font-size:12px; }}
  </style>
</head>
<body>

  <div class="card">
    <h1>Fuzz API 测试报告</h1>
    <div class="muted">生成时间：{gen_time}</div>
    <div style="margin-top:10px">
      <span class="pill">总轮数：{rounds}</span>
      <span class="pill">端口数：{len(summary)}</span>
      <span class="pill">总请求：{sum(s["total"] for s in summary.values())}</span>
    </div>
  </div>

  <div class="card">
    <h2 style="margin:0 0 10px 0;font-size:18px;">端口统计</h2>
    <table>
      <thead>
        <tr>
          <th>Endpoint</th>
          <th>Total</th>
          <th>2xx</th>
          <th>4xx</th>
          <th>5xx</th>
          <th>Success Rate</th>
          <th>4xx Rate</th>
          <th>5xx Rate</th>
          <th>Top Status Codes</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>
    <div class="footer">
      说明：Success/4xx/5xx Rate 为该端口请求中对应区间占比；Top Status Codes 为出现最多的状态码。
    </div>
  </div>

</body>
</html>
"""
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)


def run_random_fuzz(client, rounds=200, save_files=True, save_html=True):
    state = {
        "token": None,
        "headers": None,
        "doc_ids": [],
        "links": [],
        "stats": defaultdict(lambda: {
            "total": 0, "2xx": 0, "4xx": 0, "5xx": 0, "codes": Counter()
        })
    }

    for _ in range(rounds):
        fuzz_once(client, state)

    report = build_report(state["stats"], rounds)

    if save_files:
        save_report_files(report)

    if save_html:
        save_html_report(report)

    return report


# pytest 入口（用 app_client fixture）
def test_fuzz_api_random_fuzz(app_client):
    app, client = app_client
    run_random_fuzz(client, rounds=120, save_files=True, save_html=True)
