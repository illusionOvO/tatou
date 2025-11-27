# server/test/test_health.py

import sys
import os
from pathlib import Path

# 让 Python 能找到 src/server
THIS_DIR = os.path.dirname(__file__)
SERVER_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))
if SERVER_ROOT not in sys.path:
    sys.path.insert(0, SERVER_ROOT)

# from src.server import app


def test_health(client):
    # client = app.test_client()
    r = client.get("/healthz")
    assert r.status_code == 200
