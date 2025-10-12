# check_clients_keys.py
from pathlib import Path
from pgpy import PGPKey
import sys

clients_dir = Path("server/keys/clients").resolve()
bad = []
print(f"[check] scanning: {clients_dir}")

for asc in sorted(clients_dir.glob("*.asc")):
    try:
        key, _ = PGPKey.from_file(str(asc))
        # 基本信息
        fps = getattr(key, "fingerprint", None)
        uid = next(iter(key.userids), None)
        print(f"OK  - {asc.name:20}  fpr={fps}  uid={uid}")
    except Exception as e:
        print(f"BAD - {asc.name:20}  error={e}")
        bad.append(asc.name)

print("\nSummary:")
print("BAD files:", bad if bad else "none")
sys.exit(1 if bad else 0)
