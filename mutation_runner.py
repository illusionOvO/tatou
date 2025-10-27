import os
import sys
import subprocess
from pathlib import Path
import argparse
import time

def run_command(cmd, cwd=None):
    """执行命令并实时输出"""
    print(f"\n[RUN] {cmd}")
    process = subprocess.Popen(
        cmd, shell=True, cwd=cwd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    for line in process.stdout:
        print(line.strip())
    process.wait()
    return process.returncode

def write_mutmut_toml():
    """如果不存在 mutmut.toml 就自动生成"""
    path = Path("mutmut.toml")
    if path.exists():
        print("[INFO] 已检测到 mutmut.toml，跳过生成。")
        return
    content = """[mutmut]
paths_to_mutate = ['src/']
tests_dir = "test"
runner = "pytest -q"
timeout = 30
"""
    path.write_text(content, encoding="utf-8")
    print("[INFO] 已生成默认 mutmut.toml ✅")

def main():
    parser = argparse.ArgumentParser(description="Mutation testing runner for Tatou project")
    parser.add_argument("--paths", default="server/src/", help="Paths to mutate")
    parser.add_argument("--tests", default="server/test", help="Tests directory")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout for test run")
    parser.add_argument("--runner", default="pytest -q", help="Pytest command")
    args = parser.parse_args()

    # 自动切换到 server 目录
    server_dir = Path("server")
    if server_dir.exists():
        os.chdir(server_dir)
        print(f"[INFO] 已切换到目录: {Path.cwd()}")

    write_mutmut_toml()

    # baseline 测试
    print("\n[STEP 1] 运行 baseline 测试")
    start = time.time()
    code = run_command(f"{args.runner} {args.tests}")
    if code != 0:
        print("[ERROR] baseline 测试未通过，停止 mutation。")
        sys.exit(1)
    print(f"[INFO] baseline 测试完成，用时 {time.time()-start:.2f}s ✅")

    # mutation 测试
    print("\n[STEP 2] 运行 mutation 测试")
    start = time.time()
    run_command(f"{sys.executable} -m mutmut run")
    print(f"[INFO] Mutation 测试完成，用时 {time.time()-start:.2f}s ✅")

    print("\n[RESULT] Mutation 测试结果：")
    run_command(f"{sys.executable} -m mutmut results")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[FATAL] 出错: {e}")
        sys.exit(1)
