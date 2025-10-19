#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mutation Testing one-shot runner for Tatou project.
- Creates mutmut.toml if missing
- Runs baseline pytest
- Runs mutmut and stores results
- Works on Windows/macOS/Linux
"""
import argparse
import os
import sys
import subprocess
from pathlib import Path
from textwrap import dedent

def run_cmd(cmd, **kw):
    print(f"\n$ {' '.join(cmd)}")
    return subprocess.run(cmd, check=False, text=True, **kw)

def ensure_installed(pkgs):
    # Try to install missing packages via pip in current interpreter
    for pkg in pkgs:
        print(f"[*] Ensuring package installed: {pkg}")
        r = run_cmd([sys.executable, "-m", "pip", "show", pkg], capture_output=True)
        if r.returncode != 0:
            print(f"[+] Installing {pkg} ...")
            ir = run_cmd([sys.executable, "-m", "pip", "install", pkg])
            if ir.returncode != 0:
                print(f"[!] Failed to install {pkg}. Please install it manually.")
                sys.exit(ir.returncode)

def write_mutmut_toml_if_missing(paths_to_mutate, tests_dir, timeout, excluded):
    cfg = Path("mutmut.toml")
    if cfg.exists():
        print("[*] mutmut.toml already exists. Skipping creation.")
        return
    content = dedent(f"""
    [mutmut]
    paths_to_mutate = {paths_to_mutate!r}
    tests_dir = "{tests_dir}"
    runner = "pytest -q"
    timeout = {timeout}
    backup = true
    excluded_paths = {excluded!r}
    """).strip() + "\n"
    cfg.write_text(content, encoding="utf-8")
    print("[+] Wrote mutmut.toml")

def main():
    parser = argparse.ArgumentParser(description="One-shot Mutation Testing runner")
    parser.add_argument("--paths", default="tatou/", help="Path(s) to mutate, comma-separated (default: tatou/)")
    parser.add_argument("--tests", default="tests", help="Tests directory (default: tests)")
    parser.add_argument("--timeout", type=int, default=30, help="Per-test timeout seconds (default: 30)")
    parser.add_argument("--exclude", default="tatou/migrations/,tatou/third_party/", help="Excluded paths, comma-separated")
    parser.add_argument("--skip-install", action="store_true", help="Skip pip installs")
    parser.add_argument("--skip-baseline", action="store_true", help="Skip baseline pytest")
    parser.add_argument("--apply", type=int, default=None, help="Apply a specific mutant id (for local repro)")
    parser.add_argument("--runner", default="pytest -q", help="Custom test runner command for mutmut (default: pytest -q)")
    args = parser.parse_args()

    project_root = Path.cwd()
    reports_dir = project_root / "reports"
    reports_dir.mkdir(exist_ok=True)

    paths_to_mutate = [p.strip() for p in args.paths.split(",") if p.strip()]
    excluded_paths = [p.strip() for p in args.exclude.split(",") if p.strip()]

    # 0) Ensure deps
    if not args.skip_install:
        ensure_installed(["pytest", "mutmut"])

    # 1) Config
    write_mutmut_toml_if_missing(paths_to_mutate, args.tests, args.timeout, excluded_paths)

    # 2) Optional: apply a mutant (debug)
    if args.apply is not None:
        print(f"[!] Applying mutant id {args.apply} for local repro (remember to revert with git).")
        rc = run_cmd(["mutmut", "apply", str(args.apply)]).returncode
        sys.exit(rc)

    # 3) Baseline pytest
    if not args.skip_baseline:
        print("\n=== Running baseline tests (pytest) ===")
        rc = run_cmd(["pytest", "-q"]).returncode
        if rc != 0:
            print("[!] Baseline tests failed. Fix tests before mutation testing.")
            sys.exit(rc)

    # 4) Run mutmut
    print("\n=== Running mutation tests (mutmut) ===")
    # Prefer passing runner explicitly to allow user override
    run_cmd(["mutmut", "run", "--runner", args.runner])

    # 5) Results
    print("\n=== Mutation results ===")
    res = run_cmd(["mutmut", "results"], capture_output=True)
    sys.stdout.write(res.stdout)
    (reports_dir / "mutmut_results.txt").write_text(res.stdout, encoding="utf-8")
    print(f"\n[+] Saved summary to {reports_dir/'mutmut_results.txt'}")

    # 6) Optional: list survivors with hints
    print("\nTip: Show a specific mutant diff with:")
    print("  mutmut show <id>")
    print("Then write/strengthen a test to kill it, and re-run this script.")

if __name__ == "__main__":
    # Windows friendliness: stable hashing avoids some flaky tests
    os.environ.setdefault("PYTHONHASHSEED", "0")
    main()
