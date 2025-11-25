"""
watermarking_cli.py — CLI for PDF watermark toolkit
(fully compatible with test_watermarking_cli.py)
"""

from __future__ import annotations
import argparse
import json
import sys
import getpass
from typing import Iterable, Optional

from .watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
)

# --- import from utils ---
from server.src.watermarking_utils import (
    METHODS,
    apply_watermark,
    read_watermark,
    explore_pdf,
    is_watermarking_applicable,
)

__version__ = "0.1.0"


# ======================================================================
# Helpers
# ======================================================================
def _read_text_from_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _read_text_from_stdin() -> str:
    data = sys.stdin.read()
    if not data:
        raise ValueError("No data received on stdin")
    return data


def _resolve_secret(args: argparse.Namespace) -> str:
    if args.secret is not None:
        return args.secret
    if args.secret_file is not None:
        return _read_text_from_file(args.secret_file)
    if args.secret_stdin:
        return _read_text_from_stdin()
    return getpass.getpass("Secret: ")


def _resolve_key(args: argparse.Namespace) -> str:
    if args.key is not None:
        return args.key
    if args.key_file is not None:
        return _read_text_from_file(args.key_file).strip()
    if args.key_stdin:
        return _read_text_from_stdin().strip()
    if args.key_prompt:
        return getpass.getpass("Key: ")
    return getpass.getpass("Key: ")


# ======================================================================
# Subcommands
# ======================================================================

def cmd_methods(_args: argparse.Namespace) -> int:
    for m in sorted(METHODS):
        print(m)
    return 0


def cmd_explore(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def cmd_embed(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)

    # test expects pdf_path=..., method=...
    if not is_watermarking_applicable(
        pdf=args.input,
        method=args.method,
        position=args.position,
    ):
        print(f"Method {args.method} is not applicable.")
        return 5

    pdf_bytes = apply_watermark(
        pdf=args.input,
        secret=secret,
        key=key,
        method=args.method,
        position=args.position,
    )

    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)

    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    key = _resolve_key(args)

    # ⚠ extract() test does NOT provide --position
    # so DO NOT pass position into read_watermark()
    secret = read_watermark(
        method=args.method,
        pdf=args.input,
        key=key,
    )

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)

    return 0


# ======================================================================
# Parser
# ======================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pdfwm", description="PDF watermark CLI")
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_exp = sub.add_parser("explore")
    p_exp.add_argument("input")
    p_exp.add_argument("--out")
    p_exp.set_defaults(func=cmd_explore)

    # embed
    p_emb = sub.add_parser("embed")
    p_emb.add_argument("input")
    p_emb.add_argument("output")
    p_emb.add_argument("--method", default="toy-eof")
    p_emb.add_argument("--position", default=None)

    g_sec = p_emb.add_argument_group("secret")
    g_sec.add_argument("--secret")
    g_sec.add_argument("--secret-file")
    g_sec.add_argument("--secret-stdin", action="store_true")

    g_key = p_emb.add_argument_group("key")
    g_key.add_argument("--key")
    g_key.add_argument("--key-file")
    g_key.add_argument("--key-stdin", action="store_true")
    g_key.add_argument("--key-prompt", action="store_true")

    p_emb.set_defaults(func=cmd_embed)

    # extract
    p_ext = sub.add_parser("extract")
    p_ext.add_argument("input")
    p_ext.add_argument("--method", default="toy-eof")

    g_key2 = p_ext.add_argument_group("key")
    g_key2.add_argument("--key")
    g_key2.add_argument("--key-file")
    g_key2.add_argument("--key-stdin", action="store_true")
    g_key2.add_argument("--key-prompt", action="store_true")

    p_ext.add_argument("--out")
    p_ext.set_defaults(func=cmd_extract)

    return p


# ======================================================================
# Entry
# ======================================================================
def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
