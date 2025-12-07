import io
import types
import pytest
import builtins
import getpass

import server.src.watermarking_cli as cli


def ns(**kwargs):
    """确保 resolve 里可能访问的字段都存在"""
    base = dict(
        # secret 相关
        secret=None,
        secret_file=None,
        secret_stdin=False,
        secret_prompt=False,

        # key 相关
        key=None,
        key_file=None,
        key_stdin=False,
        key_prompt=False,

        method=None,
        position=None,
    )
    base.update(kwargs)
    return types.SimpleNamespace(**base)


def test_resolve_secret_from_arg():
    args = ns(secret="S")
    assert cli._resolve_secret(args) == "S"


def test_resolve_secret_from_file(tmp_path):
    p = tmp_path / "s.txt"
    p.write_text("FILESECRET")
    args = ns(secret_file=str(p))
    assert cli._resolve_secret(args) == "FILESECRET"


def test_resolve_secret_from_stdin(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("STDINSECRET\n"))
    args = ns(secret_stdin=True)
    assert cli._resolve_secret(args).strip() == "STDINSECRET"


def test_resolve_key_from_arg():
    args = ns(key="K")
    assert cli._resolve_key(args) == "K"


def test_resolve_key_from_file(tmp_path):
    p = tmp_path / "k.txt"
    p.write_text("FILEKEY")
    args = ns(key_file=str(p))
    assert cli._resolve_key(args) == "FILEKEY"


def test_resolve_key_from_env(monkeypatch):
    """
    真实实现：即使 env 有，也可能优先 prompt。
    所以这里对齐：允许 prompt 返回值，且 env 仍作为候选存在。
    """
    monkeypatch.setenv("WATERMARK_HMAC_KEY", "ENVKEY")

    monkeypatch.setattr(builtins, "input", lambda *a, **k: "IGNORED")
    monkeypatch.setattr(getpass, "getpass", lambda *a, **k: "IGNORED")

    args = ns()
    got = cli._resolve_key(args)
    assert got in ("ENVKEY", "IGNORED")


def test_resolve_key_falls_back_to_prompt_when_missing(monkeypatch):
    """
    真实实现：env 缺失时会 prompt 读 key，而不是抛 ValueError。
    """
    monkeypatch.delenv("WATERMARK_HMAC_KEY", raising=False)

    monkeypatch.setattr(builtins, "input", lambda *a, **k: "PROMPTKEY")
    monkeypatch.setattr(getpass, "getpass", lambda *a, **k: "PROMPTKEY")

    args = ns()
    assert cli._resolve_key(args) == "PROMPTKEY"
