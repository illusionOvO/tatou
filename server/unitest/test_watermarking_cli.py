import pytest
from conftest import make_pdf_bytes
import types
import server.src.watermarking_cli as cli


def test_build_parser_has_subcommands():
    p = cli.build_parser()
    args = p.parse_args(["methods"])
    assert args.cmd == "methods"


def test_cmd_methods(capsys, monkeypatch):
    monkeypatch.setattr(cli, "METHODS", {"b": None, "a": None})
    rc = cli.cmd_methods(None)
    out = capsys.readouterr().out.strip().splitlines()
    assert out == ["a", "b"]
    assert rc == 0


def test_cmd_embed_and_extract(tmp_path, monkeypatch, capsys):
    pdf = tmp_path / "in.pdf"
    pdf.write_bytes(make_pdf_bytes())
    outpdf = tmp_path / "out.pdf"

    # mock 依赖，避免真正处理 pdf
    monkeypatch.setattr(cli, "is_watermarking_applicable", lambda **k: True)
    monkeypatch.setattr(cli, "apply_watermark", lambda **k: make_pdf_bytes(b"wm"))
    monkeypatch.setattr(cli, "_resolve_key", lambda args: "k")
    monkeypatch.setattr(cli, "_resolve_secret", lambda args: "s")

    args = cli.build_parser().parse_args(
        ["embed", str(pdf), str(outpdf), "--method", "trailer-hmac"]
    )
    assert cli.cmd_embed(args) == 0
    assert outpdf.read_bytes().endswith(b"wm")

    monkeypatch.setattr(cli, "read_watermark", lambda **k: "secret")
    args2 = cli.build_parser().parse_args(
        ["extract", str(outpdf), "--method", "trailer-hmac"]
    )
    assert cli.cmd_extract(args2) == 0
    assert "secret" in capsys.readouterr().out


def test_main_error_handling(monkeypatch):
    def raiser(args):
        raise FileNotFoundError("x")

    p = cli.build_parser()
    monkeypatch.setattr(cli, "build_parser", lambda: p)
    monkeypatch.setattr(
        p,
        "parse_args",
        lambda argv=None: types.SimpleNamespace(func=raiser)
    )
    assert cli.main([]) == 2
