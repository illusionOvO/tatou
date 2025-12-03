import json
import pytest
import subprocess
import sys
from server.src import watermarking_cli as cli


@pytest.mark.timeout(3) # 限制测试在 3 秒内完成
def test_cli_execution_with_valid_args():
    # ... 使用 subprocess 调用 watermarking_cli.py
    pass

def run_cli(args):
    """Run CLI inside same process, capturing stdout/stderr & exit code."""
    from io import StringIO
    import sys

    real_out, real_err = sys.stdout, sys.stderr
    fake_out, fake_err = StringIO(), StringIO()

    sys.stdout = fake_out
    sys.stderr = fake_err

    try:
        code = cli.main(args)
    finally:
        sys.stdout = real_out
        sys.stderr = real_err

    return code, fake_out.getvalue(), fake_err.getvalue()


@pytest.fixture
def sample_pdf(tmp_path):
    pdf = tmp_path / "sample.pdf"
    pdf.write_bytes(b"%PDF-1.4 test")
    return pdf


def test_cli_methods_lists_methods():
    code, out, err = run_cli(["methods"])
    assert code == 0

    expected = ["trailer-hmac", "metadata-xmp", "visible-text-redundant"]
    for m in expected:
        assert m in out


def test_cli_explore_outputs_json(tmp_path, sample_pdf):
    out_file = tmp_path / "tree.json"
    code, out, err = run_cli(["explore", str(sample_pdf), "--out", str(out_file)])

    assert code == 0
    assert out_file.exists()
    tree = json.loads(out_file.read_text())
    assert isinstance(tree, dict)


def test_cli_embed_then_extract(tmp_path, sample_pdf):
    out_pdf = tmp_path / "out.pdf"

    # embed
    code, out, err = run_cli([
        "embed",
        str(sample_pdf),
        str(out_pdf),
        "--method", "trailer-hmac",
        "--secret", "HELLO",
        "--key", "K123",
    ])
    assert code == 0
    assert out_pdf.exists()

    # extract
    code, out, err = run_cli([
        "extract",
        str(out_pdf),
        "--method", "trailer-hmac",
        "--key", "K123"
    ])
    assert code == 0
    assert out.strip() == "HELLO"


def test_cli_embed_missing_input():
    code, out, err = run_cli([
        "embed",
        "nope.pdf",
        "out.pdf",
        "--secret", "abc",
        "--key", "xyz",
    ])

    assert code == 5  # FileNotFoundError


def test_cli_extract_wrong_key(tmp_path, sample_pdf):
    out_pdf = tmp_path / "out.pdf"

    run_cli([
        "embed",
        str(sample_pdf),
        str(out_pdf),
        "--method", "trailer-hmac",
        "--secret", "SECRET",
        "--key", "RIGHT",
    ])

    code, out, err = run_cli([
        "extract",
        str(out_pdf),
        "--method", "trailer-hmac",
        "--key", "WRONG",
    ])

    assert code == 2
    # assert "invalid" in err.lower()




# 确保你能访问 CLI 脚本的路径
CLI_MODULE_NAME = "server.src.watermarking_cli" # <-- 新的模块名定义

def test_cli_rejects_missing_secret(tmp_path):
    """
    测试 CLI 在缺少 --secret/-s 和 --secret-file 时是否快速退出并返回错误码 (非 0)。
    """
    input_pdf = tmp_path / "dummy.pdf"
    input_pdf.write_bytes(b"%PDF-1.4\n")
    
    # 使用正确的命令，但故意缺少 --secret/-s 和 --secret-file
    cmd = [
        sys.executable, "-m", CLI_MODULE_NAME, 
        "apply", 
        "--pdf", str(input_pdf),
        "--method", "trailer-hmac", 
        "--key", "dummy_key" # key 存在，但 secret 缺失
    ]
    
    # 设置超时，强制测试在 1 秒内失败，以应对变异体的无限循环
    @pytest.mark.timeout(1)
    def run_cli_test():
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1)
        # 断言：由于缺少必需参数，预期 CLI 会返回非零错误码
        assert result.returncode != 0
        assert "argument" in result.stderr or "required" in result.stderr

    run_cli_test()