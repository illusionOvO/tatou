import server.src.watermarking_utils as wu


def test_explore_pdf_regex_fallback(monkeypatch):
    """
    强制 explore_pdf 走 regex fallback，并验证：
    - regex 枚举 obj 节点确实执行
    - /Type /Page 能被识别（从而覆盖 page_nodes 推导分支）
    """

    # 1) 强制禁用三方库分支 => try 块不 return，直接落到 regex
    monkeypatch.setattr(wu, "_HAS_FITZ", False, raising=False)
    monkeypatch.setattr(wu, "_HAS_PIKEPDF", False, raising=False)

    # 有些实现会先检查 fitz 是否存在，这里也保险置空
    if hasattr(wu, "fitz"):
        monkeypatch.setattr(wu, "fitz", None, raising=False)

    # 2) 构造包含 /Type /Page 的最小 PDF（必须有 obj/endobj）
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"2 0 obj\n<< /Type /Page >>\nendobj\n"
        b"trailer\n<<>>\n%%EOF\n"
    )

    tree = wu.explore_pdf(pdf)
    assert tree["type"] == "Document"

    children = tree.get("children", [])
    # 3) regex loop 至少扫出了对象
    assert any(isinstance(c.get("id"), str) and c["id"].startswith("obj:")
               for c in children)

    # 4) 覆盖 /Type /Page 的识别 & page_nodes 推导：
    #    - 至少存在一个 type == "Page" 的原始对象
    #    - 或存在派生的 page:* 节点
    assert (
        any(c.get("type") == "Page" for c in children)
        or any(isinstance(c.get("id"), str) and c["id"].startswith("page:")
               for c in children)
    )
