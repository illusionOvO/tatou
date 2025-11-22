import fitz  # PyMuPDF

def create_simple_pdf():
    # 1. 创建一个新的空文档
    doc = fitz.open()
    
    # 2. 添加一页
    page = doc.new_page()
    
    # 3. 写入一些简单的内容 (确保有内容可被读取)
    page.insert_text((50, 50), "Hello from Windows! This represents a valid PDF.", fontsize=12)
    
    # 4. 保存文件 (PyMuPDF 会自动处理跨平台的二进制格式)
    doc.save("Test.pdf")
    print("✅ Test.pdf 已成功创建！此文件在 Linux 上完全兼容。")

if __name__ == "__main__":
    create_simple_pdf()
