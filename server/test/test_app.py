# server/src/app.py
# 这是一个简单的应用启动文件

# 修复导入 - 使用绝对导入
from server.src.rmap_routes import bp as rmap_bp
from server.src.server import create_app

app = create_app()

if __name__ == "__main__":
    app.run()