import os
import http.server
import socketserver
import cgi
import json
import urllib.parse
from datetime import datetime
import argparse
import socket  # 添加socket模块用于获取IP地址

# 用于存储用户偏好的文件
PREFERENCES_FILE = "user_preferences.json"

class FileHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def do_GET(self):
        # 解析URL
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        # 主页
        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            # 加载之前的设置
            preferences = self.load_preferences()

            # 创建HTML表单
            html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>文件和文本服务器</title>
                <meta charset="UTF-8">
                <style>
                    body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
                    h1, h2 {{ color: #333; }}
                    .section {{ margin-bottom: 30px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }}
                    input, textarea {{ margin: 10px 0; padding: 8px; width: calc(100% - 20px); }}
                    button {{ background-color: #4CAF50; color: white; padding: 10px 15px; border: none; cursor: pointer; }}
                    button:hover {{ background-color: #45a049; }}
                    ul {{ list-style-type: none; padding: 0; }}
                    li {{ padding: 8px; margin: 5px 0; background-color: #f9f9f9; }}
                    a {{ text-decoration: none; color: #2196F3; }}
                </style>
            </head>
            <body>
                <h1>文件和文本服务器</h1>

                <div class="section">
                    <h2>上传文件</h2>
                    <form action="/upload" method="post" enctype="multipart/form-data">
                        <input type="file" name="file" required>
                        <button type="submit">上传</button>
                    </form>
                </div>

                <div class="section">
                    <h2>上传文本</h2>
                    <form action="/upload_text" method="post">
                        <textarea name="text" rows="4" placeholder="输入要保存的文本">{preferences.get('last_text', '')}</textarea>
                        <input type="text" name="filename" placeholder="文件名（如：notes.txt）" value="{preferences.get('last_text_filename', 'text.txt')}">
                        <button type="submit">保存文本</button>
                    </form>
                </div>

                <div class="section">
                    <h2>文件列表</h2>
                    <ul>
            """

            # 添加文件列表
            for filename in sorted(os.listdir('.')):
                if os.path.isfile(filename) and not filename.startswith('.') and filename != PREFERENCES_FILE:
                    file_size = os.path.getsize(filename)
                    file_time = datetime.fromtimestamp(os.path.getmtime(filename)).strftime('%Y-%m-%d %H:%M:%S')

                    # 格式化文件大小
                    if file_size < 1024:
                        size_str = f"{file_size} B"
                    elif file_size < 1024 * 1024:
                        size_str = f"{file_size/1024:.1f} KB"
                    else:
                        size_str = f"{file_size/(1024*1024):.1f} MB"

                    html += f"""
                    <li>
                        <a href="/download/{filename}" download>{filename}</a>
                        <span style="color:#666;">({size_str}, {file_time})</span>
                        <a href="/delete/{filename}" style="color:red;float:right;">删除</a>
                    </li>
                    """

            html += """
                    </ul>
                </div>
            </body>
            </html>
            """

            self.wfile.write(html.encode())
            return

        # 下载文件
        elif path.startswith('/download/'):
            filename = os.path.basename(path[10:])
            if os.path.isfile(filename):
                self.send_response(200)
                self.send_header('Content-type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                self.end_headers()

                with open(filename, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "文件未找到")
            return

        # 删除文件
        elif path.startswith('/delete/'):
            filename = os.path.basename(path[8:])
            if os.path.isfile(filename) and filename != PREFERENCES_FILE:
                os.remove(filename)
                self.send_response(302)
                self.send_header('Location', '/')
                self.end_headers()
            else:
                self.send_error(404, "文件未找到或不能删除")
            return

        # 其他静态文件
        else:
            super().do_GET()

    def do_POST(self):
        # 文件上传
        if self.path == '/upload':
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST'}
            )

            if 'file' in form:
                fileitem = form['file']

                # 检查文件是否被上传
                if fileitem.filename:
                    # 保存文件
                    filename = os.path.basename(fileitem.filename)
                    with open(filename, 'wb') as f:
                        f.write(fileitem.file.read())

                    # 重定向到主页
                    self.send_response(302)
                    self.send_header('Location', '/')
                    self.end_headers()
                else:
                    self.send_error(400, "未选择文件")
            else:
                self.send_error(400, "无文件上传")

        # 文本上传
        elif self.path == '/upload_text':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')

            # 解析表单数据
            form_data = urllib.parse.parse_qs(post_data)
            text = form_data.get('text', [''])[0]
            filename = form_data.get('filename', ['text.txt'])[0]

            # 保存文本到文件
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(text)

            # 保存用户选择
            preferences = self.load_preferences()
            preferences['last_text'] = text
            preferences['last_text_filename'] = filename
            self.save_preferences(preferences)

            # 重定向到主页
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()
        else:
            self.send_error(404)

    def load_preferences(self):
        """加载用户偏好设置"""
        if os.path.exists(PREFERENCES_FILE):
            try:
                with open(PREFERENCES_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_preferences(self, preferences):
        """保存用户偏好设置"""
        with open(PREFERENCES_FILE, 'w', encoding='utf-8') as f:
            json.dump(preferences, f, ensure_ascii=False, indent=2)

def get_local_ip():
    """获取本机的IP地址"""
    try:
        # 创建一个临时socket连接到外部，从而获取本机IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 不需要真正连接到8.8.8.8，只是用来确定使用哪个网络接口
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        # 如果上面的方法失败，尝试其他方法
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return "127.0.0.1"  # 如果所有方法都失败，返回localhost

def run_server(port=8000):
    """运行HTTP服务器"""
    handler = FileHandler

    # 获取本机IP地址
    local_ip = get_local_ip()

    # 尝试绑定到指定端口，使用0.0.0.0地址允许外部连接
    try:
        httpd = socketserver.TCPServer(("0.0.0.0", port), handler)
        print(f"服务器运行在 0.0.0.0:{port}")
        print(f"- 本机访问: http://localhost:{port}/")
        print(f"- 局域网访问: http://{local_ip}:{port}/")
        print("按Ctrl+C停止服务器")
        httpd.serve_forever()
    except OSError as e:
        print(f"无法绑定到端口 {port}: {e}")
        return False
    except KeyboardInterrupt:
        print("\n服务器已停止")
    return True

if __name__ == "__main__":
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='HTTP文件和文本服务器')
    parser.add_argument('-p', '--port', type=int, default=8000, help='服务器端口 (默认: 8000)')
    args = parser.parse_args()

    # 记住之前的端口
    preferences = {}
    if os.path.exists(PREFERENCES_FILE):
        try:
            with open(PREFERENCES_FILE, 'r', encoding='utf-8') as f:
                preferences = json.load(f)
        except:
            pass

    port = args.port
    if port == 8000 and 'last_port' in preferences:
        port = preferences['last_port']

    # 运行服务器
    if run_server(port):
        # 保存端口作为默认值
        preferences['last_port'] = port
        with open(PREFERENCES_FILE, 'w', encoding='utf-8') as f:
            json.dump(preferences, f, ensure_ascii=False, indent=2)
