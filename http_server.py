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

# 文件传输配置
CHUNK_SIZE = 8192  # 8KB 传输块大小

# 全局配置
_config = {
    'max_file_size': 1024 * 1024 * 1024  # 1GB 默认最大文件大小
}

def format_file_size(size_bytes):
    """格式化文件大小显示"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes/1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes/(1024*1024):.1f} MB"
    else:
        return f"{size_bytes/(1024*1024*1024):.1f} GB"

def get_max_file_size():
    """获取最大文件大小配置"""
    return _config['max_file_size']

def set_max_file_size(size_bytes):
    """设置最大文件大小配置"""
    _config['max_file_size'] = size_bytes

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
                    size_str = format_file_size(file_size)

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
                file_size = os.path.getsize(filename)
                self.send_response(200)
                self.send_header('Content-type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                self.send_header('Content-Length', str(file_size))
                self.end_headers()

                # 使用流式传输，避免内存溢出
                try:
                    with open(filename, 'rb') as f:
                        while True:
                            chunk = f.read(CHUNK_SIZE)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    # 客户端断开连接，这是正常的
                    pass
                except Exception as e:
                    print(f"文件传输错误: {e}")
                    # 如果还没有发送响应头，发送错误响应
                    if not self.wfile.closed:
                        self.send_error(500, "文件传输失败")
                    return
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
                    try:
                        with open(filename, 'wb') as f:
                            # 使用流式写入，避免内存溢出
                            total_size = 0
                            while True:
                                chunk = fileitem.file.read(CHUNK_SIZE)
                                if not chunk:
                                    break
                                total_size += len(chunk)
                                if total_size > get_max_file_size():
                                    # 删除已写入的部分文件
                                    f.close()
                                    os.remove(filename)
                                    self.send_error(413, f"文件太大，最大允许 {format_file_size(get_max_file_size())}")
                                    return
                                f.write(chunk)
                    except Exception as e:
                        print(f"文件上传错误: {e}")
                        # 如果文件已创建，删除它
                        if os.path.exists(filename):
                            try:
                                os.remove(filename)
                            except:
                                pass
                        self.send_error(500, "文件上传失败")
                        return

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

def get_network_interfaces():
    """获取所有可用的网络接口"""
    interfaces = []
    try:
        # 获取所有网络接口
        for interface in socket.getaddrinfo(socket.gethostname(), None):
            ip = interface[4][0]
            # 只添加IPv4地址，排除localhost
            if ':' not in ip and ip != '127.0.0.1':
                interfaces.append(ip)

        # 尝试获取外部连接的IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            if ip not in interfaces:
                interfaces.append(ip)
        except:
            pass

        # 如果没有找到任何接口，添加localhost
        if not interfaces:
            interfaces.append('127.0.0.1')

        return interfaces
    except:
        return ['127.0.0.1']

def get_preferred_ip(preferences):
    """获取首选IP地址"""
    interfaces = get_network_interfaces()
    preferred_ip = preferences.get('preferred_ip')

    # 如果有保存的首选IP且仍然可用，则使用它
    if preferred_ip and preferred_ip in interfaces:
        return preferred_ip

    # 否则返回第一个可用的IP
    return interfaces[0]

def run_server(port=8000):
    """运行HTTP服务器"""
    handler = FileHandler

    # 加载用户偏好
    preferences = {}
    if os.path.exists(PREFERENCES_FILE):
        try:
            with open(PREFERENCES_FILE, 'r', encoding='utf-8') as f:
                preferences = json.load(f)
        except:
            pass

    # 配置服务器以支持大文件传输
    socketserver.TCPServer.allow_reuse_address = True
    socketserver.TCPServer.timeout = 300  # 5分钟超时

    # 获取所有可用的网络接口
    interfaces = get_network_interfaces()

    # 显示网络接口选择
    print("\n可用的网络接口：")
    default_ip = preferences.get('preferred_ip')

    # 如果默认IP不在当前可用的接口中，设为None
    if default_ip and default_ip not in interfaces:
        default_ip = None

    # 显示所有接口，标记默认选项
    for i, ip in enumerate(interfaces, 1):
        default_mark = " (上次选择)" if ip == default_ip else ""
        print(f"{i}. http://{ip}:{port}/{default_mark}")

    # 如果只有一个接口，直接使用它
    if len(interfaces) == 1:
        selected_ip = interfaces[0]
        print(f"\n只有一个可用接口，将使用: http://{selected_ip}:{port}/")
    else:
        # 让用户选择接口
        while True:
            try:
                default_index = interfaces.index(default_ip) + 1 if default_ip in interfaces else 1
                choice = input(f"\n请选择网络接口 (1-{len(interfaces)}, 直接回车选择{default_index}): ").strip()

                # 如果用户直接回车，使用默认值
                if not choice:
                    choice = str(default_index)

                choice_index = int(choice) - 1
                if 0 <= choice_index < len(interfaces):
                    selected_ip = interfaces[choice_index]
                    break
                else:
                    print("无效的选择，请重试")
            except ValueError:
                print("无效的输入，请输入数字")

    # 询问用户是否要修改最大文件大小
    current_max_size = get_max_file_size() // (1024 * 1024)  # 转换为MB
    print(f"\n当前最大文件大小: {current_max_size} MB")

    while True:
        try:
            max_size_input = input(f"是否要修改最大文件大小？(y/N, 直接回车保持{current_max_size}MB): ").strip().lower()

            if not max_size_input or max_size_input == 'n':
                print(f"保持最大文件大小为 {current_max_size} MB")
                break
            elif max_size_input == 'y':
                while True:
                    try:
                        new_max_size = input(f"请输入新的最大文件大小(MB) [{current_max_size}]: ").strip()
                        if not new_max_size:
                            print(f"保持最大文件大小为 {current_max_size} MB")
                            break

                        new_max_size = int(new_max_size)
                        if new_max_size > 0:
                            set_max_file_size(new_max_size * 1024 * 1024)  # 转换为字节
                            print(f"最大文件大小已设置为 {new_max_size} MB")
                            break
                        else:
                            print("最大文件大小必须大于0")
                    except ValueError:
                        print("请输入有效的数字")
                break
            else:
                print("请输入 y 或 n")
        except KeyboardInterrupt:
            print(f"\n保持最大文件大小为 {current_max_size} MB")
            break

    # 保存用户选择
    preferences['preferred_ip'] = selected_ip
    preferences['max_file_size_mb'] = get_max_file_size() // (1024 * 1024)  # 保存为MB
    with open(PREFERENCES_FILE, 'w', encoding='utf-8') as f:
        json.dump(preferences, f, ensure_ascii=False, indent=2)

    # 尝试绑定到指定端口，使用0.0.0.0地址允许外部连接
    try:
        httpd = socketserver.TCPServer(("0.0.0.0", port), handler)
        print(f"\n服务器运行在 0.0.0.0:{port}")
        print(f"- 本机访问: http://localhost:{port}/")
        print(f"- 选定的访问地址: http://{selected_ip}:{port}/")
        print(f"- 配置的最大文件大小: {format_file_size(get_max_file_size())}")
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
    parser.add_argument('-m', '--max-size', type=int, default=1024,
                       help='最大文件大小(MB) (默认: 1024 MB)')
    args = parser.parse_args()

    # 设置最大文件大小
    set_max_file_size(args.max_size * 1024 * 1024)  # 转换为字节

    # 记住之前的端口
    preferences = {}
    if os.path.exists(PREFERENCES_FILE):
        try:
            with open(PREFERENCES_FILE, 'r', encoding='utf-8') as f:
                preferences = json.load(f)
        except:
            pass

    # 如果用户没有通过命令行指定最大文件大小，则使用之前保存的设置
    if args.max_size == 1024 and 'max_file_size_mb' in preferences:
        saved_max_size = preferences['max_file_size_mb']
        set_max_file_size(saved_max_size * 1024 * 1024)
        print(f"使用之前保存的最大文件大小设置: {saved_max_size} MB")

    port = args.port
    if port == 8000 and 'last_port' in preferences:
        port = preferences['last_port']

    # 运行服务器
    if run_server(port):
        # 保存端口作为默认值
        preferences['last_port'] = port
        with open(PREFERENCES_FILE, 'w', encoding='utf-8') as f:
            json.dump(preferences, f, ensure_ascii=False, indent=2)
