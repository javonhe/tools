# SSH文件传输工具使用示例

## 基本使用流程

### 1. 首次使用

```bash
# 进入工具目录
cd ssh_file_copy

# 安装依赖
pip install -r requirements.txt

# 运行工具
python ssh_file_copy.py
```

### 2. 交互式输入示例

```
=== SSH文件传输工具 ===
请输入连接信息 (直接回车使用默认值):
IP地址 []: 192.168.1.100
端口 [22]:
用户名 []: admin
密码: ********
源文件路径 []: /path/to/local/file.txt
目标目录 []: /home/admin/uploads
目标文件名 (可选，留空使用原文件名) []: new_file.txt
```

### 3. 传输过程示例

```
配置已保存到: ssh_transfer_config.json

计算源文件MD5...
源文件MD5: d41d8cd98f00b204e9800998ecf8427e
连接到 192.168.1.100:22...
SSH连接成功
连接稳定性测试通过
检测SFTP支持...
✓ SFTP可用
使用SFTP传输文件...
创建SFTP客户端...
检查目标目录: /home/admin/uploads
目标目录已存在
发现同名文件，正在备份: /home/admin/uploads/new_file.txt -> /home/admin/uploads/new_file.txt.bak
✓ 文件备份成功: /home/admin/uploads/new_file.txt.bak
开始传输文件: /path/to/local/file.txt -> /home/admin/uploads/new_file.txt
文件传输完成
验证文件传输...
远程文件MD5: d41d8cd98f00b204e9800998ecf8427e
✓ 文件传输验证成功！MD5值匹配
文件传输任务完成！
```

## 常见使用场景

### 场景1：传输配置文件
```bash
python ssh_file_copy.py
# 输入：
# IP地址: 192.168.1.100
# 用户名: admin
# 密码: ****
# 源文件: /home/user/config.conf
# 目标目录: /etc/app/
# 目标文件名: app.conf
```

### 场景2：备份数据库文件
```bash
python ssh_file_copy.py
# 输入：
# IP地址: 192.168.1.101
# 用户名: backup
# 密码: ****
# 源文件: /backup/database.sql
# 目标目录: /backup/remote/
# 目标文件名: database_$(date +%Y%m%d).sql
```

## 配置文件示例

程序会自动创建 `ssh_transfer_config.json` 配置文件：

```json
{
  "ip": "192.168.1.100",
  "port": 22,
  "username": "admin",
  "password": "your_password",
  "source_file": "/path/to/local/file.txt",
  "target_dir": "/home/admin/uploads",
  "target_filename": "new_file.txt"
}
```

## 故障排除示例

### 问题1：连接失败
```
SSH连接失败: [Errno 111] Connection refused
```

**解决方案：**
```bash
# 检查SSH服务状态
ssh admin@192.168.1.100 "systemctl status sshd"

# 检查防火墙
ssh admin@192.168.1.100 "ufw status"

# 测试网络连接
ping 192.168.1.100
```

### 问题2：认证失败
```
Authentication failed
```

**解决方案：**
```bash
# 测试SSH连接
ssh admin@192.168.1.100

# 检查用户权限
ssh admin@192.168.1.100 "whoami && groups"
```

## 安全建议

### 1. 使用SSH密钥认证
```bash
# 生成SSH密钥
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"

# 复制公钥到服务器
ssh-copy-id admin@192.168.1.100
```

### 2. 保护配置文件
```bash
# 设置配置文件权限
chmod 600 ssh_transfer_config.json
```