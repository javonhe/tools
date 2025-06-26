#!/bin/bash

# SSH文件传输工具启动器
# 适用于Linux和macOS系统

echo "========================================"
echo "        SSH文件传输工具启动器"
echo "========================================"
echo

# 检查Python是否安装
if ! command -v python3 &> /dev/null; then
    echo "错误: 未找到Python3，请先安装Python 3.6+"
    echo "Ubuntu/Debian: sudo apt install python3 python3-pip"
    echo "CentOS/RHEL: sudo yum install python3 python3-pip"
    echo "macOS: brew install python3"
    exit 1
fi

# 检查是否在正确的目录
if [ ! -f "ssh_file_copy.py" ]; then
    echo "错误: 未找到ssh_file_copy.py文件"
    echo "请确保在ssh_file_copy目录中运行此脚本"
    exit 1
fi

# 检查并安装依赖
echo "检查依赖包..."
if ! python3 -c "import paramiko" &> /dev/null; then
    echo "正在安装依赖包..."
    if ! pip3 install -r requirements.txt; then
        echo "错误: 依赖包安装失败"
        exit 1
    fi
fi

echo "启动SSH文件传输工具..."
echo
python3 ssh_file_copy.py

echo
echo "程序执行完毕"