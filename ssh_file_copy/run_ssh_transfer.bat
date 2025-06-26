@echo off
chcp 65001 >nul
echo ========================================
echo        SSH文件传输工具启动器
echo ========================================
echo.

REM 检查Python是否安装
python --version >nul 2>&1
if errorlevel 1 (
    echo 错误: 未找到Python，请先安装Python 3.6+
    echo 下载地址: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM 检查是否在正确的目录
if not exist "ssh_file_copy.py" (
    echo 错误: 未找到ssh_file_copy.py文件
    echo 请确保在ssh_file_copy目录中运行此脚本
    pause
    exit /b 1
)

REM 检查并安装依赖
echo 检查依赖包...
python -c "import paramiko" >nul 2>&1
if errorlevel 1 (
    echo 正在安装依赖包...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo 错误: 依赖包安装失败
        pause
        exit /b 1
    )
)

echo 启动SSH文件传输工具...
echo.
python ssh_file_copy.py

echo.
echo 程序执行完毕
pause