#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
单文件打包脚本
使用PyInstaller将项目打包成单个可执行文件
"""

import PyInstaller.__main__
import subprocess
import sys
import os
from pathlib import Path

def check_uv_environment():
    """检查uv环境是否可用"""
    try:
        subprocess.run(['uv', '--version'], check=True, capture_output=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("错误: 请先安装uv并激活虚拟环境")
        return False

def install_dependencies():
    """安装项目依赖"""
    print("正在安装项目依赖...")
    try:
        subprocess.run(['uv', 'sync'], check=True)
        print("依赖安装完成")
        return True
    except subprocess.CalledProcessError as e:
        print(f"依赖安装失败: {e}")
        return False

def build_executable():
    """构建可执行文件"""
    print("正在构建可执行文件...")
    
    # 获取项目根目录
    project_root = Path(__file__).parent
    
    # PyInstaller参数
    args = [
        'src/interfaces/cli/main.py',  # 主程序入口
        '--onefile',                   # 单文件模式
        '--name=iptables-analyzer',    # 可执行文件名
        '--add-data=config:config',    # 添加配置文件
        '--add-data=templates:templates',  # 添加模板文件
        '--hidden-import=iptc',        # 隐藏导入
        '--hidden-import=typer',       # 隐藏导入
        '--hidden-import=jinja2',      # 隐藏导入
        '--hidden-import=graphviz',    # 隐藏导入
        '--clean',                     # 清理临时文件
        '--noconfirm',                 # 不确认覆盖
        '--distpath=dist',             # 输出目录
        '--workpath=build',            # 工作目录
    ]
    
    try:
        PyInstaller.__main__.run(args)
        print("构建完成！可执行文件位于: dist/iptables-analyzer")
        return True
    except Exception as e:
        print(f"构建失败: {e}")
        return False

def test_executable():
    """测试可执行文件"""
    executable_path = Path("dist/iptables-analyzer")
    if not executable_path.exists():
        print("错误: 可执行文件不存在")
        return False
    
    print("正在测试可执行文件...")
    try:
        result = subprocess.run([str(executable_path), '--help'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("测试通过！")
            return True
        else:
            print(f"测试失败: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("测试超时")
        return False
    except Exception as e:
        print(f"测试出错: {e}")
        return False

def main():
    """主函数"""
    print("=== iptables-ipvs-analyzer 单文件打包工具 ===")
    
    # 检查uv环境
    if not check_uv_environment():
        sys.exit(1)
    
    # 安装依赖
    if not install_dependencies():
        sys.exit(1)
    
    # 构建可执行文件
    if not build_executable():
        sys.exit(1)
    
    # 测试可执行文件
    if not test_executable():
        print("警告: 可执行文件测试失败，但构建已完成")
    
    print("=== 打包完成 ===")
    print("使用方法:")
    print("  ./dist/iptables-analyzer --help")
    print("  ./dist/iptables-analyzer parse --output rules.json")
    print("  ./dist/iptables-analyzer demo rules.json 192.168.1.10 10.96.0.10 80 tcp outbound")

if __name__ == "__main__":
    main()
