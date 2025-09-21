# -*- coding: utf-8 -*-
"""
日志服务模块
提供分级日志服务，支持文件和控制台输出
"""

import logging
from pathlib import Path
from typing import Optional


class Logger:
    """日志服务类"""
    
    def __init__(self, log_file: Optional[str] = None, level: str = "INFO"):
        self.logger = logging.getLogger('iptables-analyzer')
        self.logger.setLevel(getattr(logging, level.upper()))
        
        # 清除现有的处理器
        self.logger.handlers.clear()
        
        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # 文件处理器（可选）
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
    
    def debug(self, message: str):
        """记录调试日志"""
        self.logger.debug(message)
    
    def info(self, message: str):
        """记录信息日志"""
        self.logger.info(message)
    
    def warning(self, message: str):
        """记录警告日志"""
        self.logger.warning(message)
    
    def error(self, message: str):
        """记录错误日志"""
        self.logger.error(message)
    
    def critical(self, message: str):
        """记录严重错误日志"""
        self.logger.critical(message)
    
    def set_level(self, level: str):
        """设置日志级别"""
        self.logger.setLevel(getattr(logging, level.upper()))
        for handler in self.logger.handlers:
            handler.setLevel(getattr(logging, level.upper()))


# 全局日志实例
logger = Logger(log_file="logs/iptables-analyzer.log")
