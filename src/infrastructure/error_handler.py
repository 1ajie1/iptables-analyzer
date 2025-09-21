# -*- coding: utf-8 -*-
"""
异常处理模块
定义自定义异常类和错误处理装饰器
"""

from functools import wraps
from typing import Callable
from .logger import logger


class IptablesAnalyzerError(Exception):
    """工具基础异常类"""
    pass


class ParseError(IptablesAnalyzerError):
    """规则解析错误"""
    pass


class MatchError(IptablesAnalyzerError):
    """规则匹配错误"""
    pass


class ValidationError(IptablesAnalyzerError):
    """数据验证错误"""
    pass


class ConfigError(IptablesAnalyzerError):
    """配置错误"""
    pass


def handle_parse_error(func: Callable) -> Callable:
    """解析错误装饰器"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"解析失败: {e}")
            raise ParseError(f"规则解析失败: {e}")
    return wrapper


def handle_match_error(func: Callable) -> Callable:
    """匹配错误装饰器"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"匹配失败: {e}")
            raise MatchError(f"规则匹配失败: {e}")
    return wrapper


def handle_validation_error(func: Callable) -> Callable:
    """验证错误装饰器"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"验证失败: {e}")
            raise ValidationError(f"数据验证失败: {e}")
    return wrapper


def handle_config_error(func: Callable) -> Callable:
    """配置错误装饰器"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"配置错误: {e}")
            raise ConfigError(f"配置处理失败: {e}")
    return wrapper
