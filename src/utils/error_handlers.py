# -*- coding: utf-8 -*-
"""
增强的错误处理模块
"""

import logging
import traceback
from typing import Optional, Dict, Any, Callable, List
from functools import wraps
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """错误严重程度"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ErrorCategory(Enum):
    """错误类别"""
    VALIDATION = "VALIDATION"
    PARSING = "PARSING"
    MATCHING = "MATCHING"
    NAT = "NAT"
    CONNECTION = "CONNECTION"
    SYSTEM = "SYSTEM"
    UNKNOWN = "UNKNOWN"


@dataclass
class ErrorContext:
    """错误上下文"""
    error_type: str
    error_message: str
    severity: ErrorSeverity
    category: ErrorCategory
    context: Dict[str, Any]
    stack_trace: Optional[str] = None
    timestamp: float = 0.0
    recoverable: bool = True


class ErrorHandler:
    """错误处理器"""
    
    def __init__(self):
        self.error_history: List[ErrorContext] = []
        self.max_history_size = 1000
        self.error_counts: Dict[str, int] = {}
    
    def handle_error(self, 
                    error: Exception, 
                    error_type: str,
                    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                    category: ErrorCategory = ErrorCategory.UNKNOWN,
                    context: Optional[Dict[str, Any]] = None,
                    recoverable: bool = True) -> ErrorContext:
        """
        处理错误
        
        Args:
            error: 异常对象
            error_type: 错误类型
            severity: 严重程度
            category: 错误类别
            context: 上下文信息
            recoverable: 是否可恢复
            
        Returns:
            错误上下文
        """
        import time
        
        error_context = ErrorContext(
            error_type=error_type,
            error_message=str(error),
            severity=severity,
            category=category,
            context=context or {},
            stack_trace=traceback.format_exc(),
            timestamp=time.time(),
            recoverable=recoverable
        )
        
        # 记录错误
        self._log_error(error_context)
        
        # 添加到历史记录
        self._add_to_history(error_context)
        
        # 更新错误计数
        self._update_error_counts(error_type)
        
        return error_context
    
    def _log_error(self, error_context: ErrorContext) -> None:
        """记录错误日志"""
        log_message = f"[{error_context.category.value}] {error_context.error_type}: {error_context.error_message}"
        
        if error_context.severity == ErrorSeverity.CRITICAL:
            logger.critical(log_message)
        elif error_context.severity == ErrorSeverity.HIGH:
            logger.error(log_message)
        elif error_context.severity == ErrorSeverity.MEDIUM:
            logger.warning(log_message)
        else:
            logger.info(log_message)
        
        if error_context.context:
            logger.debug(f"错误上下文: {error_context.context}")
        
        if error_context.stack_trace:
            logger.debug(f"堆栈跟踪: {error_context.stack_trace}")
    
    def _add_to_history(self, error_context: ErrorContext) -> None:
        """添加到历史记录"""
        self.error_history.append(error_context)
        
        # 保持历史记录大小
        if len(self.error_history) > self.max_history_size:
            self.error_history = self.error_history[-self.max_history_size:]
    
    def _update_error_counts(self, error_type: str) -> None:
        """更新错误计数"""
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
    
    def get_error_stats(self) -> Dict[str, Any]:
        """获取错误统计信息"""
        total_errors = len(self.error_history)
        
        # 按严重程度统计
        severity_counts = {}
        for error in self.error_history:
            severity = error.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # 按类别统计
        category_counts = {}
        for error in self.error_history:
            category = error.category.value
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # 按类型统计
        type_counts = {}
        for error in self.error_history:
            error_type = error.error_type
            type_counts[error_type] = type_counts.get(error_type, 0) + 1
        
        return {
            "total_errors": total_errors,
            "severity_distribution": severity_counts,
            "category_distribution": category_counts,
            "type_distribution": type_counts,
            "error_counts": self.error_counts
        }
    
    def get_recent_errors(self, limit: int = 10) -> List[ErrorContext]:
        """获取最近的错误"""
        return self.error_history[-limit:]
    
    def clear_error_history(self) -> None:
        """清空错误历史"""
        self.error_history.clear()
        self.error_counts.clear()


# 全局错误处理器实例
error_handler = ErrorHandler()


def handle_errors(error_type: str,
                 severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 category: ErrorCategory = ErrorCategory.UNKNOWN,
                 recoverable: bool = True,
                 default_return: Any = None):
    """
    错误处理装饰器
    
    Args:
        error_type: 错误类型
        severity: 严重程度
        category: 错误类别
        recoverable: 是否可恢复
        default_return: 默认返回值
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # 获取上下文信息
                context = {
                    "function": func.__name__,
                    "args": str(args)[:200],  # 限制长度
                    "kwargs": str(kwargs)[:200]
                }
                
                # 处理错误
                error_handler.handle_error(
                    error=e,
                    error_type=error_type,
                    severity=severity,
                    category=category,
                    context=context,
                    recoverable=recoverable
                )
                
                # 如果可恢复，返回默认值
                if recoverable:
                    return default_return
                else:
                    # 重新抛出异常
                    raise
        
        return wrapper
    return decorator


def handle_parse_error(func: Callable) -> Callable:
    """解析错误处理装饰器"""
    return handle_errors(
        error_type="PARSE_ERROR",
        severity=ErrorSeverity.MEDIUM,
        category=ErrorCategory.PARSING,
        recoverable=True,
        default_return=None
    )(func)


def handle_matching_error(func: Callable) -> Callable:
    """匹配错误处理装饰器"""
    return handle_errors(
        error_type="MATCHING_ERROR",
        severity=ErrorSeverity.MEDIUM,
        category=ErrorCategory.MATCHING,
        recoverable=True,
        default_return=False
    )(func)


def handle_nat_error(func: Callable) -> Callable:
    """NAT错误处理装饰器"""
    return handle_errors(
        error_type="NAT_ERROR",
        severity=ErrorSeverity.HIGH,
        category=ErrorCategory.NAT,
        recoverable=True,
        default_return=None
    )(func)


def handle_connection_error(func: Callable) -> Callable:
    """连接错误处理装饰器"""
    return handle_errors(
        error_type="CONNECTION_ERROR",
        severity=ErrorSeverity.MEDIUM,
        category=ErrorCategory.CONNECTION,
        recoverable=True,
        default_return=None
    )(func)


def handle_validation_error(func: Callable) -> Callable:
    """验证错误处理装饰器"""
    return handle_errors(
        error_type="VALIDATION_ERROR",
        severity=ErrorSeverity.LOW,
        category=ErrorCategory.VALIDATION,
        recoverable=True,
        default_return=False
    )(func)


class ValidationError(Exception):
    """验证错误"""
    pass


class ParsingError(Exception):
    """解析错误"""
    pass


class MatchingError(Exception):
    """匹配错误"""
    pass


class NATError(Exception):
    """NAT错误"""
    pass


class ConnectionError(Exception):
    """连接错误"""
    pass


def validate_ip_address(ip: str) -> bool:
    """验证IP地址"""
    try:
        import ipaddress
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    """验证端口号"""
    return 1 <= port <= 65535


def validate_protocol(protocol: str) -> bool:
    """验证协议"""
    valid_protocols = {"tcp", "udp", "icmp", "all"}
    return protocol.lower() in valid_protocols


def safe_int(value: Any, default: int = 0) -> int:
    """安全转换为整数"""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_str(value: Any, default: str = "") -> str:
    """安全转换为字符串"""
    try:
        return str(value)
    except Exception:
        return default
