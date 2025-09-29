# -*- coding: utf-8 -*-
"""
连接状态管理器
"""

import time
import threading
from typing import Dict, Optional, List
from dataclasses import dataclass
from enum import Enum

from src.models.nat_models import ConnectionState, NATState


class ConnectionStateType(Enum):
    """连接状态类型"""
    NEW = "NEW"
    ESTABLISHED = "ESTABLISHED"
    RELATED = "RELATED"
    INVALID = "INVALID"


@dataclass
class ConnectionTracker:
    """连接跟踪器"""
    connection_id: str
    state: ConnectionStateType
    last_seen: float
    packet_count: int = 0
    byte_count: int = 0
    timeout: int = 300


class ConnectionManager:
    """连接状态管理器"""
    
    def __init__(self, default_timeout: int = 300, cleanup_interval: int = 60):
        """
        初始化连接管理器
        
        Args:
            default_timeout: 默认连接超时时间（秒）
            cleanup_interval: 清理间隔时间（秒）
        """
        self.default_timeout = default_timeout
        self.cleanup_interval = cleanup_interval
        self.connections: Dict[str, ConnectionTracker] = {}
        self.nat_state = NATState()
        
        # 启动清理线程
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        
        # 线程锁
        self._lock = threading.RLock()
    
    def track_connection(self, traffic_request, nat_rule=None) -> Optional[ConnectionTracker]:
        """
        跟踪连接
        
        Args:
            traffic_request: 流量请求
            nat_rule: NAT规则（如果有）
            
        Returns:
            连接跟踪器
        """
        with self._lock:
            connection_id = self._generate_connection_id(traffic_request)
            current_time = time.time()
            
            # 查找现有连接
            if connection_id in self.connections:
                tracker = self.connections[connection_id]
                tracker.last_seen = current_time
                tracker.packet_count += 1
                return tracker
            
            # 创建新连接
            state = self._determine_connection_state(traffic_request)
            tracker = ConnectionTracker(
                connection_id=connection_id,
                state=state,
                last_seen=current_time,
                packet_count=1,
                timeout=self.default_timeout
            )
            
            self.connections[connection_id] = tracker
            
            # 如果有NAT规则，创建NAT连接
            if nat_rule:
                self.nat_state.create_connection(traffic_request, nat_rule)
            
            return tracker
    
    def get_connection_state(self, traffic_request) -> Optional[ConnectionStateType]:
        """
        获取连接状态
        
        Args:
            traffic_request: 流量请求
            
        Returns:
            连接状态类型
        """
        with self._lock:
            connection_id = self._generate_connection_id(traffic_request)
            tracker = self.connections.get(connection_id)
            
            if tracker:
                return tracker.state
            
            return None
    
    def update_connection_state(self, traffic_request, new_state: ConnectionStateType) -> bool:
        """
        更新连接状态
        
        Args:
            traffic_request: 流量请求
            new_state: 新状态
            
        Returns:
            是否更新成功
        """
        with self._lock:
            connection_id = self._generate_connection_id(traffic_request)
            tracker = self.connections.get(connection_id)
            
            if tracker:
                tracker.state = new_state
                tracker.last_seen = time.time()
                return True
            
            return False
    
    def is_connection_established(self, traffic_request) -> bool:
        """
        检查连接是否已建立
        
        Args:
            traffic_request: 流量请求
            
        Returns:
            是否已建立
        """
        state = self.get_connection_state(traffic_request)
        return state == ConnectionStateType.ESTABLISHED
    
    def is_connection_related(self, traffic_request) -> bool:
        """
        检查连接是否相关
        
        Args:
            traffic_request: 流量请求
            
        Returns:
            是否相关
        """
        state = self.get_connection_state(traffic_request)
        return state == ConnectionStateType.RELATED
    
    def _generate_connection_id(self, traffic_request) -> str:
        """生成连接ID"""
        return f"{traffic_request.source_ip}:{traffic_request.source_port or 0}-{traffic_request.destination_ip}:{traffic_request.destination_port or 0}-{traffic_request.protocol}"
    
    def _determine_connection_state(self, traffic_request) -> ConnectionStateType:
        """确定连接状态"""
        # 根据流量请求的状态确定连接状态
        if traffic_request.state == "NEW":
            return ConnectionStateType.NEW
        elif traffic_request.state == "ESTABLISHED":
            return ConnectionStateType.ESTABLISHED
        elif traffic_request.state == "RELATED":
            return ConnectionStateType.RELATED
        elif traffic_request.state == "INVALID":
            return ConnectionStateType.INVALID
        else:
            return ConnectionStateType.NEW
    
    def _cleanup_loop(self):
        """清理循环"""
        while True:
            try:
                time.sleep(self.cleanup_interval)
                self.cleanup_expired_connections()
            except Exception as e:
                print(f"连接清理过程中出现错误: {e}")
    
    def cleanup_expired_connections(self) -> int:
        """清理过期连接"""
        with self._lock:
            current_time = time.time()
            expired_connections = []
            
            for conn_id, tracker in self.connections.items():
                if current_time - tracker.last_seen > tracker.timeout:
                    expired_connections.append(conn_id)
            
            for conn_id in expired_connections:
                del self.connections[conn_id]
            
            # 同时清理NAT状态中的过期连接
            nat_cleaned = self.nat_state.cleanup_expired_connections()
            
            return len(expired_connections) + nat_cleaned
    
    def get_connection_stats(self) -> Dict:
        """获取连接统计信息"""
        with self._lock:
            stats = {
                "total_connections": len(self.connections),
                "connections_by_state": {},
                "nat_stats": self.nat_state.get_connection_stats()
            }
            
            # 按状态统计连接
            for tracker in self.connections.values():
                state = tracker.state.value if hasattr(tracker.state, 'value') else str(tracker.state)
                stats["connections_by_state"][state] = stats["connections_by_state"].get(state, 0) + 1
            
            return stats
    
    def get_connection_details(self, connection_id: str) -> Optional[Dict]:
        """获取连接详细信息"""
        with self._lock:
            tracker = self.connections.get(connection_id)
            if not tracker:
                return None
            
            return {
                "connection_id": tracker.connection_id,
                "state": tracker.state.value,
                "last_seen": tracker.last_seen,
                "packet_count": tracker.packet_count,
                "byte_count": tracker.byte_count,
                "timeout": tracker.timeout
            }
    
    def list_connections(self, state_filter: Optional[ConnectionStateType] = None) -> List[Dict]:
        """列出连接"""
        with self._lock:
            connections = []
            
            for tracker in self.connections.values():
                if state_filter and tracker.state != state_filter:
                    continue
                
                connections.append({
                    "connection_id": tracker.connection_id,
                    "state": tracker.state.value,
                    "last_seen": tracker.last_seen,
                    "packet_count": tracker.packet_count,
                    "byte_count": tracker.byte_count
                })
            
            return connections
    
    def clear_all_connections(self) -> int:
        """清空所有连接"""
        with self._lock:
            count = len(self.connections)
            self.connections.clear()
            self.nat_state.connections.clear()
            return count
