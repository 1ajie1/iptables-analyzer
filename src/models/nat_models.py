# -*- coding: utf-8 -*-
"""
NAT相关数据模型
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum


class NATType(Enum):
    """NAT类型枚举"""
    SNAT = "SNAT"  # 源地址转换
    DNAT = "DNAT"  # 目标地址转换
    MASQUERADE = "MASQUERADE"  # 动态源地址转换
    REDIRECT = "REDIRECT"  # 端口重定向


@dataclass
class NATRule:
    """NAT规则"""
    rule_id: str
    nat_type: NATType
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    to_source: Optional[str] = None
    to_destination: Optional[str] = None
    to_source_port: Optional[int] = None
    to_destination_port: Optional[int] = None
    interface: Optional[str] = None
    protocol: Optional[str] = None
    enabled: bool = True


@dataclass
class ConnectionState:
    """连接状态"""
    connection_id: str
    original_source_ip: str
    original_destination_ip: str
    original_source_port: int
    original_destination_port: int
    translated_source_ip: Optional[str] = None
    translated_destination_ip: Optional[str] = None
    translated_source_port: Optional[int] = None
    translated_destination_port: Optional[int] = None
    protocol: str = "tcp"
    state: str = "NEW"  # NEW, ESTABLISHED, RELATED, INVALID
    timeout: int = 300  # 连接超时时间（秒）
    last_seen: float = 0.0  # 最后看到的时间戳
    nat_type: Optional[NATType] = None


@dataclass
class NATState:
    """NAT状态管理器"""
    snat_rules: List[NATRule] = field(default_factory=list)
    dnat_rules: List[NATRule] = field(default_factory=list)
    connections: Dict[str, ConnectionState] = field(default_factory=dict)
    connection_timeout: int = 300  # 默认连接超时时间
    
    def add_snat_rule(self, rule: NATRule) -> None:
        """添加SNAT规则"""
        self.snat_rules.append(rule)
    
    def add_dnat_rule(self, rule: NATRule) -> None:
        """添加DNAT规则"""
        self.dnat_rules.append(rule)
    
    def find_matching_snat_rule(self, traffic_request) -> Optional[NATRule]:
        """查找匹配的SNAT规则"""
        for rule in self.snat_rules:
            if not rule.enabled:
                continue
            if self._rule_matches_traffic(rule, traffic_request):
                return rule
        return None
    
    def find_matching_dnat_rule(self, traffic_request) -> Optional[NATRule]:
        """查找匹配的DNAT规则"""
        for rule in self.dnat_rules:
            if not rule.enabled:
                continue
            if self._rule_matches_traffic(rule, traffic_request):
                return rule
        return None
    
    def _rule_matches_traffic(self, rule: NATRule, traffic_request) -> bool:
        """检查规则是否匹配流量"""
        # 检查协议
        if rule.protocol and rule.protocol != traffic_request.protocol:
            return False
        
        # 检查源IP
        if rule.source_ip and not self._ip_matches(rule.source_ip, traffic_request.source_ip):
            return False
        
        # 检查目标IP
        if rule.destination_ip and not self._ip_matches(rule.destination_ip, traffic_request.destination_ip):
            return False
        
        # 检查源端口
        if rule.source_port and traffic_request.source_port and rule.source_port != traffic_request.source_port:
            return False
        
        # 检查目标端口
        if rule.destination_port and traffic_request.destination_port and rule.destination_port != traffic_request.destination_port:
            return False
        
        return True
    
    def _ip_matches(self, rule_ip: str, packet_ip: str) -> bool:
        """检查IP是否匹配（支持CIDR）"""
        try:
            from src.utils.ip_utils import IPUtils
            ip_utils = IPUtils()
            return ip_utils.is_ip_in_network(packet_ip, rule_ip)
        except Exception:
            return rule_ip == packet_ip
    
    def create_connection(self, traffic_request, nat_rule: NATRule) -> ConnectionState:
        """创建新连接"""
        import time
        
        connection_id = self._generate_connection_id(traffic_request)
        
        connection = ConnectionState(
            connection_id=connection_id,
            original_source_ip=traffic_request.source_ip,
            original_destination_ip=traffic_request.destination_ip,
            original_source_port=traffic_request.source_port or 0,
            original_destination_port=traffic_request.destination_port or 0,
            protocol=traffic_request.protocol,
            state=traffic_request.state,
            last_seen=time.time(),
            nat_type=nat_rule.nat_type
        )
        
        # 应用NAT转换
        self._apply_nat_to_connection(connection, nat_rule)
        
        self.connections[connection_id] = connection
        return connection
    
    def find_existing_connection(self, traffic_request) -> Optional[ConnectionState]:
        """查找现有连接"""
        connection_id = self._generate_connection_id(traffic_request)
        return self.connections.get(connection_id)
    
    def update_connection(self, connection: ConnectionState) -> None:
        """更新连接状态"""
        import time
        connection.last_seen = time.time()
        self.connections[connection.id] = connection
    
    def _generate_connection_id(self, traffic_request) -> str:
        """生成连接ID"""
        return f"{traffic_request.source_ip}:{traffic_request.source_port or 0}-{traffic_request.destination_ip}:{traffic_request.destination_port or 0}-{traffic_request.protocol}"
    
    def _apply_nat_to_connection(self, connection: ConnectionState, nat_rule: NATRule) -> None:
        """对连接应用NAT转换"""
        if nat_rule.nat_type == NATType.SNAT:
            if nat_rule.to_source:
                connection.translated_source_ip = nat_rule.to_source
            if nat_rule.to_source_port:
                connection.translated_source_port = nat_rule.to_source_port
        
        elif nat_rule.nat_type == NATType.DNAT:
            if nat_rule.to_destination:
                connection.translated_destination_ip = nat_rule.to_destination
            if nat_rule.to_destination_port:
                connection.translated_destination_port = nat_rule.to_destination_port
        
        elif nat_rule.nat_type == NATType.MASQUERADE:
            # MASQUERADE使用出接口的IP作为源IP
            connection.translated_source_ip = "MASQUERADE"
        
        elif nat_rule.nat_type == NATType.REDIRECT:
            # REDIRECT重定向到本地端口
            connection.translated_destination_ip = "127.0.0.1"
            if nat_rule.to_destination_port:
                connection.translated_destination_port = nat_rule.to_destination_port
    
    def cleanup_expired_connections(self) -> int:
        """清理过期连接"""
        import time
        current_time = time.time()
        expired_connections = []
        
        for conn_id, connection in self.connections.items():
            if current_time - connection.last_seen > self.connection_timeout:
                expired_connections.append(conn_id)
        
        for conn_id in expired_connections:
            del self.connections[conn_id]
        
        return len(expired_connections)
    
    def get_connection_stats(self) -> Dict[str, int]:
        """获取连接统计信息"""
        stats = {
            "total_connections": len(self.connections),
            "snat_rules": len(self.snat_rules),
            "dnat_rules": len(self.dnat_rules)
        }
        
        # 按状态统计连接
        state_counts = {}
        for connection in self.connections.values():
            state_counts[connection.state] = state_counts.get(connection.state, 0) + 1
        
        stats["connections_by_state"] = state_counts
        return stats
