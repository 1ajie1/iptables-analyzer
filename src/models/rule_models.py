# -*- coding: utf-8 -*-
"""
规则数据模型
定义iptables和ipvs规则的数据结构
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any


@dataclass
class MatchConditions:
    """匹配条件数据类，与JSON格式完全对应"""
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    in_interface: Optional[str] = None
    out_interface: Optional[str] = None
    state: Optional[str] = None


@dataclass
class IptablesRule:
    """iptables规则数据类"""
    rule_id: str
    match_conditions: MatchConditions
    action: str
    jump_chain: Optional[str] = None
    target: Optional[str] = None


@dataclass
class ChainData:
    """链数据类"""
    default_policy: str
    rules: List[IptablesRule]


@dataclass
class TableData:
    """表数据类"""
    PREROUTING: ChainData
    INPUT: ChainData
    FORWARD: ChainData
    OUTPUT: ChainData
    POSTROUTING: ChainData


@dataclass
class RealServer:
    """ipvs真实服务器数据类"""
    rs_id: str
    ip: str
    port: int
    weight: int


@dataclass
class VirtualService:
    """ipvs虚拟服务数据类"""
    vs_id: str
    ip: str
    port: int
    protocol: str
    scheduler: str
    real_servers: List[RealServer]


@dataclass
class RuleSet:
    """规则集数据类"""
    metadata: Dict[str, Any]
    iptables_rules: Dict[str, TableData]
    ipvs_rules: Dict[str, List[VirtualService]]
    
    def to_dict(self) -> dict:
        """转换为字典格式，便于JSON序列化"""
        result = {
            'metadata': self.metadata,
            'iptables_rules': {},
            'ipvs_rules': self.ipvs_rules or {"virtual_services": []}
        }
        
        # 处理iptables_rules - 支持字典格式
        if isinstance(self.iptables_rules, dict):
            result['iptables_rules'] = self.iptables_rules
        else:
            # 如果是其他格式，尝试转换
            result['iptables_rules'] = {}
        
        return result
    
    @classmethod
    def from_dict(cls, data: dict) -> 'RuleSet':
        """从字典创建RuleSet对象"""
        # 实现从JSON数据构建RuleSet对象的逻辑
        pass
