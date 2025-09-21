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
        return {
            'metadata': self.metadata,
            'iptables_rules': {
                table_name: {
                    chain_name: {
                        'default_policy': chain_data.default_policy,
                        'rules': [
                            {
                                'rule_id': rule.rule_id,
                                'match_conditions': {
                                    'source_ip': rule.match_conditions.source_ip,
                                    'destination_ip': rule.match_conditions.destination_ip,
                                    'protocol': rule.match_conditions.protocol,
                                    'source_port': rule.match_conditions.source_port,
                                    'destination_port': rule.match_conditions.destination_port,
                                    'in_interface': rule.match_conditions.in_interface,
                                    'out_interface': rule.match_conditions.out_interface,
                                    'state': rule.match_conditions.state
                                },
                                'action': rule.action,
                                'jump_chain': rule.jump_chain,
                                'target': rule.target
                            } for rule in chain_data.rules
                        ]
                    } for chain_name, chain_data in table_data.__dict__.items()
                } for table_name, table_data in self.iptables_rules.items()
            },
            'ipvs_rules': {
                'virtual_services': [
                    {
                        'vs_id': vs.vs_id,
                        'ip': vs.ip,
                        'port': vs.port,
                        'protocol': vs.protocol,
                        'scheduler': vs.scheduler,
                        'real_servers': [
                            {
                                'rs_id': rs.rs_id,
                                'ip': rs.ip,
                                'port': rs.port,
                                'weight': rs.weight
                            } for rs in vs.real_servers
                        ]
                    } for vs in self.ipvs_rules['virtual_services']
                ]
            }
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'RuleSet':
        """从字典创建RuleSet对象"""
        # 实现从JSON数据构建RuleSet对象的逻辑
        pass
