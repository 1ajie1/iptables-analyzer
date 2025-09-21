# -*- coding: utf-8 -*-
"""
流量数据模型
定义流量请求和模拟结果的数据结构
"""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class TrafficRequest:
    """流量请求数据类"""
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    in_interface: Optional[str] = None
    out_interface: Optional[str] = None
    state: Optional[str] = None
    
    # 保持向后兼容性的别名
    @property
    def src_ip(self) -> str:
        return self.source_ip
    
    @property
    def dst_ip(self) -> str:
        return self.destination_ip
    
    @property
    def src_port(self) -> Optional[int]:
        return self.source_port
    
    @property
    def dst_port(self) -> Optional[int]:
        return self.destination_port


@dataclass
class TableResult:
    """表处理结果数据类"""
    table_name: str
    matched_rules: List = None
    final_action: str = "ACCEPT"
    jump_results: List = None

    def __post_init__(self):
        if self.matched_rules is None:
            self.matched_rules = []
        if self.jump_results is None:
            self.jump_results = []


@dataclass
class SimulationResult:
    """模拟结果数据类"""
    request: TrafficRequest
    final_action: str = "ACCEPT"
    matched_rules: List = None
    chain_traversal: List = None
    execution_path: List = None
    metadata: dict = None
    
    # 保持向后兼容性
    table_results: List[TableResult] = None
    
    def __post_init__(self):
        if self.matched_rules is None:
            self.matched_rules = []
        if self.chain_traversal is None:
            self.chain_traversal = []
        if self.execution_path is None:
            self.execution_path = []
        if self.metadata is None:
            self.metadata = {}
        if self.table_results is None:
            self.table_results = []
    
    # 保持向后兼容性的属性
    @property
    def final_result(self) -> str:
        return self.final_action
    
    def add_table_result(self, table_result: TableResult):
        """添加表处理结果"""
        self.table_results.append(table_result)
    
    def to_dict(self) -> dict:
        """转换为字典格式，便于JSON序列化"""
        return {
            'request': self.request.__dict__,
            'final_action': self.final_action,
            'matched_rules': [
                {
                    'rule_id': getattr(rule, 'rule', {}).get('rule_id', 'unknown') if hasattr(rule, 'rule') else str(rule),
                    'match_result': getattr(rule, 'match_result', {}).get('value', 'unknown') if hasattr(rule, 'match_result') else 'unknown',
                    'execution_action': getattr(rule, 'execution_action', 'unknown') if hasattr(rule, 'execution_action') else 'unknown'
                } for rule in self.matched_rules
            ],
            'chain_traversal': [
                {
                    'table_name': getattr(chain, 'table_name', 'unknown') if hasattr(chain, 'table_name') else str(chain),
                    'chain_name': getattr(chain, 'chain_name', 'unknown') if hasattr(chain, 'chain_name') else 'unknown',
                    'final_action': getattr(chain, 'final_action', 'unknown') if hasattr(chain, 'final_action') else 'unknown'
                } for chain in self.chain_traversal
            ],
            'execution_path': self.execution_path,
            'metadata': self.metadata,
            # 保持向后兼容性
            'table_results': [result.__dict__ for result in self.table_results],
            'final_result': self.final_action
        }
