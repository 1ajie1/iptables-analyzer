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
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    direction: str
    src_port: Optional[int] = None


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
    table_results: List[TableResult] = None
    final_result: str = "ACCEPT"
    
    def __post_init__(self):
        if self.table_results is None:
            self.table_results = []
    
    def add_table_result(self, table_result: TableResult):
        """添加表处理结果"""
        self.table_results.append(table_result)
    
    def to_dict(self) -> dict:
        """转换为字典格式，便于JSON序列化"""
        return {
            'request': self.request.__dict__,
            'table_results': [result.__dict__ for result in self.table_results],
            'final_result': self.final_result
        }
